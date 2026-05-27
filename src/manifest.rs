use chrono::{DateTime, Utc};
use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::ProgressBar;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::hash::hash_file_with_advise;
use crate::io_utils;

/// A single entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Hex-encoded BLAKE3 hash.
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
    /// Timestamp of when this entry was last verified.
    pub last_verified: DateTime<Utc>,
}

/// The full manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Version of the manifest format.
    pub version: u32,
    /// Glob patterns used to exclude files during compute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_patterns: Vec<String>,
    /// Entries keyed by relative path.
    pub entries: HashMap<String, ManifestEntry>,
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            version: 1,
            exclude_patterns: Vec::new(),
            entries: HashMap::new(),
        }
    }

    /// Load a manifest from a JSON file.
    pub fn load(path: &Path) -> io::Result<Self> {
        let content = fs::read_to_string(path)?;
        serde_json::from_str(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
    }

    /// Save the manifest to a JSON file atomically (write to tmp, then rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let content = serde_json::to_string_pretty(self).map_err(io::Error::other)?;

        // Write to a sibling temp file, then atomically rename
        let dir = path.parent().unwrap_or(Path::new("."));
        let tmp_path = dir.join(format!(".integritas-manifest-{}.tmp", std::process::id()));
        fs::write(&tmp_path, &content)?;
        fs::rename(&tmp_path, path).inspect_err(|_| {
            // Clean up tmp on rename failure
            let _ = fs::remove_file(&tmp_path);
        })
    }
}

/// Build a `GlobSet` from a list of patterns.
/// Returns None if the list is empty.
pub fn build_glob_set(patterns: &[String]) -> io::Result<Option<GlobSet>> {
    if patterns.is_empty() {
        return Ok(None);
    }
    let mut builder = GlobSetBuilder::new();
    for pat in patterns {
        let glob = Glob::new(pat)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        builder.add(glob);
    }
    let set = builder
        .build()
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
    Ok(Some(set))
}

/// Convert a path to a UTF-8 string, returning an error if the path contains non-UTF-8 bytes.
fn path_to_utf8(path: &Path) -> io::Result<String> {
    path.to_str()
        .map(std::string::ToString::to_string)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("non-UTF-8 path: {path:?}"),
            )
        })
}

/// Filter a list of absolute paths, removing those whose relative path matches any exclude glob.
fn filter_excluded(
    files: Vec<PathBuf>,
    root_dir: &Path,
    excludes: Option<&GlobSet>,
) -> Vec<PathBuf> {
    match excludes {
        None => files,
        Some(set) => files
            .into_iter()
            .filter(|p| {
                // strip_prefix is infallible here: all paths come from walkdir rooted at root_dir
                let rel = p
                    .strip_prefix(root_dir)
                    .expect("walkdir path must start with root_dir");
                let rel_str = rel
                    .to_str()
                    .expect("non-UTF-8 path should have been rejected earlier");
                !set.is_match(rel_str)
            })
            .collect(),
    }
}

/// Result of verifying a single file.
#[derive(Debug, PartialEq)]
pub enum VerifyStatus {
    Ok,
    Changed,
    Missing,
    New,
}

/// Summary of a verification run.
#[derive(Debug, Default)]
pub struct VerifySummary {
    pub ok: u32,
    pub changed: Vec<String>,
    pub missing: Vec<String>,
    pub new: Vec<String>,
    /// Computed hashes from the check run (path -> (`hash_hex`, size)).
    /// Contains entries for both OK and CHANGED files.
    /// Used by --prompt to rebuild the manifest without re-hashing.
    pub computed_hashes: HashMap<String, (String, u64)>,
}

/// Append new files to an existing manifest without re-hashing known files.
/// Files already in the manifest are kept as-is. Only files not present in the
/// manifest are hashed and added. Files that were in the manifest but no longer
/// exist on disk are removed.
pub fn compute_append(
    root_dir: &Path,
    existing: Option<&Manifest>,
    threads: usize,
    excludes: &[String],
    progress: Option<&ProgressBar>,
) -> io::Result<Manifest> {
    let now = Utc::now();
    let threads = threads.max(1);

    // Collect all current files, applying excludes
    let all_files = io_utils::collect_sorted_by_inode(root_dir)?;
    let glob_set = build_glob_set(excludes)?;
    let all_files = filter_excluded(all_files, root_dir, glob_set.as_ref());

    // Merge excludes: keep existing manifest's excludes + new CLI excludes
    let mut final_excludes: Vec<String> = existing
        .map(|m| m.exclude_patterns.clone())
        .unwrap_or_default();
    for pat in excludes {
        if !final_excludes.contains(pat) {
            final_excludes.push(pat.clone());
        }
    }

    // Determine which files need hashing (not in existing manifest)
    let existing_entries = existing.map(|m| &m.entries);
    let mut manifest = Manifest::new();
    manifest.exclude_patterns = final_excludes;

    let mut new_files: Vec<&PathBuf> = Vec::new();

    for abs_path in &all_files {
        let rel_path = path_to_utf8(
            abs_path
                .strip_prefix(root_dir)
                .expect("path must be under root_dir"),
        )?;

        // If already in manifest, keep the existing entry
        if let Some(entries) = existing_entries {
            if let Some(entry) = entries.get(&rel_path) {
                manifest.entries.insert(rel_path, entry.clone());
                continue;
            }
        }

        // New file — needs hashing
        new_files.push(abs_path);
    }

    let new_count = new_files.len();

    // Hash new files (parallel or sequential)
    if threads > 1 && new_count > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let entries: Vec<(String, ManifestEntry)> = pool.install(|| {
            new_files
                .par_iter()
                .map(|abs_path| {
                    let rel_path = path_to_utf8(
                        abs_path
                            .strip_prefix(root_dir)
                            .expect("path must be under root_dir"),
                    )?;
                    let (hash, size) = hash_file_with_advise(abs_path, true)?;
                    if let Some(pb) = progress {
                        pb.inc(1);
                    }
                    Ok((
                        rel_path,
                        ManifestEntry {
                            hash: hash.to_hex().to_string(),
                            size,
                            last_verified: now,
                        },
                    ))
                })
                .collect::<io::Result<Vec<_>>>()
        })?;

        for (key, entry) in entries {
            manifest.entries.insert(key, entry);
        }
    } else {
        for abs_path in &new_files {
            let rel_path = path_to_utf8(
                abs_path
                    .strip_prefix(root_dir)
                    .expect("path must be under root_dir"),
            )?;
            let (hash, size) = hash_file_with_advise(abs_path, true)?;
            if let Some(pb) = progress {
                pb.inc(1);
            }
            manifest.entries.insert(
                rel_path,
                ManifestEntry {
                    hash: hash.to_hex().to_string(),
                    size,
                    last_verified: now,
                },
            );
        }
    }

    Ok(manifest)
}

/// Compute a manifest for all files under `root_dir`.
/// Uses simple sequential hashing (for backwards compatibility and tests).
pub fn compute(root_dir: &Path) -> io::Result<Manifest> {
    compute_with_threads(root_dir, 1, None, &[])
}

/// Compute a manifest using the specified number of threads.
/// When threads > 1, files are hashed in parallel with fadvise and inode sorting.
/// When threads == 1, files are hashed sequentially with fadvise.
/// If a `ProgressBar` is provided, it is incremented per file.
/// Exclude patterns are stored in the manifest and used to filter files.
pub fn compute_with_threads(
    root_dir: &Path,
    threads: usize,
    progress: Option<&ProgressBar>,
    excludes: &[String],
) -> io::Result<Manifest> {
    let now = Utc::now();
    let threads = threads.max(1);

    // Always sort by inode (helps on HDD, no-op perf cost on SSD)
    let files = io_utils::collect_sorted_by_inode(root_dir)?;
    let glob_set = build_glob_set(excludes)?;
    let files = filter_excluded(files, root_dir, glob_set.as_ref());

    if threads > 1 {
        // Build a custom thread pool with the requested size
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        pool.install(|| {
            let entries: Vec<(String, ManifestEntry)> = files
                .par_iter()
                .map(|abs_path| {
                    let rel_path = path_to_utf8(
                        abs_path
                            .strip_prefix(root_dir)
                            .expect("path must be under root_dir"),
                    )?;
                    let (hash, size) = hash_file_with_advise(abs_path, true)?;
                    if let Some(pb) = progress {
                        pb.inc(1);
                    }
                    Ok((
                        rel_path,
                        ManifestEntry {
                            hash: hash.to_hex().to_string(),
                            size,
                            last_verified: now,
                        },
                    ))
                })
                .collect::<io::Result<Vec<_>>>()?;

            let mut m = Manifest::new();
            m.exclude_patterns = excludes.to_vec();
            for (key, entry) in entries {
                m.entries.insert(key, entry);
            }
            Ok(m)
        })
    } else {
        let mut m = Manifest::new();
        m.exclude_patterns = excludes.to_vec();
        for abs_path in &files {
            let rel_path = path_to_utf8(
                abs_path
                    .strip_prefix(root_dir)
                    .expect("path must be under root_dir"),
            )?;
            let (hash, size) = hash_file_with_advise(abs_path, true)?;
            if let Some(pb) = progress {
                pb.inc(1);
            }
            m.entries.insert(
                rel_path,
                ManifestEntry {
                    hash: hash.to_hex().to_string(),
                    size,
                    last_verified: now,
                },
            );
        }
        Ok(m)
    }
}

/// Walk a directory and collect relative paths of files not in `known` and not matching `excludes`.
fn find_new_files(
    root_dir: &Path,
    known: &HashMap<String, ManifestEntry>,
    excludes: Option<&GlobSet>,
) -> io::Result<Vec<String>> {
    let mut new_files = Vec::new();
    for entry in walkdir::WalkDir::new(root_dir) {
        let entry =
            entry.map_err(|e| io::Error::other(format!("failed to read directory entry: {e}")))?;
        if !entry.file_type().is_file() || entry.file_name() == MANIFEST_FILENAME {
            continue;
        }
        let rel_path = path_to_utf8(
            entry
                .path()
                .strip_prefix(root_dir)
                .expect("path must be under root_dir"),
        )?;
        if known.contains_key(&rel_path) {
            continue;
        }
        if let Some(set) = excludes {
            if set.is_match(&rel_path) {
                continue;
            }
        }
        new_files.push(rel_path);
    }
    Ok(new_files)
}

/// Verify files under `root_dir` against an existing manifest.
pub fn check(root_dir: &Path, manifest: &Manifest) -> io::Result<VerifySummary> {
    check_with_threads(root_dir, manifest, 1, None)
}

/// Verify with the specified number of threads.
pub fn check_with_threads(
    root_dir: &Path,
    manifest: &Manifest,
    threads: usize,
    progress: Option<&ProgressBar>,
) -> io::Result<VerifySummary> {
    let threads = threads.max(1);
    let glob_set = build_glob_set(&manifest.exclude_patterns)?;

    let summary = if threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        let entries: Vec<_> = manifest.entries.iter().collect();

        enum CheckResult {
            Ok(String, String, u64),      // path, hash_hex, size
            Changed(String, String, u64), // path, hash_hex, size
            Missing(String),
        }

        let results: Vec<CheckResult> = pool.install(|| {
            entries
                .par_iter()
                .map(|(rel_path, entry)| {
                    let abs_path = root_dir.join(rel_path);
                    match hash_file_with_advise(&abs_path, true) {
                        Err(e) if e.kind() == io::ErrorKind::NotFound => {
                            if let Some(pb) = progress {
                                pb.inc(1);
                            }
                            Ok(CheckResult::Missing((*rel_path).clone()))
                        }
                        Err(e) => Err(e),
                        Ok((hash, size)) => {
                            let hex = hash.to_hex().to_string();
                            if let Some(pb) = progress {
                                pb.inc(1);
                            }
                            if hex == entry.hash {
                                Ok(CheckResult::Ok((*rel_path).clone(), hex, size))
                            } else {
                                Ok(CheckResult::Changed((*rel_path).clone(), hex, size))
                            }
                        }
                    }
                })
                .collect::<io::Result<Vec<_>>>()
        })?;

        let mut summary = VerifySummary::default();
        for result in results {
            match result {
                CheckResult::Ok(p, h, s) => {
                    summary.computed_hashes.insert(p, (h, s));
                    summary.ok += 1;
                }
                CheckResult::Changed(p, h, s) => {
                    summary.computed_hashes.insert(p.clone(), (h, s));
                    summary.changed.push(p);
                }
                CheckResult::Missing(p) => summary.missing.push(p),
            }
        }

        // Detect new files
        summary.new = find_new_files(root_dir, &manifest.entries, glob_set.as_ref())?;

        summary
    } else {
        let mut summary = VerifySummary::default();

        for (rel_path, entry) in &manifest.entries {
            let abs_path = root_dir.join(rel_path);
            match hash_file_with_advise(&abs_path, true) {
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    summary.missing.push(rel_path.clone());
                }
                Err(e) => return Err(e),
                Ok((hash, size)) => {
                    let hex = hash.to_hex().to_string();
                    if hex == entry.hash {
                        summary
                            .computed_hashes
                            .insert(rel_path.clone(), (hex, size));
                        summary.ok += 1;
                    } else {
                        summary
                            .computed_hashes
                            .insert(rel_path.clone(), (hex, size));
                        summary.changed.push(rel_path.clone());
                    }
                }
            }
            if let Some(pb) = progress {
                pb.inc(1);
            }
        }

        let new = find_new_files(root_dir, &manifest.entries, glob_set.as_ref())?;
        summary.new = new;

        summary
    };

    Ok(summary)
}

/// The default manifest filename.
pub const MANIFEST_FILENAME: &str = ".integritas-manifest.json";

/// Determine the default manifest path for a given directory.
pub fn manifest_path(root_dir: &Path) -> PathBuf {
    root_dir.join(MANIFEST_FILENAME)
}

/// Summary of differences between two manifests.
#[derive(Debug, Default)]
pub struct DiffSummary {
    /// Files present in both with matching hashes.
    pub unchanged: u32,
    /// Files present in both but with different hashes.
    pub changed: Vec<String>,
    /// Files only in the old manifest (removed).
    pub removed: Vec<String>,
    /// Files only in the new manifest (added).
    pub added: Vec<String>,
}

/// Build an updated manifest from check results.
/// Uses already-computed hashes for OK/CHANGED files, hashes NEW files,
/// and drops MISSING files.
pub fn build_updated_manifest(
    root_dir: &Path,
    summary: &VerifySummary,
    old_manifest: &Manifest,
    threads: usize,
    progress: Option<&ProgressBar>,
) -> io::Result<Manifest> {
    let now = Utc::now();
    let threads = threads.max(1);

    let mut m = Manifest::new();
    m.exclude_patterns
        .clone_from(&old_manifest.exclude_patterns);

    // Add OK and CHANGED files from computed_hashes
    for (path, (hash, size)) in &summary.computed_hashes {
        m.entries.insert(
            path.clone(),
            ManifestEntry {
                hash: hash.clone(),
                size: *size,
                last_verified: now,
            },
        );
    }

    // Hash NEW files
    if !summary.new.is_empty() {
        let new_paths: Vec<PathBuf> = summary.new.iter().map(|p| root_dir.join(p)).collect();

        if threads > 1 && new_paths.len() > 1 {
            let pool = rayon::ThreadPoolBuilder::new()
                .num_threads(threads)
                .build()
                .map_err(|e| io::Error::other(e.to_string()))?;

            let entries: Vec<(String, ManifestEntry)> = pool.install(|| {
                new_paths
                    .par_iter()
                    .map(|abs_path| {
                        let rel_path = path_to_utf8(
                            abs_path
                                .strip_prefix(root_dir)
                                .expect("path must be under root_dir"),
                        )?;
                        let (hash, size) = hash_file_with_advise(abs_path, true)?;
                        if let Some(pb) = progress {
                            pb.inc(1);
                        }
                        Ok((
                            rel_path,
                            ManifestEntry {
                                hash: hash.to_hex().to_string(),
                                size,
                                last_verified: now,
                            },
                        ))
                    })
                    .collect::<io::Result<Vec<_>>>()
            })?;

            for (key, entry) in entries {
                m.entries.insert(key, entry);
            }
        } else {
            for abs_path in &new_paths {
                let rel_path = path_to_utf8(
                    abs_path
                        .strip_prefix(root_dir)
                        .expect("path must be under root_dir"),
                )?;
                let (hash, size) = hash_file_with_advise(abs_path, true)?;
                if let Some(pb) = progress {
                    pb.inc(1);
                }
                m.entries.insert(
                    rel_path,
                    ManifestEntry {
                        hash: hash.to_hex().to_string(),
                        size,
                        last_verified: now,
                    },
                );
            }
        }
    }

    Ok(m)
}

/// Compare two manifests and return the differences.
pub fn diff(old: &Manifest, new: &Manifest) -> DiffSummary {
    let mut summary = DiffSummary::default();

    // Check entries in old manifest
    for (path, old_entry) in &old.entries {
        match new.entries.get(path) {
            Some(new_entry) => {
                if old_entry.hash == new_entry.hash {
                    summary.unchanged += 1;
                } else {
                    summary.changed.push(path.clone());
                }
            }
            None => {
                summary.removed.push(path.clone());
            }
        }
    }

    // Find entries only in new manifest
    for path in new.entries.keys() {
        if !old.entries.contains_key(path) {
            summary.added.push(path.clone());
        }
    }

    summary
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_test_dir() -> TempDir {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("file1.txt"), b"hello").unwrap();
        fs::write(dir.path().join("file2.txt"), b"world").unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("sub/file3.txt"), b"nested").unwrap();
        dir
    }

    #[test]
    fn test_compute_finds_all_files() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        assert_eq!(manifest.entries.len(), 3);
        assert!(manifest.entries.contains_key("file1.txt"));
        assert!(manifest.entries.contains_key("file2.txt"));
        assert!(manifest.entries.contains_key("sub/file3.txt"));
    }

    #[test]
    fn test_compute_correct_hash() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        let expected = crate::hash::hash_bytes(b"hello").to_hex().to_string();
        assert_eq!(manifest.entries["file1.txt"].hash, expected);
    }

    #[test]
    fn test_check_all_ok() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.ok, 3);
        assert!(summary.changed.is_empty());
        assert!(summary.missing.is_empty());
        assert!(summary.new.is_empty());
    }

    #[test]
    fn test_check_detects_changed() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        // Modify a file
        fs::write(dir.path().join("file1.txt"), b"modified").unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.ok, 2);
        assert_eq!(summary.changed, vec!["file1.txt"]);
    }

    #[test]
    fn test_check_detects_missing() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        fs::remove_file(dir.path().join("file2.txt")).unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.ok, 2);
        assert_eq!(summary.missing, vec!["file2.txt"]);
    }

    #[test]
    fn test_check_detects_new() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        fs::write(dir.path().join("new_file.txt"), b"new").unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.ok, 3);
        assert_eq!(summary.new, vec!["new_file.txt"]);
    }

    #[test]
    fn test_manifest_round_trip() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        let manifest_file = dir.path().join("manifest.json");
        manifest.save(&manifest_file).unwrap();
        let loaded = Manifest::load(&manifest_file).unwrap();
        assert_eq!(manifest.entries.len(), loaded.entries.len());
        for (key, entry) in &manifest.entries {
            assert_eq!(entry, loaded.entries.get(key).unwrap());
        }
    }

    #[test]
    fn test_compute_append_adds_new_files() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        assert_eq!(manifest.entries.len(), 3);

        // Add a new file
        fs::write(dir.path().join("file4.txt"), b"new file").unwrap();

        // Append should only hash the new file
        let updated = compute_append(dir.path(), Some(&manifest), 1, &[], None).unwrap();
        assert_eq!(updated.entries.len(), 4);
        assert!(updated.entries.contains_key("file4.txt"));

        // Existing entries should be preserved (same hash)
        assert_eq!(
            updated.entries["file1.txt"].hash,
            manifest.entries["file1.txt"].hash
        );
    }

    #[test]
    fn test_compute_append_removes_deleted_files() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();

        // Delete a file
        fs::remove_file(dir.path().join("file2.txt")).unwrap();

        let updated = compute_append(dir.path(), Some(&manifest), 1, &[], None).unwrap();
        assert_eq!(updated.entries.len(), 2);
        assert!(!updated.entries.contains_key("file2.txt"));
    }

    #[test]
    fn test_compute_append_no_existing_manifest() {
        let dir = create_test_dir();
        // Append with no existing manifest should compute everything
        let manifest = compute_append(dir.path(), None, 1, &[], None).unwrap();
        assert_eq!(manifest.entries.len(), 3);
    }

    #[test]
    fn test_compute_excludes_files() {
        let dir = create_test_dir();
        fs::write(dir.path().join("debug.tmp"), b"temp data").unwrap();
        fs::write(dir.path().join("notes.log"), b"log data").unwrap();

        let excludes = vec!["*.tmp".to_string(), "*.log".to_string()];
        let manifest = compute_with_threads(dir.path(), 1, None, &excludes).unwrap();

        assert_eq!(manifest.entries.len(), 3); // only file1.txt, file2.txt, sub/file3.txt
        assert!(!manifest.entries.contains_key("debug.tmp"));
        assert!(!manifest.entries.contains_key("notes.log"));
        assert_eq!(manifest.exclude_patterns, excludes);
    }

    #[test]
    fn test_check_excludes_new_files_matching_pattern() {
        let dir = create_test_dir();
        let excludes = vec!["*.tmp".to_string()];
        let manifest = compute_with_threads(dir.path(), 1, None, &excludes).unwrap();

        // Add a .tmp file — should NOT be reported as NEW
        fs::write(dir.path().join("scratch.tmp"), b"temp").unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert!(summary.new.is_empty());
        assert_eq!(summary.ok, 3);
    }

    #[test]
    fn test_compute_parallel_correctness() {
        let dir = create_test_dir();
        // Add more files to exercise parallelism
        for i in 0..20 {
            fs::write(
                dir.path().join(format!("par_{i}.txt")),
                format!("data {i}").as_bytes(),
            )
            .unwrap();
        }

        let sequential = compute_with_threads(dir.path(), 1, None, &[]).unwrap();
        let parallel = compute_with_threads(dir.path(), 4, None, &[]).unwrap();

        assert_eq!(sequential.entries.len(), parallel.entries.len());
        for (path, entry) in &sequential.entries {
            let par_entry = parallel
                .entries
                .get(path)
                .expect("missing in parallel result");
            assert_eq!(entry.hash, par_entry.hash, "hash mismatch for {path}");
            assert_eq!(entry.size, par_entry.size);
        }
    }

    #[test]
    fn test_diff_identical_manifests() {
        let dir = create_test_dir();
        let m = compute(dir.path()).unwrap();
        let summary = diff(&m, &m);
        assert_eq!(summary.unchanged, 3);
        assert!(summary.changed.is_empty());
        assert!(summary.added.is_empty());
        assert!(summary.removed.is_empty());
    }

    #[test]
    fn test_diff_detects_changes() {
        let dir = create_test_dir();
        let old = compute(dir.path()).unwrap();

        // Modify a file and add a new one, remove one
        fs::write(dir.path().join("file1.txt"), b"modified").unwrap();
        fs::write(dir.path().join("new.txt"), b"brand new").unwrap();
        fs::remove_file(dir.path().join("file2.txt")).unwrap();

        let new = compute(dir.path()).unwrap();
        let summary = diff(&old, &new);

        assert_eq!(summary.unchanged, 1); // sub/file3.txt
        assert!(summary.changed.contains(&"file1.txt".to_string()));
        assert!(summary.added.contains(&"new.txt".to_string()));
        assert!(summary.removed.contains(&"file2.txt".to_string()));
    }

    #[test]
    fn test_compute_append_respects_excludes() {
        let dir = create_test_dir();
        let excludes = vec!["*.tmp".to_string()];
        let manifest = compute_with_threads(dir.path(), 1, None, &excludes).unwrap();

        // Add a .tmp file and a .txt file
        fs::write(dir.path().join("cache.tmp"), b"temp").unwrap();
        fs::write(dir.path().join("file4.txt"), b"real").unwrap();

        let updated = compute_append(dir.path(), Some(&manifest), 1, &excludes, None).unwrap();
        assert_eq!(updated.entries.len(), 4); // 3 original + file4.txt
        assert!(!updated.entries.contains_key("cache.tmp"));
        assert!(updated.entries.contains_key("file4.txt"));
    }

    #[test]
    fn test_build_updated_manifest() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();

        // Modify a file and add a new one, remove one
        fs::write(dir.path().join("file1.txt"), b"modified").unwrap();
        fs::write(dir.path().join("new_file.txt"), b"brand new").unwrap();
        fs::remove_file(dir.path().join("file2.txt")).unwrap();

        // Run check to get summary with computed hashes
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.changed.len(), 1);
        assert_eq!(summary.missing.len(), 1);
        assert_eq!(summary.new.len(), 1);

        // Build updated manifest
        let updated = build_updated_manifest(dir.path(), &summary, &manifest, 1, None).unwrap();

        // Should have: file1.txt (changed hash), sub/file3.txt (ok), new_file.txt (new)
        assert_eq!(updated.entries.len(), 3);
        assert!(updated.entries.contains_key("file1.txt"));
        assert!(updated.entries.contains_key("sub/file3.txt"));
        assert!(updated.entries.contains_key("new_file.txt"));
        assert!(!updated.entries.contains_key("file2.txt")); // missing = removed

        // Verify the changed file has the new hash
        let expected_hash = crate::hash::hash_bytes(b"modified").to_hex().to_string();
        assert_eq!(updated.entries["file1.txt"].hash, expected_hash);

        // Verify the new file was hashed correctly
        let expected_new = crate::hash::hash_bytes(b"brand new").to_hex().to_string();
        assert_eq!(updated.entries["new_file.txt"].hash, expected_new);
    }
}
