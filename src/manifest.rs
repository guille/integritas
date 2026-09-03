use globset::{Glob, GlobSet, GlobSetBuilder};
use indicatif::ProgressBar;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs;
use std::io;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::hash::hash_file_with_advise;
use crate::io_utils;

/// Hasher for the path-keyed collections below. Keys are relative paths from
/// walking a user-nominated tree, so std's HashDoS-resistant `SipHash` buys
/// nothing an attacker with write access to that tree could not bypass anyway.
pub type PathHasher = foldhash::fast::RandomState;

/// A collection keyed by relative path.
pub type PathMap<V> = HashMap<String, V, PathHasher>;
pub type PathSet<'a> = HashSet<&'a str, PathHasher>;

/// A single entry in the manifest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    /// Hex-encoded BLAKE3 hash.
    pub hash: String,
    /// File size in bytes.
    pub size: u64,
}

/// Buffer for streaming the manifest out; `to_writer_pretty` issues many tiny
/// writes, so the default 8 KiB would mean thousands of syscalls.
const WRITE_BUF_SIZE: usize = 256 * 1024;

/// The manifest format version this build writes.
pub const MANIFEST_VERSION: u32 = 2;

/// Oldest format version that can read files this build writes.
/// Only bumps when a field is removed or changes meaning.
pub const MIN_READER_VERSION: u32 = 2;

fn v1() -> u32 {
    1
}

/// Version fields only, for diagnosing a failed full parse.
#[derive(Deserialize)]
struct Header {
    #[serde(default = "v1")]
    min_reader_version: u32,
}

/// The full manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    /// Format version of the build that wrote this file.
    pub version: u32,
    /// Oldest format version that can read this file correctly.
    /// Absent in v1 files.
    #[serde(default = "v1")]
    pub min_reader_version: u32,
    /// Glob patterns used to exclude files during compute.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_patterns: Vec<String>,
    /// Entries keyed by relative path.
    #[serde(serialize_with = "serialize_sorted")]
    pub entries: PathMap<ManifestEntry>,
}

/// Emit entries in key order. `HashMap` iteration order is randomized per
/// process, so without this two saves of an identical manifest differ byte for
/// byte, which makes manifests noisy under `git diff`.
fn serialize_sorted<S: serde::Serializer>(
    entries: &PathMap<ManifestEntry>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    use serde::ser::SerializeMap;

    let mut pairs: Vec<(&String, &ManifestEntry)> = entries.iter().collect();
    pairs.sort_unstable_by(|a, b| a.0.cmp(b.0));

    let mut map = serializer.serialize_map(Some(pairs.len()))?;
    for (key, entry) in pairs {
        map.serialize_entry(key, entry)?;
    }
    map.end()
}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            version: MANIFEST_VERSION,
            min_reader_version: MIN_READER_VERSION,
            exclude_patterns: Vec::new(),
            entries: PathMap::default(),
        }
    }

    /// Load a manifest from a JSON file.
    /// Fails with `InvalidData` on malformed JSON or a format this build cannot read.
    pub fn load(path: &Path) -> io::Result<Self> {
        // Keep `read_to_string` + `from_str`: one bulk UTF-8 pass is cheaper
        // than the per-string validation `from_slice`'s reader has to do.
        let content = fs::read_to_string(path)?;
        let manifest: Self = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                // A newer format may have dropped a field we require.
                if let Ok(header) = serde_json::from_str::<Header>(&content) {
                    check_readable(header.min_reader_version)?;
                }
                return Err(io::Error::new(io::ErrorKind::InvalidData, e));
            }
        };
        check_readable(manifest.min_reader_version)?;
        Ok(manifest)
    }

    /// Fail if rewriting this manifest with this build would lose data.
    /// Update paths rebuild from scratch, so fields of a newer format are dropped.
    pub fn ensure_rewritable(&self) -> io::Result<()> {
        if self.version > MANIFEST_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "manifest format version {} is newer than this build writes ({MANIFEST_VERSION}); \
                     rewriting it would drop fields this build does not understand",
                    self.version
                ),
            ));
        }
        Ok(())
    }

    /// Save the manifest to a JSON file atomically (write to tmp, then rename).
    pub fn save(&self, path: &Path) -> io::Result<()> {
        // Write to a sibling temp file, then atomically rename
        let dir = path.parent().unwrap_or(Path::new("."));
        let tmp_path = dir.join(format!(".integritas-manifest-{}.tmp", std::process::id()));

        // Serializing straight into the file avoids materializing the whole
        // document as a String first, which on a large manifest is a second
        // copy of the output and the peak of the process.
        let write = || -> io::Result<()> {
            let mut writer =
                io::BufWriter::with_capacity(WRITE_BUF_SIZE, fs::File::create(&tmp_path)?);
            serde_json::to_writer_pretty(&mut writer, self).map_err(io::Error::other)?;
            writer.flush()
        };

        write()
            .and_then(|()| fs::rename(&tmp_path, path))
            .inspect_err(|_| {
                let _ = fs::remove_file(&tmp_path);
            })
    }
}

fn check_readable(min_reader_version: u32) -> io::Result<()> {
    if min_reader_version > MANIFEST_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "manifest requires format version {min_reader_version} or newer to read \
                 (this build supports {MANIFEST_VERSION}); upgrade integritas"
            ),
        ));
    }
    Ok(())
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

/// Summary of a verification run.
#[derive(Debug, Default)]
pub struct VerifySummary {
    pub ok: u32,
    pub changed: Vec<String>,
    pub missing: Vec<String>,
    pub new: Vec<String>,
    /// Hashes of OK and CHANGED files (path -> (`hash_hex`, size)), so the
    /// manifest can be rebuilt without re-hashing. Empty unless requested.
    pub computed_hashes: PathMap<(String, u64)>,
}

/// Hash one file and build its manifest entry, ticking the progress bar.
fn hash_entry(
    abs: &Path,
    rel: &str,
    progress: Option<&ProgressBar>,
) -> io::Result<(String, ManifestEntry)> {
    let (hash, size) = hash_file_with_advise(abs, true)?;
    if let Some(pb) = progress {
        pb.inc(1);
    }
    Ok((
        rel.to_string(),
        ManifestEntry {
            hash: hash.to_hex().to_string(),
            size,
        },
    ))
}

/// Hash a batch of files into manifest entries.
/// Runs in a dedicated rayon pool when there is more than one file to hash.
fn hash_all(
    files: &[(&Path, &str)],
    threads: usize,
    progress: Option<&ProgressBar>,
) -> io::Result<Vec<(String, ManifestEntry)>> {
    if threads > 1 && files.len() > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        pool.install(|| {
            files
                .par_iter()
                .map(|(abs, rel)| hash_entry(abs, rel, progress))
                .collect()
        })
    } else {
        files
            .iter()
            .map(|(abs, rel)| hash_entry(abs, rel, progress))
            .collect()
    }
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
    let threads = threads.max(1);

    // Merge excludes: keep existing manifest's excludes + new CLI excludes
    let mut final_excludes: Vec<String> = existing
        .map(|m| m.exclude_patterns.clone())
        .unwrap_or_default();
    for pat in excludes {
        if !final_excludes.contains(pat) {
            final_excludes.push(pat.clone());
        }
    }

    // Collect all current files, applying the merged excludes
    let glob_set = build_glob_set(&final_excludes)?;
    let all_files = io_utils::walk_files(root_dir, glob_set.as_ref())?;

    // Determine which files need hashing (not in existing manifest)
    let existing_entries = existing.map(|m| &m.entries);
    let mut manifest = Manifest::new();
    manifest.exclude_patterns = final_excludes;

    let mut new_files: Vec<&io_utils::WalkedFile> = Vec::new();

    for f in &all_files {
        // If already in manifest, keep the existing entry
        if let Some(entry) = existing_entries.and_then(|entries| entries.get(&f.rel)) {
            manifest.entries.insert(f.rel.clone(), entry.clone());
            continue;
        }
        // New file — needs hashing
        new_files.push(f);
    }

    let to_hash: Vec<(&Path, &str)> = new_files
        .iter()
        .map(|f| (f.abs.as_path(), f.rel.as_str()))
        .collect();
    for (key, entry) in hash_all(&to_hash, threads, progress)? {
        manifest.entries.insert(key, entry);
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
    let threads = threads.max(1);

    // Single walk: prunes excluded dirs and returns files in inode order
    // (helps on HDD, no-op perf cost on SSD)
    let glob_set = build_glob_set(excludes)?;
    let files = io_utils::walk_files(root_dir, glob_set.as_ref())?;

    let mut m = Manifest::new();
    m.exclude_patterns = excludes.to_vec();

    let to_hash: Vec<(&Path, &str)> = files
        .iter()
        .map(|f| (f.abs.as_path(), f.rel.as_str()))
        .collect();
    for (key, entry) in hash_all(&to_hash, threads, progress)? {
        m.entries.insert(key, entry);
    }
    Ok(m)
}

/// Verify files under `root_dir` against an existing manifest.
pub fn check(root_dir: &Path, manifest: &Manifest) -> io::Result<VerifySummary> {
    check_with_threads(root_dir, manifest, 1, None, true)
}

/// Verify with the specified number of threads.
/// `keep_hashes` populates `VerifySummary::computed_hashes`; skip it when the
/// manifest will not be rebuilt, as it costs two `String`s per file.
pub fn check_with_threads(
    root_dir: &Path,
    manifest: &Manifest,
    threads: usize,
    progress: Option<&ProgressBar>,
    keep_hashes: bool,
) -> io::Result<VerifySummary> {
    let threads = threads.max(1);
    let glob_set = build_glob_set(&manifest.exclude_patterns)?;

    // Single walk: discovers new files and yields known files in inode order
    // (reduces seeking on rotational drives).
    let walked = io_utils::walk_files(root_dir, glob_set.as_ref())?;

    let mut to_verify: Vec<(String, PathBuf)> = Vec::new();
    let mut new_files: Vec<String> = Vec::new();
    for f in walked {
        if manifest.entries.contains_key(&f.rel) {
            to_verify.push((f.rel, f.abs));
        } else {
            new_files.push(f.rel);
        }
    }

    // Manifest entries the walk didn't see are usually missing, but may just
    // be hidden from the walk (e.g. behind an exclude pattern added after
    // compute) — try to hash them and let NotFound decide. These have no
    // dirent to read an inode from, so they're appended out of inode order.
    let unseen: Vec<(String, PathBuf)> = {
        let seen: PathSet = to_verify.iter().map(|(rel, _)| rel.as_str()).collect();
        manifest
            .entries
            .keys()
            .filter(|rel| !seen.contains(rel.as_str()))
            .map(|rel| (rel.clone(), root_dir.join(rel)))
            .collect()
    };
    to_verify.extend(unseen);

    enum Status {
        Ok,
        Changed,
        Missing,
    }
    type Computed = Option<(String, u64)>;

    let verify_one = |rel: &str, abs: &PathBuf| -> io::Result<(Status, Computed)> {
        let result = match hash_file_with_advise(abs, true) {
            Err(e) if e.kind() == io::ErrorKind::NotFound => (Status::Missing, None),
            Err(e) => return Err(e),
            Ok((hash, size)) => {
                let hex = hash.to_hex().to_string();
                let status = if hex == manifest.entries[rel].hash {
                    Status::Ok
                } else {
                    Status::Changed
                };
                (status, keep_hashes.then_some((hex, size)))
            }
        };
        if let Some(pb) = progress {
            pb.inc(1);
        }
        Ok(result)
    };

    let results: Vec<(Status, Computed)> = if threads > 1 {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .map_err(|e| io::Error::other(e.to_string()))?;

        pool.install(|| {
            to_verify
                .par_iter()
                .map(|(rel, abs)| verify_one(rel, abs))
                .collect::<io::Result<Vec<_>>>()
        })?
    } else {
        to_verify
            .iter()
            .map(|(rel, abs)| verify_one(rel, abs))
            .collect::<io::Result<Vec<_>>>()?
    };

    let mut summary = VerifySummary {
        new: new_files,
        ..VerifySummary::default()
    };
    for ((rel, _), (status, computed)) in to_verify.into_iter().zip(results) {
        match status {
            Status::Ok => summary.ok += 1,
            Status::Changed => summary.changed.push(rel.clone()),
            Status::Missing => summary.missing.push(rel.clone()),
        }
        if let Some(c) = computed {
            summary.computed_hashes.insert(rel, c);
        }
    }

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
            },
        );
    }

    // Hash NEW files
    let new_paths: Vec<PathBuf> = summary.new.iter().map(|rel| root_dir.join(rel)).collect();
    let to_hash: Vec<(&Path, &str)> = new_paths
        .iter()
        .zip(&summary.new)
        .map(|(abs, rel)| (abs.as_path(), rel.as_str()))
        .collect();
    for (key, entry) in hash_all(&to_hash, threads, progress)? {
        m.entries.insert(key, entry);
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
    fn test_check_verifies_entries_hidden_by_late_exclude() {
        let dir = create_test_dir();
        let mut manifest = compute(dir.path()).unwrap();

        // An exclude added after compute hides file1.txt from the walk, but
        // the file still exists on disk — it must verify OK, not MISSING.
        manifest.exclude_patterns.push("file1.txt".to_string());
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.ok, 3);
        assert!(summary.missing.is_empty());

        // A hidden entry that actually changed is still caught.
        fs::write(dir.path().join("file1.txt"), b"modified").unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.changed, vec!["file1.txt"]);

        // And a hidden entry that is truly gone is reported missing.
        fs::remove_file(dir.path().join("file1.txt")).unwrap();
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.missing, vec!["file1.txt"]);
    }

    #[test]
    fn test_check_parallel_matches_sequential() {
        let dir = create_test_dir();
        for i in 0..20 {
            fs::write(
                dir.path().join(format!("par_{i}.txt")),
                format!("data {i}").as_bytes(),
            )
            .unwrap();
        }
        let manifest = compute(dir.path()).unwrap();

        fs::write(dir.path().join("par_0.txt"), b"changed").unwrap();
        fs::write(dir.path().join("par_1.txt"), b"also changed").unwrap();
        fs::remove_file(dir.path().join("par_2.txt")).unwrap();
        fs::write(dir.path().join("brand_new.txt"), b"new").unwrap();

        let sorted = |mut v: Vec<String>| {
            v.sort();
            v
        };
        let seq = check_with_threads(dir.path(), &manifest, 1, None, true).unwrap();
        let par = check_with_threads(dir.path(), &manifest, 4, None, true).unwrap();

        assert_eq!(sorted(par.changed), vec!["par_0.txt", "par_1.txt"]);
        assert_eq!(par.missing, vec!["par_2.txt"]);
        assert_eq!(par.new, vec!["brand_new.txt"]);
        assert_eq!(seq.ok, par.ok);
        assert_eq!(seq.computed_hashes, par.computed_hashes);
    }

    #[test]
    fn test_check_without_keep_hashes_leaves_map_empty() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        fs::write(dir.path().join("file1.txt"), b"changed").unwrap();

        let summary = check_with_threads(dir.path(), &manifest, 1, None, false).unwrap();
        assert_eq!(summary.ok, 2);
        assert_eq!(summary.changed, vec!["file1.txt"]);
        assert!(summary.computed_hashes.is_empty());
    }

    #[test]
    fn test_build_updated_manifest_parallel_matches_sequential() {
        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        // Several new files to exercise the parallel hashing branch
        for i in 0..10 {
            fs::write(
                dir.path().join(format!("new_{i}.txt")),
                format!("new {i}").as_bytes(),
            )
            .unwrap();
        }
        let summary = check(dir.path(), &manifest).unwrap();
        assert_eq!(summary.new.len(), 10);

        let seq = build_updated_manifest(dir.path(), &summary, &manifest, 1, None).unwrap();
        let par = build_updated_manifest(dir.path(), &summary, &manifest, 4, None).unwrap();

        assert_eq!(seq.entries.len(), 13);
        assert_eq!(seq.entries.len(), par.entries.len());
        for (path, entry) in &seq.entries {
            let par_entry = par.entries.get(path).expect("missing in parallel result");
            assert_eq!(entry.hash, par_entry.hash, "hash mismatch for {path}");
            assert_eq!(entry.size, par_entry.size);
        }
    }

    #[test]
    fn test_save_is_byte_identical_regardless_of_insertion_order() {
        let dir = TempDir::new().unwrap();

        let entry = |i: u32| ManifestEntry {
            hash: format!("{i:064x}"),
            size: u64::from(i),
        };

        let mut forward = Manifest::new();
        let mut backward = Manifest::new();
        for i in 0..64u32 {
            forward.entries.insert(format!("path/{i:03}.txt"), entry(i));
        }
        for i in (0..64u32).rev() {
            backward
                .entries
                .insert(format!("path/{i:03}.txt"), entry(i));
        }

        let a = dir.path().join("a.json");
        let b = dir.path().join("b.json");
        forward.save(&a).unwrap();
        backward.save(&b).unwrap();

        assert_eq!(fs::read(&a).unwrap(), fs::read(&b).unwrap());
    }

    #[test]
    fn test_load_rejects_invalid_json() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.json");
        fs::write(&path, b"not json {").unwrap();
        let err = Manifest::load(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn test_load_rejects_unreadable_min_reader_version() {
        let dir = create_test_dir();
        let mut manifest = compute(dir.path()).unwrap();
        manifest.version = MANIFEST_VERSION + 1;
        manifest.min_reader_version = MANIFEST_VERSION + 1;
        let path = dir.path().join("future.json");
        manifest.save(&path).unwrap();

        let err = Manifest::load(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("requires format version"));
    }

    #[test]
    fn test_load_accepts_newer_version_with_compatible_reader() {
        // An additive future format keeps min_reader_version at ours.
        let dir = create_test_dir();
        let mut manifest = compute(dir.path()).unwrap();
        manifest.version = MANIFEST_VERSION + 1;
        let path = dir.path().join("future.json");
        manifest.save(&path).unwrap();

        let loaded = Manifest::load(&path).unwrap();
        assert_eq!(loaded.version, MANIFEST_VERSION + 1);
        assert_eq!(loaded.entries.len(), 3);
    }

    #[test]
    fn test_load_reports_version_when_newer_format_fails_to_parse() {
        // A breaking future format that dropped `size`.
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("future.json");
        let content = format!(
            r#"{{"version": {v}, "min_reader_version": {v}, "entries": {{"a": {{"hash": "00"}}}}}}"#,
            v = MANIFEST_VERSION + 1
        );
        fs::write(&path, content).unwrap();

        let err = Manifest::load(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("requires format version"));
        assert!(!err.to_string().contains("missing field"));
    }

    #[test]
    fn test_load_v1_manifest() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("v1.json");
        fs::write(
            &path,
            br#"{
  "version": 1,
  "exclude_patterns": ["*.tmp"],
  "entries": {
    "a.txt": {
      "hash": "ea8f163db38682925e4491c5e58d4bb3506ef8c14eb78a86e908c5624a67200f",
      "size": 5,
      "last_verified": "2026-09-02T12:34:56.789012345Z"
    }
  }
}"#,
        )
        .unwrap();

        let loaded = Manifest::load(&path).unwrap();
        assert_eq!(loaded.version, 1);
        assert_eq!(loaded.min_reader_version, 1);
        assert_eq!(loaded.exclude_patterns, vec!["*.tmp"]);
        assert_eq!(loaded.entries["a.txt"].size, 5);
        loaded.ensure_rewritable().unwrap();
    }

    #[test]
    fn test_ensure_rewritable_refuses_newer_version() {
        let mut manifest = Manifest::new();
        manifest.ensure_rewritable().unwrap();
        manifest.version = MANIFEST_VERSION + 1;
        let err = manifest.ensure_rewritable().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }

    #[test]
    fn test_check_errors_on_unreadable_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = create_test_dir();
        let manifest = compute(dir.path()).unwrap();
        let target = dir.path().join("file1.txt");
        fs::set_permissions(&target, fs::Permissions::from_mode(0o000)).unwrap();
        if fs::File::open(&target).is_ok() {
            return; // running as root — permissions are not enforced
        }

        let err = check(dir.path(), &manifest).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_compute_append_merges_excludes() {
        let dir = create_test_dir();
        let manifest = compute_with_threads(dir.path(), 1, None, &["*.tmp".to_string()]).unwrap();

        fs::write(dir.path().join("cache.tmp"), b"temp").unwrap();
        fs::write(dir.path().join("notes.log"), b"log").unwrap();
        fs::write(dir.path().join("file4.txt"), b"real").unwrap();

        // CLI adds *.log and repeats *.tmp; both apply, without duplicates.
        let cli_excludes = vec!["*.log".to_string(), "*.tmp".to_string()];
        let updated = compute_append(dir.path(), Some(&manifest), 1, &cli_excludes, None).unwrap();

        assert!(!updated.entries.contains_key("cache.tmp"));
        assert!(!updated.entries.contains_key("notes.log"));
        assert!(updated.entries.contains_key("file4.txt"));
        assert_eq!(updated.exclude_patterns, vec!["*.tmp", "*.log"]);
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
