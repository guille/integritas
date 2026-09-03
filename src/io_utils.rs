//! I/O performance utilities: fadvise, inode sorting.

use globset::GlobSet;
use std::fs;
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};
use walkdir::DirEntryExt;

/// Hint to the kernel that we'll read this file sequentially.
/// Call before reading.
pub fn advise_sequential(file: &fs::File) {
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_SEQUENTIAL);
    }
}

/// Hint to the kernel that we're done with this file's pages.
/// Call after reading to avoid polluting the page cache.
pub fn advise_dontneed(file: &fs::File) {
    unsafe {
        libc::posix_fadvise(file.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED);
    }
}

/// A file discovered during a directory walk.
#[derive(Debug)]
pub struct WalkedFile {
    /// Absolute path (rooted at the walk root).
    pub abs: PathBuf,
    /// Path relative to the walk root, as UTF-8 (manifest key).
    pub rel: String,
    /// Inode number, taken from the dirent (no extra stat).
    pub ino: u64,
}

/// Walk all files under `root`, skipping the manifest file and anything
/// matching `excludes` (directories matching a pattern are pruned entirely,
/// so their subtrees are never visited). Results are sorted by inode number,
/// which reduces disk seeking on rotational drives.
pub fn walk_files(root: &Path, excludes: Option<&GlobSet>) -> std::io::Result<Vec<WalkedFile>> {
    let mut files: Vec<WalkedFile> = Vec::new();

    let walker = walkdir::WalkDir::new(root).into_iter().filter_entry(|e| {
        // Prune excluded directories so their subtrees are never walked.
        if e.depth() == 0 || !e.file_type().is_dir() {
            return true;
        }
        match (
            excludes,
            e.path().strip_prefix(root).ok().and_then(Path::to_str),
        ) {
            (Some(set), Some(rel)) => !set.is_match(rel),
            _ => true,
        }
    });

    for entry in walker {
        let entry = entry
            .map_err(|e| std::io::Error::other(format!("failed to read directory entry: {e}")))?;
        if !entry.file_type().is_file() || entry.file_name() == crate::manifest::MANIFEST_FILENAME {
            continue;
        }
        let rel_path = entry
            .path()
            .strip_prefix(root)
            .expect("walkdir path must start with root");
        // Reject non-UTF-8 paths early — our manifest format requires UTF-8
        let Some(rel) = rel_path.to_str() else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-UTF-8 path: {:?}", entry.path()),
            ));
        };
        if excludes.is_some_and(|set| set.is_match(rel)) {
            continue;
        }
        files.push(WalkedFile {
            rel: rel.to_string(),
            ino: entry.ino(),
            abs: entry.into_path(),
        });
    }

    files.sort_unstable_by_key(|f| f.ino);
    Ok(files)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_walk_files_sorted_by_inode() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("b.txt"), b"b").unwrap();
        let files = walk_files(dir.path(), None).unwrap();
        assert_eq!(files.len(), 2);
        assert!(files.windows(2).all(|w| w[0].ino <= w[1].ino));
        assert!(files.iter().all(|f| f.abs.is_absolute() || f.abs.exists()));
    }

    #[test]
    fn test_walk_files_prunes_excluded_dirs() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("keep.txt"), b"keep").unwrap();
        fs::create_dir(dir.path().join("cache")).unwrap();
        fs::write(dir.path().join("cache/blob.bin"), b"skip").unwrap();
        fs::write(dir.path().join("skip.tmp"), b"skip").unwrap();

        let set = crate::manifest::build_glob_set(&["cache".to_string(), "*.tmp".to_string()])
            .unwrap()
            .unwrap();
        let files = walk_files(dir.path(), Some(&set)).unwrap();
        let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        assert_eq!(rels, vec!["keep.txt"]);
    }

    /// `manifest::unseen_entries` shortcuts on the walked count matching the
    /// manifest's, which is only sound while no path is yielded twice.
    #[test]
    fn test_walk_files_yields_unique_relative_paths() {
        use std::os::unix::fs::symlink;

        let dir = TempDir::new().unwrap();
        fs::create_dir(dir.path().join("real")).unwrap();
        fs::write(dir.path().join("real/a.txt"), b"a").unwrap();
        // A second path to the same inode.
        fs::hard_link(dir.path().join("real/a.txt"), dir.path().join("real/b.txt")).unwrap();
        // Two more routes to the same files, plus a cycle back to the root.
        symlink(dir.path().join("real"), dir.path().join("link_dir")).unwrap();
        symlink(
            dir.path().join("real/a.txt"),
            dir.path().join("link_file.txt"),
        )
        .unwrap();
        symlink(dir.path(), dir.path().join("real/loop")).unwrap();

        let files = walk_files(dir.path(), None).unwrap();
        let rels: Vec<&str> = files.iter().map(|f| f.rel.as_str()).collect();
        let unique: std::collections::HashSet<&str> = rels.iter().copied().collect();
        assert_eq!(rels.len(), unique.len(), "duplicate path in {rels:?}");

        // Symlinks are not followed, so neither the aliases nor the cycle are
        // walked; the hardlink is a distinct path and counts on its own.
        let mut sorted = rels;
        sorted.sort_unstable();
        assert_eq!(sorted, vec!["real/a.txt", "real/b.txt"]);
    }

    #[test]
    fn test_rejects_non_utf8_path() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let dir = TempDir::new().unwrap();
        // Create a file with invalid UTF-8 in its name (0xFF byte)
        let invalid_name = OsStr::from_bytes(b"bad\xFFname.txt");
        let invalid_path = dir.path().join(invalid_name);
        fs::write(&invalid_path, b"data").unwrap();

        let result = walk_files(dir.path(), None);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("non-UTF-8"));
    }
}
