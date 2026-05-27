//! I/O performance utilities: fadvise, inode sorting.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::io::AsRawFd;
use std::path::Path;

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

/// Collect all file paths under `root` and sort by inode number.
/// This reduces disk seeking on rotational drives.
pub fn collect_sorted_by_inode(root: &Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut entries: Vec<(std::path::PathBuf, u64)> = Vec::new();

    for entry in walkdir::WalkDir::new(root).into_iter().filter(|e| {
        e.as_ref().map_or(true, |e| {
            e.file_type().is_file() && e.file_name() != crate::manifest::MANIFEST_FILENAME
        }) // keep errors so we can propagate them
    }) {
        let entry = entry
            .map_err(|e| std::io::Error::other(format!("failed to read directory entry: {e}")))?;
        if !entry.file_type().is_file() {
            continue;
        }
        // Reject non-UTF-8 paths early — our manifest format requires UTF-8
        let path = entry.path();
        if path.to_str().is_none() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("non-UTF-8 path: {path:?}"),
            ));
        }
        let metadata = entry.metadata()?;
        entries.push((entry.into_path(), metadata.ino()));
    }

    entries.sort_by_key(|e| e.1);
    Ok(entries.into_iter().map(|e| e.0).collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_collect_sorted_by_inode() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("b.txt"), b"b").unwrap();
        let files = collect_sorted_by_inode(dir.path()).unwrap();
        assert_eq!(files.len(), 2);
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

        let result = collect_sorted_by_inode(dir.path());
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("non-UTF-8"));
    }
}
