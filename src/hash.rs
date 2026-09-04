use std::cell::RefCell;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::io_utils;

/// Size of the read buffer (256 KiB).
const BUF_SIZE: usize = 256 * 1024;

/// Threshold above which we memory-map the file and hash with `update_rayon`.
const RAYON_THRESHOLD: u64 = 4 * 1024 * 1024; // 4 MiB

/// Hash a file using BLAKE3 with a 256 KiB read buffer.
/// Returns the hash and file size.
#[must_use = "hash result should not be discarded"]
pub fn hash_file(path: &Path) -> io::Result<(blake3::Hash, u64)> {
    hash_file_with_advise(path, false)
}

/// Hash a file with optional `posix_fadvise` hints.
/// When `use_fadvise` is true, hints SEQUENTIAL before reading and DONTNEED after.
#[must_use = "hash result should not be discarded"]
pub fn hash_file_with_advise(path: &Path, use_fadvise: bool) -> io::Result<(blake3::Hash, u64)> {
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;
    let size = metadata.len();

    if use_fadvise {
        io_utils::advise_sequential(&file);
    }

    let hash = if size >= RAYON_THRESHOLD {
        hash_large_file(&mut file)?
    } else if size < BUF_SIZE as u64 {
        hash_tiny_file(&mut file, size)?
    } else {
        hash_small_file(&mut file)?
    };

    if use_fadvise {
        io_utils::advise_dontneed(&file);
    }

    Ok((hash, size))
}

/// Hash a file smaller than the read buffer by reading it whole.
/// Avoids zeroing a 256 KiB buffer for files much smaller than that.
fn hash_tiny_file(file: &mut File, size: u64) -> io::Result<blake3::Hash> {
    // One spare byte lets read_to_end hit EOF without growing the buffer.
    #[allow(clippy::cast_possible_truncation)] // size < BUF_SIZE
    let mut data = Vec::with_capacity(size as usize + 1);
    file.read_to_end(&mut data)?;
    Ok(blake3::hash(&data))
}

thread_local! {
    /// Read buffer, zeroed once per thread rather than per file.
    static BUF: RefCell<Vec<u8>> = RefCell::new(vec![0u8; BUF_SIZE]);
}

/// Hash a small file sequentially.
fn hash_small_file(file: &mut File) -> io::Result<blake3::Hash> {
    BUF.with_borrow_mut(|buf| {
        let mut hasher = blake3::Hasher::new();
        loop {
            let n = file.read(buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(hasher.finalize())
    })
}

/// Hash a large file by memory-mapping it and hashing with BLAKE3's
/// rayon-based parallelism across the whole file — no read syscalls or
/// buffer copies, and page faults overlap with hashing.
/// Falls back to chunked streaming if the file cannot be mapped.
fn hash_large_file(file: &mut File) -> io::Result<blake3::Hash> {
    // SAFETY: mapping a file another process truncates concurrently can
    // fault. Like b3sum, we accept this in exchange for the throughput.
    match unsafe { memmap2::Mmap::map(&*file) } {
        Ok(map) => {
            let _ = map.advise(memmap2::Advice::Sequential);
            let mut hasher = blake3::Hasher::new();
            hasher.update_rayon(&map);
            Ok(hasher.finalize())
        }
        Err(_) => hash_large_file_streaming(file),
    }
}

/// Streaming fallback for large files on filesystems where mmap fails.
fn hash_large_file_streaming(file: &mut File) -> io::Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    // Use 4 MiB chunks for rayon — large enough to benefit from parallel BLAKE3 compression
    const RAYON_CHUNK: usize = 4 * 1024 * 1024;

    let mut buf = vec![0u8; RAYON_CHUNK];
    loop {
        let n = read_exact_or_eof(file, &mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update_rayon(&buf[..n]);
    }

    Ok(hasher.finalize())
}

/// Read as much as possible into buf, returning bytes read (0 = EOF).
fn read_exact_or_eof(reader: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut total = 0;
    while total < buf.len() {
        let n = reader.read(&mut buf[total..])?;
        if n == 0 {
            break;
        }
        total += n;
    }
    Ok(total)
}

/// Hash raw bytes using BLAKE3 (for testing).
#[must_use]
pub fn hash_bytes(data: &[u8]) -> blake3::Hash {
    blake3::hash(data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_hash_known_value() {
        // BLAKE3 hash of empty input
        let hash = hash_bytes(b"");
        assert_eq!(
            hash.to_hex().to_string(),
            "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262"
        );
    }

    #[test]
    fn test_hash_file_matches_bytes() {
        let data = b"hello world";
        let expected = hash_bytes(data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        let (got, size) = hash_file(tmp.path()).unwrap();
        assert_eq!(got, expected);
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_hash_file_with_advise_matches() {
        let data = b"test data with fadvise";
        let expected = hash_bytes(data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(data).unwrap();
        tmp.flush().unwrap();

        let (got, size) = hash_file_with_advise(tmp.path(), true).unwrap();
        assert_eq!(got, expected);
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_hash_large_file_rayon() {
        // Exercise the mmap + rayon path directly — a 2 MB file would
        // normally take the buffered path (threshold is 4 MiB).
        let data: Vec<u8> = (0..2_000_000u64)
            .map(|i| u8::try_from(i % 256).unwrap())
            .collect();
        let expected = hash_bytes(&data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let mut file = File::open(tmp.path()).unwrap();
        let got = hash_large_file(&mut file).unwrap();
        assert_eq!(got, expected);

        let mut file = File::open(tmp.path()).unwrap();
        let got_streaming = hash_large_file_streaming(&mut file).unwrap();
        assert_eq!(got_streaming, expected);
    }

    #[test]
    fn test_hash_file_not_found() {
        let result = hash_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }
}
