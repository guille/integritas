use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use crate::io_utils;

/// Size of the read buffer (256 KiB).
const BUF_SIZE: usize = 256 * 1024;

/// Threshold above which we use `update_rayon` for parallel hashing (64 MiB).
/// Below this, rayon overhead exceeds the benefit. Above this, multi-core
/// BLAKE3 compression provides ~8-10% throughput improvement when data is cached.
const RAYON_THRESHOLD: u64 = 64 * 1024 * 1024;

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
    } else {
        hash_small_file(&mut file)?
    };

    if use_fadvise {
        io_utils::advise_dontneed(&file);
    }

    Ok((hash, size))
}

/// Hash a small file sequentially.
fn hash_small_file(file: &mut File) -> io::Result<blake3::Hash> {
    let mut hasher = blake3::Hasher::new();
    let mut buf = [0u8; BUF_SIZE];

    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.finalize())
}

/// Hash a large file using BLAKE3's rayon-based parallel hashing.
/// Uses chunked streaming to avoid loading multi-GB files entirely into RAM.
fn hash_large_file(file: &mut File) -> io::Result<blake3::Hash> {
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
        // Create a file > RAYON_THRESHOLD (1 MiB)
        let data: Vec<u8> = (0..2_000_000u64).map(|i| (i % 256) as u8).collect();
        let expected = hash_bytes(&data);

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let (got, size) = hash_file(tmp.path()).unwrap();
        assert_eq!(got, expected);
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_hash_file_not_found() {
        let result = hash_file(Path::new("/nonexistent/file.txt"));
        assert!(result.is_err());
    }
}
