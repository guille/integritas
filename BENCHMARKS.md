# Benchmarks

## v1.0

### Setup

- **integritas**: BLAKE3, parallel file hashing via rayon, `update_rayon` for files > 64 MiB, posix_fadvise, inode-sorted traversal, release build
- **hashdeep**: v4.4, MD5+SHA256 (default dual-hash mode)
- **System**: NVMe SSD (encrypted LUKS + btrfs), 8 cores
- **Data**: Random bytes generated via `/dev/urandom`

### Results

| Test | integritas -j8 | integritas -j1 | hashdeep -j8 | hashdeep -j1 | Winner |
|------|-----------|-----------|-------------|-------------|--------|
| 1 GB single file | 0.281s | 0.382s | 5.652s | 5.615s | integritas -j8, ~20x vs hashdeep |
| 1000 × 4 KB files | 0.010s | 0.019s | 0.018s | 0.087s | integritas -j8, ~2x vs hashdeep -j8 |
| Mixed (1 GB: 3 large + 50 small) | 0.321s | 0.347s | 2.815s | 5.614s | integritas -j8, ~9x vs hashdeep -j8 |

### Analysis

- **Single large file**: integritas `-j8` is ~20x faster than hashdeep. Multi-threaded BLAKE3 compression (`update_rayon`) provides a noticeable boost over `-j1` on a single large file.
- **Many small files**: integritas `-j8` is ~2x faster than hashdeep `-j8`. hashdeep `-j1` is very slow (0.087s) — it depends heavily on parallelism for small-file workloads.
- **Mixed workload (realistic)**: integritas `-j8` (0.321s) is ~9x faster than hashdeep `-j8` (2.815s). integritas `-j1` (0.347s) is **16x faster** than hashdeep `-j1` (5.614s).
- **HDD recommendation**: Use `integritas -j1`. You'll be I/O-bound at disk sequential read speed while hashdeep struggles with CPU-bound dual-algorithm hashing.
- **SSD recommendation**: Use default (`-j` = CPU count) for maximum parallelism.

### update_rayon micro-benchmark (criterion, warm cache)

Measured effect of BLAKE3's `update_rayon` (multi-core compression) vs single-threaded:

| File size | Sequential | With update_rayon | Effect |
|-----------|-----------|------------------|--------|
| 10 MB | 3.77 ms | 3.99 ms | -5% (overhead) |
| 100 MB | 36.6 ms | 33.7 ms | +8% (benefit) |

Threshold set to 64 MiB: below this, rayon overhead exceeds benefit.

### Reproduction

```sh
./benchmarks/run.sh
```
