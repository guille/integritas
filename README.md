# Integritas

Fast file integrity checker using BLAKE3. An alternative to [hashdeep](https://github.com/jessek/hashdeep/) for Linux/Unix[^1] systems.

[^1]: I can't test on OSX/Windows, pretty sure it just needs a couple of `cfg` flags for it to work on those platforms.

Computes and verifies cryptographic hashes for directory trees. Stores results in a JSON manifest that can be checked later to detect changed, missing, or new files.

## Install

```sh
cargo build --release
cp target/release/integritas ~/.local/bin/
```

## Usage

### Compute a manifest

```sh
integritas compute /mnt/backup
```

Scans all files recursively, hashes them with BLAKE3, and writes `.integritas-manifest.json` in the target directory.

Options:
- `-o <path>` — write manifest to a specific path
- `-a` / `--append` — only hash new files; keep existing entries as-is
- `-e <pattern>` — exclude files matching a glob (repeatable)

### Verify against a manifest

```sh
integritas check /mnt/backup
```

Re-hashes every file and compares against the manifest. Reports changed, missing, and new files.

Options:
- `-m <path>` — use a specific manifest file
- `-r <path>` — write an HTML report
- `-p` / `--prompt` — after showing results, offer to update the manifest in-place (avoids a full re-compute)
- `--accept-new` — if new files are the only difference, add them to the manifest and exit 0; any other difference fails (or prompts) as usual

### Compare two manifests

```sh
integritas diff old.json new.json
```

Shows added, removed, and changed files between two manifests.

### Common options (on `compute` and `check`)

- `-j <N>` — number of threads (default: CPU count). Use `-j1` for HDDs.
- `-q` — quiet mode (no progress bars or status messages)

## Exit codes

- `0` — all files match / manifests identical
- `1` — differences found or errors

## Performance

Uses parallel hashing (rayon), inode-sorted file traversal, and `posix_fadvise` hints. On NVMe: ~20x faster than hashdeep for large files, ~2x for small files.

See `BENCHMARKS.md` for details.

## Manifest format

The manifest is a JSON file (`.integritas-manifest.json`) with this structure:

```json
{
  "version": 1,
  "exclude_patterns": ["*.tmp", "*.log"],
  "entries": {
    "path/to/file.txt": {
      "hash": "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
      "size": 1024,
      "last_verified": "2025-05-20T14:30:00Z"
    }
  }
}
```

Fields:
- `version` — manifest format version (currently 1); manifests with any other version are rejected
- `exclude_patterns` — globs used during compute, also applied during check
- `entries` — map of relative paths to their hash, file size, and last verification timestamp
- `hash` — hex-encoded BLAKE3 digest

The manifest file itself is excluded from scanning. Writes are atomic (temp file + rename).

## How `--prompt` works

When `check --prompt` finds differences, it shows the results and asks:

```
Update manifest to reflect current state? [y/N]
```

If accepted:
- Changed files: uses the hash already computed during verification (no re-hash)
- New files: hashes them
- Missing files: removes them from the manifest

This avoids running a full `compute` just to accept known changes.

When combined with `--accept-new`: if new files are the *only* difference no prompt is displayed and the manifest is updated, any other case else still asks.

## Requirements

- Linux/Unix (uses `posix_fadvise`, Unix inode metadata)
- Rust 1.70+
- All file paths must be valid UTF-8
