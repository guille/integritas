//! Build a synthetic source tree for `mise run bench-cli`.
//!
//! Usage: `mktree <dir> <file-count> <file-size>`
//!
//! Paths are shaped like a real source tree — nested and around 40 bytes — so
//! they match the keys the criterion manifest benches use.

use rayon::prelude::*;
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const COMPONENTS: usize = 32;
const MODULES: usize = 128;

fn rel_path(i: usize) -> PathBuf {
    PathBuf::from(format!(
        "src/component_{:02}/module_{:03}/file_{i:06}.rs",
        i % COMPONENTS,
        (i / COMPONENTS) % MODULES
    ))
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [root, count, size] = args.as_slice() else {
        eprintln!("usage: mktree <dir> <file-count> <file-size>");
        return ExitCode::FAILURE;
    };

    let root = Path::new(root);
    let (Ok(count), Ok(size)) = (count.parse::<usize>(), size.parse::<usize>()) else {
        eprintln!("file-count and file-size must be integers");
        return ExitCode::FAILURE;
    };

    let paths: Vec<PathBuf> = (0..count).map(|i| root.join(rel_path(i))).collect();

    // Created up front: creating them lazily from the parallel loop would race.
    let dirs: BTreeSet<&Path> = paths.iter().filter_map(|p| p.parent()).collect();
    for dir in dirs {
        if let Err(e) = fs::create_dir_all(dir) {
            eprintln!("{}: {e}", dir.display());
            return ExitCode::FAILURE;
        }
    }

    let data: Vec<u8> = (0..size).map(|i| u8::try_from(i % 256).unwrap()).collect();
    let result = paths.par_iter().try_for_each(|path| {
        fs::write(path, &data).map_err(|e| format!("{}: {e}", path.display()))
    });

    if let Err(e) = result {
        eprintln!("{e}");
        return ExitCode::FAILURE;
    }

    println!("{count} files of {size} B under {}", root.display());
    ExitCode::SUCCESS
}
