use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use integritas::manifest;
use std::io::Write;
use std::path::PathBuf;
use std::process;

#[derive(Parser)]
#[command(
    name = "integritas",
    version,
    about = "Fast file integrity checker using BLAKE3"
)]
#[command(after_help = "\
Examples:
  integritas compute /mnt/backup          Create a manifest
  integritas check /mnt/backup            Verify files against manifest
  integritas check /mnt/backup --prompt   Verify and offer to update manifest
  integritas diff old.json new.json       Compare two manifests

Exit codes:
  0  All files OK / manifests identical
  1  Differences found or verification errors")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn num_threads_default() -> usize {
    std::thread::available_parallelism().map_or(1, std::num::NonZero::get)
}

#[derive(Subcommand)]
enum Commands {
    /// Compute hashes for all files in a directory and create a manifest.
    Compute {
        /// Root directory to scan recursively.
        #[arg(default_value = ".")]
        directory: PathBuf,

        /// Path to write the manifest file. Defaults to <directory>/.integritas-manifest.json.
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Only hash files not already in the manifest (by path).
        /// Existing entries are kept as-is without re-verification.
        #[arg(short, long)]
        append: bool,

        /// Glob patterns to exclude from scanning (can be repeated).
        #[arg(short, long)]
        exclude: Vec<String>,

        /// Number of threads for parallel file hashing.
        /// Defaults to CPU count. Use -j1 for HDDs.
        #[arg(short = 'j', long, default_value_t = num_threads_default())]
        threads: usize,

        /// Suppress progress bars and informational messages.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Verify files against an existing manifest.
    Check {
        /// Root directory to verify recursively.
        #[arg(default_value = ".")]
        directory: PathBuf,

        /// Path to the manifest file. Defaults to <directory>/.integritas-manifest.json.
        #[arg(short, long)]
        manifest: Option<PathBuf>,

        /// Write an HTML summary report (changed/missing/new files) to this path.
        #[arg(short, long)]
        report: Option<PathBuf>,

        /// After showing results, prompt to update the manifest with current state.
        /// Changed files use already-computed hashes; new files are hashed; missing files are removed.
        #[arg(short = 'p', long)]
        prompt: bool,

        /// Number of threads for parallel file hashing.
        /// Defaults to CPU count. Use -j1 for HDDs.
        #[arg(short = 'j', long, default_value_t = num_threads_default())]
        threads: usize,

        /// Suppress progress bars and informational messages.
        #[arg(short, long)]
        quiet: bool,
    },
    /// Compare two manifests and show differences.
    Diff {
        /// Path to the first (older) manifest.
        old: PathBuf,

        /// Path to the second (newer) manifest.
        new: PathBuf,

        /// Suppress informational messages.
        #[arg(short, long)]
        quiet: bool,
    },
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Compute {
            directory,
            output,
            append,
            exclude,
            threads,
            quiet,
        } => {
            let dir = &directory;
            if !dir.is_dir() {
                eprintln!("Error: '{}' is not a directory", dir.display());
                process::exit(1);
            }

            // Helper: create a spinner progress bar (hidden if quiet)
            let make_spinner = || -> ProgressBar {
                if quiet {
                    ProgressBar::hidden()
                } else {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.green} [{elapsed_precise}] {pos} files hashed",
                        )
                        .unwrap(),
                    );
                    pb
                }
            };

            let out_path = output.unwrap_or_else(|| manifest::manifest_path(dir));

            let result = if append {
                let existing = if out_path.exists() {
                    match manifest::Manifest::load(&out_path) {
                        Ok(m) => {
                            if !quiet {
                                eprintln!(
                                    "Appending to existing manifest ({} entries, threads: {threads})",
                                    m.entries.len(),
                                );
                            }
                            Some(m)
                        }
                        Err(e) => {
                            eprintln!("Error reading existing manifest: {e}");
                            process::exit(1);
                        }
                    }
                } else {
                    if !quiet {
                        eprintln!(
                            "No existing manifest found, computing from scratch (threads: {threads})",
                        );
                    }
                    None
                };
                let pb = make_spinner();
                let result =
                    manifest::compute_append(dir, existing.as_ref(), threads, &exclude, Some(&pb));
                pb.finish_and_clear();
                result
            } else {
                if !quiet {
                    eprintln!(
                        "Computing hashes for: {} (threads: {threads})",
                        dir.display(),
                    );
                }
                let pb = make_spinner();
                let result = manifest::compute_with_threads(dir, threads, Some(&pb), &exclude);
                pb.finish_and_clear();
                result
            };

            match result {
                Ok(m) => {
                    let count = m.entries.len();
                    if let Err(e) = m.save(&out_path) {
                        eprintln!("Error writing manifest: {e}");
                        process::exit(1);
                    }
                    if !quiet {
                        eprintln!(
                            "Manifest written to: {} ({count} files)",
                            out_path.display()
                        );
                    }
                }
                Err(e) => {
                    eprintln!("Error computing hashes: {e}");
                    process::exit(1);
                }
            }
        }
        Commands::Check {
            directory,
            manifest: manifest_path_arg,
            report,
            prompt,
            threads,
            quiet,
        } => {
            let dir = &directory;
            if !dir.is_dir() {
                eprintln!("Error: '{}' is not a directory", dir.display());
                process::exit(1);
            }

            // Helper: create a spinner progress bar (hidden if quiet)
            let make_spinner = || -> ProgressBar {
                if quiet {
                    ProgressBar::hidden()
                } else {
                    let pb = ProgressBar::new_spinner();
                    pb.set_style(
                        ProgressStyle::with_template(
                            "{spinner:.green} [{elapsed_precise}] {pos} files hashed",
                        )
                        .unwrap(),
                    );
                    pb
                }
            };

            let mpath = manifest_path_arg.unwrap_or_else(|| manifest::manifest_path(dir));
            if !mpath.exists() {
                eprintln!("Error: manifest not found at '{}'", mpath.display());
                eprintln!("Run 'integritas compute' first to create a manifest.");
                process::exit(1);
            }

            let m = match manifest::Manifest::load(&mpath) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error reading manifest: {e}");
                    process::exit(1);
                }
            };

            if !quiet {
                eprintln!(
                    "Verifying: {} ({} entries, threads: {threads})",
                    dir.display(),
                    m.entries.len()
                );
            }

            let pb = if quiet {
                ProgressBar::hidden()
            } else {
                let pb = ProgressBar::new(m.entries.len() as u64);
                pb.set_style(
                    ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})")
                        .unwrap()
                        .progress_chars("#>-"),
                );
                pb
            };

            match manifest::check_with_threads(dir, &m, threads, Some(&pb)) {
                Ok(summary) => {
                    pb.finish_and_clear();
                    for path in &summary.changed {
                        println!("CHANGED: {path}");
                    }
                    for path in &summary.missing {
                        println!("MISSING: {path}");
                    }
                    for path in &summary.new {
                        println!("NEW:     {path}");
                    }

                    if !quiet {
                        eprintln!(
                            "\nSummary: {} ok, {} changed, {} missing, {} new",
                            summary.ok,
                            summary.changed.len(),
                            summary.missing.len(),
                            summary.new.len()
                        );
                    }

                    if let Some(ref report_path) = report {
                        let html = integritas::report::generate_html(dir, &summary, threads)
                            .expect("failed to generate report");
                        if let Err(e) = std::fs::write(report_path, html) {
                            eprintln!("Error writing report: {e}");
                            process::exit(1);
                        }
                        if !quiet {
                            eprintln!("Report written to: {}", report_path.display());
                        }
                    }

                    let has_differences = !summary.changed.is_empty()
                        || !summary.missing.is_empty()
                        || !summary.new.is_empty();

                    // Prompt to update manifest if --prompt and there are differences
                    if prompt && has_differences {
                        eprint!("\nUpdate manifest to reflect current state? [y/N] ");
                        let _ = std::io::stderr().flush();
                        let mut input = String::new();
                        if std::io::stdin().read_line(&mut input).is_ok()
                            && input.trim().eq_ignore_ascii_case("y")
                        {
                            let new_pb = make_spinner();
                            match manifest::build_updated_manifest(
                                dir,
                                &summary,
                                &m,
                                threads,
                                Some(&new_pb),
                            ) {
                                Ok(updated) => {
                                    new_pb.finish_and_clear();
                                    let count = updated.entries.len();
                                    if let Err(e) = updated.save(&mpath) {
                                        eprintln!("Error writing manifest: {e}");
                                        process::exit(1);
                                    }
                                    if !quiet {
                                        eprintln!(
                                            "Manifest updated: {} ({count} files)",
                                            mpath.display()
                                        );
                                    }
                                }
                                Err(e) => {
                                    new_pb.finish_and_clear();
                                    eprintln!("Error updating manifest: {e}");
                                    process::exit(1);
                                }
                            }
                        } else if !quiet {
                            eprintln!("Manifest not updated.");
                        }
                    }

                    if has_differences {
                        process::exit(1);
                    } else {
                        process::exit(0);
                    }
                }
                Err(e) => {
                    eprintln!("Error during verification: {e}");
                    process::exit(1);
                }
            }
        }
        Commands::Diff { old, new, quiet } => {
            let old_manifest = match manifest::Manifest::load(&old) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error reading old manifest '{}': {}", old.display(), e);
                    process::exit(1);
                }
            };
            let new_manifest = match manifest::Manifest::load(&new) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Error reading new manifest '{}': {}", new.display(), e);
                    process::exit(1);
                }
            };

            let summary = manifest::diff(&old_manifest, &new_manifest);

            for path in &summary.added {
                println!("ADDED:   {path}");
            }
            for path in &summary.removed {
                println!("REMOVED: {path}");
            }
            for path in &summary.changed {
                println!("CHANGED: {path}");
            }

            if !quiet {
                eprintln!(
                    "\nSummary: {} unchanged, {} changed, {} added, {} removed",
                    summary.unchanged,
                    summary.changed.len(),
                    summary.added.len(),
                    summary.removed.len()
                );
            }

            if summary.changed.is_empty() && summary.added.is_empty() && summary.removed.is_empty()
            {
                process::exit(0);
            } else {
                process::exit(1);
            }
        }
    }
}
