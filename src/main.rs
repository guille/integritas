use clap::{Parser, Subcommand};
use indicatif::{ProgressBar, ProgressStyle};
use integritas::manifest;
use std::fmt::Display;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

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

/// An application-level error carrying a user-facing message.
///
/// Command functions return these instead of calling `process::exit`, so
/// `main` is the single place that prints to stderr and picks a failure code.
#[derive(Debug)]
struct AppError(String);

impl Display for AppError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for AppError {}

/// Attach a user-facing context message to any `Result` whose error is `Display`.
///
/// The context string is only formatted on the error path, so passing a `&str`
/// literal here is free on success.
trait Context<T> {
    fn context(self, ctx: impl Display) -> Result<T, AppError>;
}

impl<T, E: Display> Context<T> for Result<T, E> {
    fn context(self, ctx: impl Display) -> Result<T, AppError> {
        self.map_err(|e| AppError(format!("{ctx}: {e}")))
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli.command) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(command: Commands) -> Result<ExitCode, AppError> {
    match command {
        Commands::Compute {
            directory,
            output,
            append,
            exclude,
            threads,
            quiet,
        } => cmd_compute(&directory, output, append, &exclude, threads, quiet),
        Commands::Check {
            directory,
            manifest,
            report,
            prompt,
            threads,
            quiet,
        } => cmd_check(
            &directory,
            manifest,
            report.as_deref(),
            prompt,
            threads,
            quiet,
        ),
        Commands::Diff { old, new, quiet } => cmd_diff(&old, &new, quiet),
    }
}

/// Create a spinner progress bar (hidden when `quiet`).
fn make_spinner(quiet: bool) -> ProgressBar {
    if quiet {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new_spinner();
        pb.set_style(
            ProgressStyle::with_template("{spinner:.green} [{elapsed_precise}] {pos} files hashed")
                .unwrap(),
        );
        pb
    }
}

fn cmd_compute(
    dir: &std::path::Path,
    output: Option<PathBuf>,
    append: bool,
    exclude: &[String],
    threads: usize,
    quiet: bool,
) -> Result<ExitCode, AppError> {
    if !dir.is_dir() {
        return Err(AppError(format!("'{}' is not a directory", dir.display())));
    }

    let out_path = output.unwrap_or_else(|| manifest::manifest_path(dir));

    let manifest = if append {
        let existing = if out_path.exists() {
            let m = manifest::Manifest::load(&out_path).context("reading existing manifest")?;
            if !quiet {
                eprintln!(
                    "Appending to existing manifest ({} entries, threads: {threads})",
                    m.entries.len(),
                );
            }
            Some(m)
        } else {
            if !quiet {
                eprintln!(
                    "No existing manifest found, computing from scratch (threads: {threads})",
                );
            }
            None
        };
        let pb = make_spinner(quiet);
        let result = manifest::compute_append(dir, existing.as_ref(), threads, exclude, Some(&pb));
        pb.finish_and_clear();
        result.context("computing hashes")?
    } else {
        if !quiet {
            eprintln!(
                "Computing hashes for: {} (threads: {threads})",
                dir.display()
            );
        }
        let pb = make_spinner(quiet);
        let result = manifest::compute_with_threads(dir, threads, Some(&pb), exclude);
        pb.finish_and_clear();
        result.context("computing hashes")?
    };

    let count = manifest.entries.len();
    manifest.save(&out_path).context("writing manifest")?;
    if !quiet {
        eprintln!(
            "Manifest written to: {} ({count} files)",
            out_path.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_check(
    dir: &std::path::Path,
    manifest_path_arg: Option<PathBuf>,
    report: Option<&std::path::Path>,
    prompt: bool,
    threads: usize,
    quiet: bool,
) -> Result<ExitCode, AppError> {
    if !dir.is_dir() {
        return Err(AppError(format!("'{}' is not a directory", dir.display())));
    }

    let mpath = manifest_path_arg.unwrap_or_else(|| manifest::manifest_path(dir));
    if !mpath.exists() {
        return Err(AppError(format!(
            "manifest not found at '{}'\nRun 'integritas compute' first to create a manifest.",
            mpath.display()
        )));
    }

    let m = manifest::Manifest::load(&mpath).context("reading manifest")?;

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
            ProgressStyle::with_template(
                "{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta})",
            )
            .unwrap()
            .progress_chars("#>-"),
        );
        pb
    };

    let summary = manifest::check_with_threads(dir, &m, threads, Some(&pb))
        .inspect_err(|_| pb.finish_and_clear())
        .context("during verification")?;
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

    if let Some(report_path) = report {
        let html = integritas::report::generate_html(dir, &summary, threads)
            .context("generating report")?;
        std::fs::write(report_path, html).context("writing report")?;
        if !quiet {
            eprintln!("Report written to: {}", report_path.display());
        }
    }

    let has_differences =
        !summary.changed.is_empty() || !summary.missing.is_empty() || !summary.new.is_empty();

    // Prompt to update the manifest if --prompt and there are differences.
    let mut manifest_updated = false;
    if prompt && has_differences {
        eprint!("\nUpdate manifest to reflect current state? [y/N] ");
        let _ = std::io::stderr().flush();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() && input.trim().eq_ignore_ascii_case("y")
        {
            let new_pb = make_spinner(quiet);
            let updated =
                manifest::build_updated_manifest(dir, &summary, &m, threads, Some(&new_pb))
                    .inspect_err(|_| new_pb.finish_and_clear())
                    .context("updating manifest")?;
            new_pb.finish_and_clear();
            let count = updated.entries.len();
            updated.save(&mpath).context("writing manifest")?;
            if !quiet {
                eprintln!("Manifest updated: {} ({count} files)", mpath.display());
            }
            manifest_updated = true;
        } else if !quiet {
            eprintln!("Manifest not updated.");
        }
    }

    Ok(check_exit_code(has_differences, manifest_updated))
}

fn cmd_diff(
    old: &std::path::Path,
    new: &std::path::Path,
    quiet: bool,
) -> Result<ExitCode, AppError> {
    let old_manifest = manifest::Manifest::load(old)
        .context(format!("reading old manifest '{}'", old.display()))?;
    let new_manifest = manifest::Manifest::load(new)
        .context(format!("reading new manifest '{}'", new.display()))?;

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

    let identical =
        summary.changed.is_empty() && summary.added.is_empty() && summary.removed.is_empty();
    Ok(if identical {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// Decide the exit code for a `check` run.
///
/// Differences yield a failure code, *unless* the manifest was just updated to
/// reflect the current state — in that case the directory matches the manifest
/// again, so the run succeeds.
fn check_exit_code(has_differences: bool, manifest_updated: bool) -> ExitCode {
    if has_differences && !manifest_updated {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ExitCode doesn't implement PartialEq, so compare via the debug repr.
    fn code(c: ExitCode) -> String {
        format!("{c:?}")
    }

    #[test]
    fn clean_run_succeeds() {
        assert_eq!(code(check_exit_code(false, false)), code(ExitCode::SUCCESS));
    }

    #[test]
    fn differences_without_update_fail() {
        assert_eq!(code(check_exit_code(true, false)), code(ExitCode::FAILURE));
    }

    #[test]
    fn differences_with_successful_update_succeed() {
        // Regression: --prompt accepted and manifest saved must exit 0.
        assert_eq!(code(check_exit_code(true, true)), code(ExitCode::SUCCESS));
    }
}
