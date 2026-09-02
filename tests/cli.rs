//! End-to-end tests that run the actual binary.

use std::fs;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use tempfile::TempDir;

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_integritas"))
        .args(args)
        .current_dir(dir)
        .output()
        .unwrap()
}

/// Run the binary with `input` piped to stdin (for `--prompt`).
fn run_with_stdin(dir: &Path, args: &[&str], input: &str) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_integritas"))
        .args(args)
        .current_dir(dir)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn exit_code(output: &Output) -> i32 {
    output.status.code().expect("killed by signal")
}

/// Create a directory with two files and a computed manifest.
fn setup() -> TempDir {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"alpha").unwrap();
    fs::write(dir.path().join("b.txt"), b"beta").unwrap();
    let out = run(dir.path(), &["compute", ".", "-q"]);
    assert!(out.status.success(), "compute failed: {}", stderr(&out));
    dir
}

fn manifest_contents(dir: &Path) -> String {
    fs::read_to_string(dir.join(".integritas-manifest.json")).unwrap()
}

#[test]
fn check_clean_exits_zero() {
    let dir = setup();
    let out = run(dir.path(), &["check", ".", "-q"]);
    assert_eq!(exit_code(&out), 0, "stderr: {}", stderr(&out));
}

#[test]
fn check_reports_all_difference_kinds_and_fails() {
    let dir = setup();
    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();
    fs::remove_file(dir.path().join("b.txt")).unwrap();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();

    let out = run(dir.path(), &["check", "."]);
    assert_eq!(exit_code(&out), 1);
    let printed = stdout(&out);
    assert!(printed.contains("CHANGED: a.txt"), "stdout: {printed}");
    assert!(printed.contains("MISSING: b.txt"), "stdout: {printed}");
    assert!(printed.contains("NEW:     c.txt"), "stdout: {printed}");
}

#[test]
fn accept_new_adds_new_files_and_passes() {
    let dir = setup();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();

    let out = run(dir.path(), &["check", ".", "--accept-new", "-q"]);
    assert_eq!(exit_code(&out), 0, "stderr: {}", stderr(&out));
    assert!(manifest_contents(dir.path()).contains("c.txt"));

    // The updated manifest matches the directory again.
    let out = run(dir.path(), &["check", ".", "-q"]);
    assert_eq!(exit_code(&out), 0);
}

#[test]
fn accept_new_refuses_when_other_differences_exist() {
    let dir = setup();
    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();

    let out = run(dir.path(), &["check", ".", "--accept-new"]);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr(&out).contains("manifest not updated"),
        "stderr: {}",
        stderr(&out)
    );
    assert!(!manifest_contents(dir.path()).contains("c.txt"));
}

#[test]
fn prompt_accepted_updates_manifest_and_passes() {
    let dir = setup();
    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();

    let out = run_with_stdin(dir.path(), &["check", ".", "--prompt", "-q"], "y\n");
    assert_eq!(exit_code(&out), 0, "stderr: {}", stderr(&out));

    let out = run(dir.path(), &["check", ".", "-q"]);
    assert_eq!(exit_code(&out), 0);
}

#[test]
fn prompt_declined_leaves_manifest_and_fails() {
    let dir = setup();
    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();
    let before = manifest_contents(dir.path());

    let out = run_with_stdin(dir.path(), &["check", ".", "--prompt", "-q"], "n\n");
    assert_eq!(exit_code(&out), 1);
    assert_eq!(manifest_contents(dir.path()), before);
}

#[test]
fn accept_new_with_prompt_still_asks_on_other_differences() {
    let dir = setup();
    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();

    let out = run_with_stdin(
        dir.path(),
        &["check", ".", "--accept-new", "--prompt"],
        "n\n",
    );
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr(&out).contains("Update manifest to reflect current state?"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn accept_new_with_prompt_skips_question_when_only_new() {
    let dir = setup();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();

    // Empty stdin: if the prompt were shown, the answer would default to no.
    let out = run_with_stdin(dir.path(), &["check", ".", "--accept-new", "--prompt"], "");
    assert_eq!(exit_code(&out), 0, "stderr: {}", stderr(&out));
    assert!(manifest_contents(dir.path()).contains("c.txt"));
}

#[test]
fn missing_manifest_is_an_error() {
    let dir = TempDir::new().unwrap();
    fs::write(dir.path().join("a.txt"), b"alpha").unwrap();

    let out = run(dir.path(), &["check", "."]);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr(&out).contains("manifest not found"),
        "stderr: {}",
        stderr(&out)
    );
}

/// Rewrite the manifest as if a future format wrote it.
fn write_future_manifest(dir: &Path, min_reader_version: u32) {
    let mpath = dir.join(".integritas-manifest.json");
    let future = manifest_contents(dir)
        .replace("\"version\": 2", "\"version\": 99")
        .replace(
            "\"min_reader_version\": 2",
            &format!("\"min_reader_version\": {min_reader_version}"),
        );
    fs::write(&mpath, future).unwrap();
}

#[test]
fn unreadable_manifest_version_is_an_error() {
    let dir = setup();
    write_future_manifest(dir.path(), 99);

    let out = run(dir.path(), &["check", "."]);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr(&out).contains("requires format version 99"),
        "stderr: {}",
        stderr(&out)
    );
}

#[test]
fn newer_but_readable_manifest_checks_fine_and_refuses_update() {
    let dir = setup();
    write_future_manifest(dir.path(), 2);
    fs::write(dir.path().join("c.txt"), b"new").unwrap();
    let before = manifest_contents(dir.path());

    let out = run(dir.path(), &["check", "."]);
    assert_eq!(exit_code(&out), 1);
    assert!(stdout(&out).contains("NEW:     c.txt"));

    let out = run(dir.path(), &["check", ".", "--accept-new"]);
    assert_eq!(exit_code(&out), 1);
    assert!(
        stderr(&out).contains("cannot update manifest"),
        "stderr: {}",
        stderr(&out)
    );
    assert_eq!(manifest_contents(dir.path()), before);
}

#[test]
fn diff_reports_differences() {
    let dir = setup();
    let out = run(dir.path(), &["compute", ".", "-q", "-o", "old.json"]);
    assert!(out.status.success());

    fs::write(dir.path().join("a.txt"), b"tampered").unwrap();
    fs::remove_file(dir.path().join("b.txt")).unwrap();
    fs::write(dir.path().join("c.txt"), b"new").unwrap();
    let out = run(dir.path(), &["compute", ".", "-q", "-o", "new.json"]);
    assert!(out.status.success());

    let out = run(dir.path(), &["diff", "old.json", "new.json"]);
    assert_eq!(exit_code(&out), 1);
    let printed = stdout(&out);
    assert!(printed.contains("CHANGED: a.txt"), "stdout: {printed}");
    assert!(printed.contains("REMOVED: b.txt"), "stdout: {printed}");
    assert!(printed.contains("ADDED:   c.txt"), "stdout: {printed}");

    let out = run(dir.path(), &["diff", "old.json", "old.json"]);
    assert_eq!(exit_code(&out), 0);
}

#[test]
fn check_writes_html_report() {
    let dir = setup();
    let out = run(dir.path(), &["check", ".", "-q", "-r", "report.html"]);
    assert_eq!(exit_code(&out), 0, "stderr: {}", stderr(&out));
    let report = fs::read_to_string(dir.path().join("report.html")).unwrap();
    assert!(report.contains("<html"));
}
