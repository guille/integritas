//! HTML report generation for integrity check results.

use std::fmt::Write;
use std::path::Path;

use chrono::Utc;

use crate::manifest::VerifySummary;

/// Generate a self-contained HTML report from a verification summary.
pub fn generate_html(directory: &Path, summary: &VerifySummary, threads: usize) -> String {
    let now = Utc::now().format("%Y-%m-%d %H:%M:%S UTC");
    let total =
        summary.ok as usize + summary.changed.len() + summary.missing.len() + summary.new.len();
    let status = if summary.changed.is_empty() && summary.missing.is_empty() {
        ("PASS", "#22c55e")
    } else {
        ("FAIL", "#ef4444")
    };

    let mut html = String::with_capacity(4096);

    write!(
        html,
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Integritas Report</title>
<style>
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace; background: #0f172a; color: #e2e8f0; padding: 2rem; line-height: 1.6; }}
  .container {{ max-width: 900px; margin: 0 auto; }}
  h1 {{ font-size: 1.5rem; margin-bottom: 1rem; }}
  .status {{ display: inline-block; padding: 0.25rem 0.75rem; border-radius: 4px; font-weight: bold; background: {status_color}; color: #fff; font-size: 1.1rem; }}
  .meta {{ color: #94a3b8; font-size: 0.85rem; margin: 1rem 0; }}
  .meta span {{ display: block; }}
  .summary {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 1rem; margin: 1.5rem 0; }}
  .card {{ background: #1e293b; border-radius: 8px; padding: 1rem; text-align: center; }}
  .card .num {{ font-size: 2rem; font-weight: bold; }}
  .card .label {{ font-size: 0.8rem; color: #94a3b8; text-transform: uppercase; }}
  .ok .num {{ color: #22c55e; }}
  .changed .num {{ color: #f59e0b; }}
  .missing .num {{ color: #ef4444; }}
  .new .num {{ color: #3b82f6; }}
  details {{ background: #1e293b; border-radius: 8px; margin: 0.5rem 0; }}
  summary {{ padding: 0.75rem 1rem; cursor: pointer; font-weight: 500; }}
  summary:hover {{ background: #334155; border-radius: 8px; }}
  .file-list {{ padding: 0 1rem 1rem; }}
  .file-list li {{ font-family: monospace; font-size: 0.85rem; padding: 0.2rem 0; color: #cbd5e1; list-style: none; }}
  .file-list li::before {{ content: "  "; }}
</style>
</head>
<body>
<div class="container">
<h1>Integrity Report <span class="status">{status_text}</span></h1>
<div class="meta">
  <span>Directory: {directory}</span>
  <span>Date: {date}</span>
  <span>Threads: {threads} | Files checked: {total}</span>
</div>
<div class="summary">
  <div class="card ok"><div class="num">{ok}</div><div class="label">OK</div></div>
  <div class="card changed"><div class="num">{changed}</div><div class="label">Changed</div></div>
  <div class="card missing"><div class="num">{missing}</div><div class="label">Missing</div></div>
  <div class="card new"><div class="num">{new}</div><div class="label">New</div></div>
</div>
"#,
        status_color = status.1,
        status_text = status.0,
        directory = html_escape(&directory.display().to_string()),
        date = now,
        threads = threads,
        total = total,
        ok = summary.ok,
        changed = summary.changed.len(),
        missing = summary.missing.len(),
        new = summary.new.len(),
    )
    .unwrap();

    if !summary.changed.is_empty() {
        write_section(&mut html, "Changed Files", "#f59e0b", &summary.changed);
    }
    if !summary.missing.is_empty() {
        write_section(&mut html, "Missing Files", "#ef4444", &summary.missing);
    }
    if !summary.new.is_empty() {
        write_section(
            &mut html,
            "New Files (not in manifest)",
            "#3b82f6",
            &summary.new,
        );
    }

    html.push_str("</div>\n</body>\n</html>\n");
    html
}

fn write_section(html: &mut String, title: &str, color: &str, files: &[String]) {
    write!(
        html,
        r#"<details open>
<summary style="border-left: 3px solid {color}; padding-left: 0.75rem;">{title} ({count})</summary>
<ul class="file-list">
"#,
        color = color,
        title = title,
        count = files.len(),
    )
    .unwrap();

    for file in files {
        writeln!(html, "<li>{}</li>", html_escape(file)).unwrap();
    }
    html.push_str("</ul>\n</details>\n");
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::manifest::VerifySummary;
    use std::path::PathBuf;

    #[test]
    fn test_report_pass() {
        let summary = VerifySummary {
            ok: 10,
            changed: vec![],
            missing: vec![],
            new: vec![],
            ..Default::default()
        };
        let html = generate_html(&PathBuf::from("/tmp/test"), &summary, 8);
        assert!(html.contains("PASS"));
        assert!(html.contains("/tmp/test"));
        assert!(html.contains(">10<"));
    }

    #[test]
    fn test_report_fail() {
        let summary = VerifySummary {
            ok: 5,
            changed: vec!["file1.txt".to_string()],
            missing: vec!["gone.txt".to_string()],
            new: vec!["new.txt".to_string()],
            ..Default::default()
        };
        let html = generate_html(&PathBuf::from("/data"), &summary, 4);
        assert!(html.contains("FAIL"));
        assert!(html.contains("file1.txt"));
        assert!(html.contains("gone.txt"));
        assert!(html.contains("new.txt"));
        assert!(html.contains("Changed Files"));
    }

    #[test]
    fn test_html_escaping() {
        let summary = VerifySummary {
            ok: 0,
            changed: vec!["<script>alert('xss')</script>".to_string()],
            missing: vec![],
            new: vec![],
            ..Default::default()
        };
        let html = generate_html(&PathBuf::from("/tmp"), &summary, 1);
        assert!(!html.contains("<script>"));
        assert!(html.contains("&lt;script&gt;"));
    }
}
