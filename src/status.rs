//! Program status reported to the terminal out of band, for tab badges and
//! taskbar progress.
//!
//! Every report carries both OSC 9;4 (`ConEmu` progress, widely supported) and
//! OSC 7501 (program status). A terminal that knows 7501 stops
//! mapping 9;4 once it sees one; for one that doesn't stop, the 7501 report
//! comes last and targets the root record (no `id`), the same one 9;4 maps
//! to, so it always wins.
use base64::{engine::general_purpose::STANDARD, Engine};
use indicatif::ProgressBar;
use std::fmt::Write as _;
use std::io::{IsTerminal, Write as _};
use std::sync::mpsc::{self, RecvTimeoutError, Sender};
use std::sync::OnceLock;
use std::thread::JoinHandle;
use std::time::Duration;

/// Encodes to exactly the protocol's 2732-byte `msg` limit.
const MAX_MSG_BYTES: usize = 2048;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

static TITLE: OnceLock<String> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State<'a> {
    /// Percent complete, or `None` when the total is unknown.
    Working(Option<u8>),
    /// Waiting for the user to answer a question.
    Blocked,
    Done(&'a str),
    Error(&'a str),
}

/// Enable reporting, labelled `title`, when stderr is a terminal.
pub fn init(title: String) {
    if std::io::stderr().is_terminal() {
        let _ = TITLE.set(title);
    }
}

pub fn question() {
    report(State::Blocked);
}

pub fn done(msg: &str) {
    report(State::Done(msg));
}

pub fn error(msg: &str) {
    report(State::Error(msg));
}

fn report(state: State) {
    if let Some(title) = TITLE.get() {
        // One write so the sequence never interleaves with progress bar draws.
        let _ = std::io::stderr().write_all(encode(title, state).as_bytes());
    }
}

fn encode(title: &str, state: State) -> String {
    let mut out = String::from("\x1b]9;4;");
    match state {
        State::Working(None) => out.push('3'),
        State::Working(Some(p)) => write!(out, "1;{p}").unwrap(),
        State::Blocked => out.push_str("4;100"),
        State::Done(_) | State::Error(_) => out.push('0'),
    }
    write!(
        out,
        "\x1b\\\x1b]7501;app=integritas:title={}",
        STANDARD.encode(title)
    )
    .unwrap();
    match state {
        State::Working(None) => out.push_str(":state=working"),
        State::Working(Some(p)) => write!(out, ":state=working:progress={p}").unwrap(),
        State::Blocked => out.push_str(":state=blocked:kind=question"),
        State::Done(msg) => write!(out, ":state=done:msg={}", encode_msg(msg)).unwrap(),
        State::Error(msg) => write!(out, ":state=error:msg={}", encode_msg(msg)).unwrap(),
    }
    out.push_str("\x1b\\");
    out
}

fn encode_msg(msg: &str) -> String {
    STANDARD.encode(&msg[..msg.floor_char_boundary(MAX_MSG_BYTES)])
}

/// Reports `working` with `pb`'s progress until dropped.
pub struct Tracker {
    stop: Option<Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

/// Mirror `pb` as `working` reports, sent only when the percentage changes.
pub fn track(pb: &ProgressBar) -> Tracker {
    let Some(title) = TITLE.get() else {
        return Tracker {
            stop: None,
            handle: None,
        };
    };
    let pb = pb.clone();
    let (stop, stopped) = mpsc::channel();
    let handle = std::thread::spawn(move || {
        let mut last = None;
        loop {
            let state = State::Working(percent(&pb));
            if last != Some(state) {
                let _ = std::io::stderr().write_all(encode(title, state).as_bytes());
                last = Some(state);
            }
            if stopped.recv_timeout(POLL_INTERVAL) != Err(RecvTimeoutError::Timeout) {
                break;
            }
        }
    });
    Tracker {
        stop: Some(stop),
        handle: Some(handle),
    }
}

fn percent(pb: &ProgressBar) -> Option<u8> {
    let len = pb.length().filter(|&len| len > 0)?;
    u8::try_from((pb.position() * 100 / len).min(100)).ok()
}

impl Drop for Tracker {
    fn drop(&mut self) {
        drop(self.stop.take());
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const T: &str = "dGVzdA=="; // base64("test")

    #[test]
    fn working_indeterminate() {
        assert_eq!(
            encode("test", State::Working(None)),
            format!("\x1b]9;4;3\x1b\\\x1b]7501;app=integritas:title={T}:state=working\x1b\\")
        );
    }

    #[test]
    fn working_with_progress() {
        assert_eq!(
            encode("test", State::Working(Some(42))),
            format!(
                "\x1b]9;4;1;42\x1b\\\x1b]7501;app=integritas:title={T}:state=working:progress=42\x1b\\"
            )
        );
    }

    #[test]
    fn blocked_on_question() {
        assert_eq!(
            encode("test", State::Blocked),
            format!(
                "\x1b]9;4;4;100\x1b\\\x1b]7501;app=integritas:title={T}:state=blocked:kind=question\x1b\\"
            )
        );
    }

    #[test]
    fn finished_states_clear_conemu_progress() {
        assert_eq!(
            encode("test", State::Done("ok")),
            format!("\x1b]9;4;0\x1b\\\x1b]7501;app=integritas:title={T}:state=done:msg=b2s=\x1b\\")
        );
        assert_eq!(
            encode("test", State::Error("ok")),
            format!(
                "\x1b]9;4;0\x1b\\\x1b]7501;app=integritas:title={T}:state=error:msg=b2s=\x1b\\"
            )
        );
    }

    #[test]
    fn long_msg_fits_protocol_limit() {
        let msg = "é".repeat(MAX_MSG_BYTES);
        assert_eq!(encode_msg(&msg).len(), 2732);
    }
}
