//! A transient, single-line upload progress indicator for `push-pending`.
//!
//! Spawns a background thread that polls a snapshot of the upload's transfer
//! bytes and redraws a `\r`-style line on stderr. Two deliberate constraints:
//!
//!   * It stays silent for the first 200ms — a push that uploads nothing new
//!     (full dedup) or finishes near-instantly never flashes a bar.
//!   * It draws only when stderr is an interactive terminal. Under the e2e
//!     harness (and any piped/redirected stderr, e.g. a CI log) it's a no-op,
//!     so captured output and the harness's assertions are unaffected.
//!
//! The handle stops the thread and clears the line on drop, so an upload that
//! errors out via `?` doesn't leave a half-drawn line behind.

use std::io::{IsTerminal, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

const SHOW_AFTER: Duration = Duration::from_millis(200);
const REFRESH: Duration = Duration::from_millis(100);
const SPINNER: [char; 4] = ['|', '/', '-', '\\'];

#[derive(Clone, Copy, Default)]
pub struct UploadSnapshot {
    pub bytes_uploaded: u64,
    /// Total new bytes to upload; 0 when nothing new yet or still preparing.
    pub bytes_total: u64,
    pub rate_bytes_per_sec: Option<f64>,
}

pub struct UploadProgress {
    stop: Option<mpsc::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl UploadProgress {
    /// Start polling `poll` on a background thread. The closure is called
    /// repeatedly (~10 Hz) once the work passes the 200ms threshold. Returns a
    /// no-op handle when stderr isn't a terminal.
    pub fn start<F>(poll: F) -> Self
    where
        F: Fn() -> UploadSnapshot + Send + 'static,
    {
        if !std::io::stderr().is_terminal() {
            return Self {
                stop: None,
                handle: None,
            };
        }
        let (tx, rx) = mpsc::channel::<()>();
        let handle = std::thread::spawn(move || run_reporter(&rx, poll));
        Self {
            stop: Some(tx),
            handle: Some(handle),
        }
    }

    /// Stop the reporter and clear the line, blocking until it has done so.
    /// Call this on the success path before any further stderr output; the
    /// `Drop` impl is the safety net for the error path.
    pub fn finish(self) {}
}

impl Drop for UploadProgress {
    fn drop(&mut self) {
        // Dropping the sender disconnects the channel, waking the reporter out
        // of its recv_timeout; the join waits for the line to be cleared.
        self.stop.take();
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

fn run_reporter<F: Fn() -> UploadSnapshot>(rx: &mpsc::Receiver<()>, poll: F) {
    // Quiet until the threshold: a fast push shows nothing at all.
    match rx.recv_timeout(SHOW_AFTER) {
        Ok(()) | Err(RecvTimeoutError::Disconnected) => return,
        Err(RecvTimeoutError::Timeout) => {}
    }

    let mut err = std::io::stderr();
    let mut frame = 0usize;
    loop {
        let _ = write!(err, "\r{}\x1b[K", render(&poll(), frame));
        let _ = err.flush();
        frame = frame.wrapping_add(1);
        match rx.recv_timeout(REFRESH) {
            Ok(()) | Err(RecvTimeoutError::Disconnected) => break,
            Err(RecvTimeoutError::Timeout) => {}
        }
    }
    // We always drew at least once above; erase it.
    let _ = write!(err, "\r\x1b[K");
    let _ = err.flush();
}

fn render(s: &UploadSnapshot, frame: usize) -> String {
    let spin = SPINNER[frame % SPINNER.len()];
    if s.bytes_total == 0 {
        return format!("{spin} Uploading to bale…");
    }
    let pct = (s.bytes_uploaded as f64 / s.bytes_total as f64 * 100.0).clamp(0.0, 100.0);
    let rate = match s.rate_bytes_per_sec {
        Some(r) if r >= 1.0 => format!("  {}/s", fmt_bytes(r as u64)),
        _ => String::new(),
    };
    format!(
        "{spin} Uploading to bale  {} / {}  {pct:.0}%{rate}",
        fmt_bytes(s.bytes_uploaded),
        fmt_bytes(s.bytes_total),
    )
}

fn fmt_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}
