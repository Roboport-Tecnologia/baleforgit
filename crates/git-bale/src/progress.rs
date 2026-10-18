//! git-style `push-pending` upload progress line (`Uploading bales: 47% (4/8),
//! 14.5 MiB | 3.0 MiB/s`), finalized with `, done.` so it persists above git's
//! own push output.
//!
//! On a TTY the live line appears only after 200ms (no flash on a fast or fully
//! deduped push). Off a TTY (CI, the e2e harness) there is no live line or escape
//! codes, only the final summary; harness assertions key on exit status and
//! error substrings, not an empty stderr. The summary prints only on `finish()`;
//! `Drop` on the error path just clears any drawn line.

use std::io::{IsTerminal, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

const SHOW_AFTER: Duration = Duration::from_millis(200);
const REFRESH: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Default)]
pub struct UploadSnapshot {
    pub bytes_uploaded: u64,
    /// 0 while still preparing or when nothing is new.
    pub bytes_total: u64,
    pub rate_bytes_per_sec: Option<f64>,
    /// Local + global dedup; known only after every file is re-cleaned, so 0 on the live line.
    pub bytes_deduped: u64,
}

pub struct UploadProgress {
    // `true` = success (print summary); `false` or dropped sender = abort (clear line).
    stop: Option<mpsc::Sender<bool>>,
    handle: Option<JoinHandle<()>>,
}

impl UploadProgress {
    /// `poll` runs at ~10 Hz on a TTY past the 200ms threshold; off a TTY only once, for the summary.
    pub fn start<F>(file_count: usize, poll: F) -> Self
    where
        F: Fn() -> UploadSnapshot + Send + 'static,
    {
        let tty = std::io::stderr().is_terminal();
        let (tx, rx) = mpsc::channel::<bool>();
        let handle = std::thread::spawn(move || run_reporter(&rx, poll, file_count, tty));
        Self {
            stop: Some(tx),
            handle: Some(handle),
        }
    }

    /// Success path only; blocks until the summary is printed, so call it before
    /// any further stderr output.
    pub fn finish(mut self) {
        self.stop_with(true);
    }

    fn stop_with(&mut self, success: bool) {
        if let Some(tx) = self.stop.take() {
            let _ = tx.send(success);
        }
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Drop for UploadProgress {
    fn drop(&mut self) {
        // No-op after finish(); otherwise an early `?` return, so abort.
        self.stop_with(false);
    }
}

fn run_reporter<F: Fn() -> UploadSnapshot>(
    rx: &mpsc::Receiver<bool>,
    poll: F,
    file_count: usize,
    tty: bool,
) {
    let mut err = std::io::stderr();

    if !tty {
        // Escape codes would garble captured logs.
        if rx.recv().unwrap_or(false) {
            let _ = writeln!(err, "{}", summary(&poll(), file_count));
            let _ = err.flush();
        }
        return;
    }

    let success = match rx.recv_timeout(SHOW_AFTER) {
        Ok(s) => s,
        Err(RecvTimeoutError::Disconnected) => false,
        Err(RecvTimeoutError::Timeout) => loop {
            let _ = write!(err, "\r{}\x1b[K", render(&poll(), file_count));
            let _ = err.flush();
            match rx.recv_timeout(REFRESH) {
                Ok(s) => break s,
                Err(RecvTimeoutError::Disconnected) => break false,
                Err(RecvTimeoutError::Timeout) => {}
            }
        },
    };

    if success {
        // `\r…\x1b[K` overwrites the live line if one was drawn; harmless otherwise.
        let _ = write!(err, "\r{}\x1b[K\n", summary(&poll(), file_count));
    } else {
        let _ = write!(err, "\r\x1b[K");
    }
    let _ = err.flush();
}

// n in (n/N) is derived from the byte fraction: xet reports bytes, not per-file completion.
fn render(s: &UploadSnapshot, file_count: usize) -> String {
    if s.bytes_total == 0 {
        return format!("Uploading bales: 0% (0/{file_count})");
    }
    let frac = (s.bytes_uploaded as f64 / s.bytes_total as f64).clamp(0.0, 1.0);
    let pct = (frac * 100.0).round() as u64;
    let n = files_done(s, file_count);
    format!(
        "Uploading bales: {pct}% ({n}/{file_count}), {}{}",
        fmt_bytes(s.bytes_uploaded),
        rate_clause(s),
    )
}

fn summary(s: &UploadSnapshot, file_count: usize) -> String {
    if s.bytes_uploaded == 0 {
        // Full dedup: name what the server already had so 0 bytes doesn't read as "nothing happened".
        match s.bytes_deduped {
            0 => format!("Uploading bales: 100% ({file_count}/{file_count}), done."),
            d => format!(
                "Uploading bales: 100% ({file_count}/{file_count}), {} already on server, done.",
                fmt_bytes(d),
            ),
        }
    } else {
        // The dedup clause distinguishes a partial re-upload from a full one.
        format!(
            "Uploading bales: 100% ({file_count}/{file_count}), {}{}{}, done.",
            fmt_bytes(s.bytes_uploaded),
            rate_clause(s),
            dedup_clause(s),
        )
    }
}

fn dedup_clause(s: &UploadSnapshot) -> String {
    match s.bytes_deduped {
        0 => String::new(),
        d => format!(" (+ {} deduped)", fmt_bytes(d)),
    }
}

// Empty until the speed tracker has enough samples to report a rate.
fn rate_clause(s: &UploadSnapshot) -> String {
    match s.rate_bytes_per_sec {
        Some(r) if r >= 1.0 => format!(" | {}/s", fmt_bytes(r as u64)),
        _ => String::new(),
    }
}

// Capped at N-1 until every byte is sent so the live line never shows N/N early.
fn files_done(s: &UploadSnapshot, file_count: usize) -> usize {
    if file_count == 0 || s.bytes_total == 0 {
        return 0;
    }
    if s.bytes_uploaded >= s.bytes_total {
        return file_count;
    }
    let frac = s.bytes_uploaded as f64 / s.bytes_total as f64;
    ((frac * file_count as f64) as usize).min(file_count.saturating_sub(1))
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
