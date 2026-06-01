//! A single-line upload progress indicator for `push-pending`.
//!
//! The line mimics git's own progress style so it reads as one with the push
//! output it precedes (`Uploading bales: 100% (8/8), 32.0 MiB | 3.0 MiB/s,
//! done.` sitting above `Enumerating objects: …`). Behaviour splits on whether
//! stderr is a terminal:
//!
//!   * On a TTY it redraws a `\r`-style line — `Uploading bales: 47% (4/8),
//!     14.5 MiB | 3.0 MiB/s` — held back for the first 200ms so a fast or
//!     fully-deduped push doesn't flash one, then on success finalizes it *in
//!     place* by appending `, done.` and a `\n`, so it persists above git's own
//!     "Enumerating objects…" output instead of being overwritten.
//!   * Off a TTY (piped/redirected stderr — CI, the e2e harness) it draws no
//!     live line and emits no escape codes: just the same final summary on
//!     success. Harness assertions key on exit status and error substrings, not
//!     on an empty stderr, so the extra line is harmless.
//!
//! The summary prints only on a successful `finish()`. On the error path the
//! handle's `Drop` prints nothing (and clears the line if one was drawn), so a
//! failed upload leaves neither a stale line nor a misleading summary.

use std::io::{IsTerminal, Write};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread::JoinHandle;
use std::time::Duration;

const SHOW_AFTER: Duration = Duration::from_millis(200);
const REFRESH: Duration = Duration::from_millis(100);

#[derive(Clone, Copy, Default)]
pub struct UploadSnapshot {
    pub bytes_uploaded: u64,
    /// Total new bytes to upload; 0 when nothing new yet or still preparing.
    pub bytes_total: u64,
    pub rate_bytes_per_sec: Option<f64>,
    /// Logical bytes skipped via dedup (local + global). Known only once all files
    /// are re-cleaned, so 0 during the live bar and meaningful in the summary.
    pub bytes_deduped: u64,
}

pub struct UploadProgress {
    // `true` = finished successfully (print persistent summary); `false`/dropped
    // = aborted (clear the line).
    stop: Option<mpsc::Sender<bool>>,
    handle: Option<JoinHandle<()>>,
}

impl UploadProgress {
    /// Start polling `poll` on a background thread. On a TTY the closure is
    /// called repeatedly (~10 Hz) once the work passes the 200ms threshold; off
    /// a TTY it's called once, at finish, for the summary. `file_count` is the
    /// number of bale files in this push, reported in the completion summary.
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

    /// Stop the reporter and print the persistent completion summary, blocking
    /// until it has done so. Call this only on the success path, before any
    /// further stderr output; the `Drop` impl clears the line on the error path.
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
        // Reached only when finish() wasn't called (early `?` return) — treat
        // as an abort and clear the line.
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
        // No live bar off a terminal — escape codes would garble captured logs.
        // Just the plain summary line on success once the upload finishes.
        if rx.recv().unwrap_or(false) {
            let _ = writeln!(err, "{}", summary(&poll(), file_count));
            let _ = err.flush();
        }
        return;
    }

    // Hold the bar back for the first 200ms so a fast push doesn't flash one —
    // but unlike the bar, the summary always prints on success below.
    let success = match rx.recv_timeout(SHOW_AFTER) {
        Ok(s) => s,
        Err(RecvTimeoutError::Disconnected) => false,
        Err(RecvTimeoutError::Timeout) => {
            // Past the threshold: redraw the live line until we're told to stop.
            loop {
                let _ = write!(err, "\r{}\x1b[K", render(&poll(), file_count));
                let _ = err.flush();
                match rx.recv_timeout(REFRESH) {
                    Ok(s) => break s,
                    Err(RecvTimeoutError::Disconnected) => break false,
                    Err(RecvTimeoutError::Timeout) => {}
                }
            }
        }
    };

    if success {
        // Finalize the line in place: ", done." appended to the same git-style
        // line, ending in `\n` so it persists above git's subsequent output.
        // The leading `\r…\x1b[K` overwrites the live line when one was drawn,
        // and is harmless when it wasn't.
        let _ = write!(err, "\r{}\x1b[K\n", summary(&poll(), file_count));
    } else {
        let _ = write!(err, "\r\x1b[K");
    }
    let _ = err.flush();
}

// git-flavoured: "Uploading bales: 47% (4/8), 14.5 MiB | 3.0 MiB/s", mirroring
// git's own "Writing objects: 47% (4/8), 12.00 MiB | 3.00 MiB/s". The (n/N)
// count is the bale files; n is derived from the byte fraction so it advances
// with the transfer (we only get byte-level progress, not per-file completion).
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
        // Nothing new transferred (full dedup) — name the bytes the server already
        // had so a 0-byte upload doesn't read as "nothing happened", like git's
        // "Counting objects: 100% (13/13), done.".
        match s.bytes_deduped {
            0 => format!("Uploading bales: 100% ({file_count}/{file_count}), done."),
            d => format!(
                "Uploading bales: 100% ({file_count}/{file_count}), {} already on server, done.",
                fmt_bytes(d),
            ),
        }
    } else {
        // Keep the size + rate, like git's "Writing objects: 100% (6/6),
        // 622 bytes | 622.00 KiB/s, done.", and append what dedup saved so a
        // partial re-upload is distinguishable from a full one.
        format!(
            "Uploading bales: 100% ({file_count}/{file_count}), {}{}{}, done.",
            fmt_bytes(s.bytes_uploaded),
            rate_clause(s),
            dedup_clause(s),
        )
    }
}

// " (+ 68.0 MiB deduped)" when dedup skipped real bytes; empty otherwise.
fn dedup_clause(s: &UploadSnapshot) -> String {
    match s.bytes_deduped {
        0 => String::new(),
        d => format!(" (+ {} deduped)", fmt_bytes(d)),
    }
}

// git-style " | 3.0 MiB/s" throughput clause; empty until the speed tracker has
// enough samples to report a rate.
fn rate_clause(s: &UploadSnapshot) -> String {
    match s.rate_bytes_per_sec {
        Some(r) if r >= 1.0 => format!(" | {}/s", fmt_bytes(r as u64)),
        _ => String::new(),
    }
}

// Files completed, approximated from the byte fraction. Capped at N-1 until the
// bytes are fully sent so the live line never shows N/N before it's actually
// done (the finalized summary is what prints N/N).
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
