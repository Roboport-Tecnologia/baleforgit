use std::path::Path;
use std::process::Command;

fn main() {
    let sha = git_sha();
    let date = build_date();
    let target = std::env::var("TARGET").unwrap_or_else(|_| "unknown".into());

    println!("cargo:rustc-env=BALE_GIT_SHA={sha}");
    println!("cargo:rustc-env=BALE_BUILD_DATE={date}");
    println!("cargo:rustc-env=BALE_TARGET={target}");

    println!("cargo:rerun-if-env-changed=BALE_GIT_SHA");
    println!("cargo:rerun-if-env-changed=SOURCE_DATE_EPOCH");
    // Re-embed the SHA when HEAD moves in local dev. logs/HEAD changes on every
    // commit/checkout/reset; a fresh CI checkout has no reflog and relies on the
    // BALE_GIT_SHA env instead. Emitting any rerun-if also pins the build date —
    // it won't drift on unrelated rebuilds.
    for p in ["../../.git/HEAD", "../../.git/logs/HEAD"] {
        if Path::new(p).exists() {
            println!("cargo:rerun-if-changed={p}");
        }
    }
}

fn git_sha() -> String {
    // CI passes BALE_GIT_SHA: the `cross`/musl containers may lack git, and a
    // release checkout's commit is authoritative. Locally, fall back to git.
    if let Ok(s) = std::env::var("BALE_GIT_SHA") {
        let s = s.trim();
        if !s.is_empty() {
            return s.to_string();
        }
    }
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

fn build_date() -> String {
    // SOURCE_DATE_EPOCH (CI sets it to the commit time) keeps the date
    // reproducible; otherwise stamp the build wall-clock.
    let secs = std::env::var("SOURCE_DATE_EPOCH")
        .ok()
        .and_then(|s| s.trim().parse::<i64>().ok())
        .or_else(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .ok()
                .map(|d| d.as_secs() as i64)
        })
        .unwrap_or(0);
    let (y, m, d) = civil_from_days(secs.div_euclid(86_400));
    format!("{y:04}-{m:02}-{d:02}")
}

// Howard Hinnant's days-from-civil inverse: Unix day number -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    (y + i64::from(m <= 2), m, d)
}
