//! Standalone profiling target for the clean filter's slow path.
//!
//! Mirrors `filter_process::handle_clean` minus the pkt-line plumbing so a
//! sampler (samply, instruments, perf) can be pointed at one process and see
//! the full xet-data CDC + xorb staging cost without git/forks in the way.
//!
//! Usage:
//!   cargo build --release --example profile_clean
//!   ./target/release/examples/profile_clean <input-file> [staging-dir]

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::clean_file;
use xet_data::processing::{FileUploadSession, Sha256Policy};
use xet_runtime::core::XetRuntime;

use git_bale::pointer::encode_pointer_string;

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let input = args
        .next()
        .ok_or_else(|| anyhow::anyhow!("usage: profile_clean <input-file> [staging-dir]"))?;
    let staging = match args.next() {
        Some(p) => std::path::PathBuf::from(p),
        None => {
            let tmp = tempfile::tempdir()?.keep();
            tmp.join("staging")
        }
    };
    std::fs::create_dir_all(&staging).with_context(|| format!("mkdir {}", staging.display()))?;

    let input_path = std::path::PathBuf::from(&input);
    let size = std::fs::metadata(&input_path)?.len();
    eprintln!(
        "input: {} ({} bytes)\nstaging: {}",
        input_path.display(),
        size,
        staging.display()
    );

    let rt = XetRuntime::new()?;
    let translator = TranslatorConfig::local_config(&staging).context("local TranslatorConfig")?;

    let t0 = Instant::now();
    let pointer = rt
        .bridge_sync(async move {
            let session = FileUploadSession::new(Arc::new(translator)).await?;
            let (info, _metrics) =
                clean_file(session.clone(), &input_path, Sha256Policy::Compute).await?;
            session.finalize().await?;
            encode_pointer_string(&info).map_err(anyhow::Error::from)
        })
        .map_err(|e| anyhow::anyhow!("xet runtime error: {e:?}"))??;
    let elapsed = t0.elapsed();

    eprintln!("clean: {:.3} s", elapsed.as_secs_f64());
    eprintln!(
        "throughput: {:.1} MiB/s",
        (size as f64) / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );
    print!("{pointer}");
    Ok(())
}
