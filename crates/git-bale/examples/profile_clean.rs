//! Standalone profiling target for the clean filter's slow path.
//!
//! Three modes:
//!   --full         Mirrors `filter_process::handle_clean`: FileUploadSession +
//!                  clean_file(Sha256Policy::Compute) + finalize.
//!   --full-no-sha  Same as --full but Sha256Policy::Skip (Option A measurement).
//!   --hash-only    Uses `data_client::hash_files_async`: CDC + merkle hash only.
//!
//! Optional: --staging <dir> reuses an existing staging dir across runs to
//! exercise the xet dedup path on second/third invocations.

use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result};
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::{clean_file, hash_files_async};
use xet_data::processing::{FileUploadSession, Sha256Policy};
use xet_runtime::core::XetRuntime;

use git_bale::pointer::encode_pointer_string;

enum Mode {
    Full,
    FullNoSha,
    HashOnly,
}

fn main() -> Result<()> {
    let mut args = std::env::args().skip(1).peekable();
    let mode = match args.peek().map(|s| s.as_str()) {
        Some("--full") => {
            args.next();
            Mode::Full
        }
        Some("--full-no-sha") => {
            args.next();
            Mode::FullNoSha
        }
        Some("--hash-only") => {
            args.next();
            Mode::HashOnly
        }
        _ => Mode::Full,
    };
    let mut staging_override: Option<std::path::PathBuf> = None;
    let mut input: Option<String> = None;
    while let Some(arg) = args.next() {
        if arg == "--staging" {
            staging_override = Some(args.next().context("--staging expects a path")?.into());
        } else if input.is_none() {
            input = Some(arg);
        } else {
            anyhow::bail!("unexpected positional arg: {arg}");
        }
    }
    let input = input.ok_or_else(|| {
        anyhow::anyhow!(
            "usage: profile_clean [--full|--full-no-sha|--hash-only] [--staging <dir>] <input-file>"
        )
    })?;
    let input_path = std::path::PathBuf::from(&input);
    let size = std::fs::metadata(&input_path)?.len();
    eprintln!("input: {} ({} bytes)", input_path.display(), size);

    let t0 = Instant::now();
    let pointer = match mode {
        Mode::Full => run_full(
            &input_path,
            Sha256Policy::Compute,
            staging_override.as_deref(),
        )?,
        Mode::FullNoSha => run_full(&input_path, Sha256Policy::Skip, staging_override.as_deref())?,
        Mode::HashOnly => run_hash_only(&input_path)?,
    };
    let elapsed = t0.elapsed();

    eprintln!(
        "{} clean: {:.3} s  ({:.1} MiB/s)",
        match mode {
            Mode::Full => "full",
            Mode::FullNoSha => "full-no-sha",
            Mode::HashOnly => "hash-only",
        },
        elapsed.as_secs_f64(),
        (size as f64) / (1024.0 * 1024.0) / elapsed.as_secs_f64()
    );
    print!("{pointer}");
    Ok(())
}

fn run_full(
    input_path: &std::path::Path,
    sha: Sha256Policy,
    staging_override: Option<&std::path::Path>,
) -> Result<String> {
    let staging = match staging_override {
        Some(p) => p.to_path_buf(),
        None => tempfile::tempdir()?.keep().join("staging"),
    };
    std::fs::create_dir_all(&staging).with_context(|| format!("mkdir {}", staging.display()))?;
    eprintln!("staging: {}", staging.display());

    let rt = XetRuntime::new()?;
    let translator = TranslatorConfig::local_config(&staging).context("local TranslatorConfig")?;
    let input = input_path.to_path_buf();
    rt.bridge_sync(async move {
        let session = FileUploadSession::new(Arc::new(translator)).await?;
        let (info, _metrics) = clean_file(session.clone(), &input, sha).await?;
        session.finalize().await?;
        encode_pointer_string(&info).map_err(anyhow::Error::from)
    })
    .map_err(|e| anyhow::anyhow!("xet runtime error: {e:?}"))?
}

fn run_hash_only(input_path: &std::path::Path) -> Result<String> {
    let rt = XetRuntime::new()?;
    let path = input_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("input path is not utf-8"))?
        .to_string();
    let infos = rt
        .bridge_sync(async move { hash_files_async(vec![path]).await })
        .map_err(|e| anyhow::anyhow!("xet runtime error: {e:?}"))?
        .context("hash_files_async")?;
    let info = infos
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("hash_files_async returned no results"))?;
    Ok(encode_pointer_string(&info)?)
}
