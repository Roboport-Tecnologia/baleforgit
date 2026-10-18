//! `git-bale push-pending` — ensure every bale file the push advertises is
//! present on (and scoped to) the remote being pushed to.
//!
//! Invoked by the pre-push hook as `git-bale push-pending <remote> <url>` with
//! git's ref-update lines on stdin. Only files reachable from the pushed refs
//! are considered; other staged markers (e.g. a `git status` re-clean of an
//! uncommitted edit) stay put for gc. Two classes of pushed file must reach the
//! target:
//!
//!   1. **Freshly staged** files (cleaned offline into `.git/bale/staging/`) —
//!      reconstructed from staging and re-cleaned through an online session.
//!   2. **Already-pushed-elsewhere** files no longer in staging (a prior push to
//!      a *different* remote drained them). Uploads are scoped per-repo, so a
//!      clone of the target would 404 on checkout. Their bytes are re-sourced
//!      from whichever remote still holds them and re-cleaned through the target
//!      session, whose reconstruction shard registers them under the target repo
//!      (xorbs dedup, so this is cheap when the remotes share a server).
//!
//! Re-cleaning (rather than POSTing staged xorbs/shards verbatim) keeps server
//! global dedup: the online session only POSTs genuinely new xorbs. CDC is
//! deterministic, so the online merkle hash must equal the sourced file hash;
//! a mismatch (version skew or corruption) aborts the push.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use gix::ObjectId;
use tempfile::NamedTempFile;
use xet_data::deduplication::DeduplicationMetrics;
use xet_data::processing::configurations::TranslatorConfig;
use xet_data::processing::data_client::{clean_file, default_config};
use xet_data::processing::{FileDownloadSession, FileUploadSession, Sha256Policy, XetFileInfo};
use xet_runtime::core::XetRuntime;

use crate::config::RawConfig;
use crate::pointer;
use crate::progress::{UploadProgress, UploadSnapshot};
use crate::remote::{self, RemoteUrl};
use crate::resolver;
use crate::staging::{
    list_staged_files, remove_empty_dirs, remove_marker, staging_root, sweep_objects,
};

/// Positional args from the pre-push hook (`$1` remote name, `$2` remote URL).
/// Both `None` when invoked by hand: auth falls back to `origin` and only the
/// staged content HEAD reaches is uploaded.
#[derive(Default, Debug)]
pub struct Args {
    pub remote_name: Option<String>,
    pub remote_url: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let raw = RawConfig::load(Some(cwd.as_path()))?;
    if raw.local_mode {
        // Objects are already durable in the local store; nothing to upload.
        tracing::debug!("git-bale push-pending: local mode, nothing to drain");
        return Ok(());
    }
    let git_dir = raw
        .git_dir
        .clone()
        .ok_or_else(|| anyhow!("not inside a git repository"))?;
    let staging = staging_root(&git_dir);

    // Mint the upload token against the remote git is pushing to (not `origin`):
    // the token determines the server-side repo scope of every upload.
    let target_remote: Option<RemoteUrl> = match args.remote_url.as_deref() {
        Some(url) => Some(
            remote::parse_remote(url)
                .with_context(|| format!("parsing push remote URL {url:?}"))?,
        ),
        None => None,
    };

    // Only content the push actually advertises is uploaded: markers also
    // exist for bytes a `git status`/`git diff` re-clean staged that the user
    // never committed, and those must not leave the machine. In hook mode git
    // tells us the ref delta on stdin; run by hand (no args) we treat it as
    // pushing HEAD (whole history, nothing hidden) and only drain staged
    // content HEAD reaches, without re-sourcing anything from other remotes.
    let hook_mode = args.remote_name.is_some();
    let updates = if hook_mode {
        read_ref_updates_from_stdin()?
    } else {
        head_as_update(&cwd)?
    };
    let pushed = reachable_pointers(&cwd, &updates)
        .map_err(|e| explain_partial_clone(e, &cwd))
        .context("enumerating bale files in the pushed commits (push aborted)")?;

    let markers: BTreeMap<String, Option<u64>> = list_staged_files(&git_dir)
        .with_context(|| format!("listing staged files in {}", staging.display()))?
        .into_iter()
        .collect();
    // Freshly staged files the push references (hex -> size). A size-less
    // marker can't drive download_to_writer, so erroring here beats
    // advertising a backless pointer.
    let mut staged: BTreeMap<String, u64> = BTreeMap::new();
    for hex in pushed.keys().filter(|h| markers.contains_key(*h)) {
        let size = markers.get(hex).copied().flatten().ok_or_else(|| {
            anyhow!("staged marker for {hex} has no size; run `git add` again to re-stage it")
        })?;
        staged.insert(hex.clone(), size);
    }
    // Staged content the target ALREADY references (commits pushed earlier with
    // `--no-verify`, or where the hook couldn't run): the remote advertises those
    // pointers with the bytes only here. Not a privacy leak — the commits are
    // already pushed.
    if hook_mode {
        let leftover: BTreeSet<String> = markers
            .keys()
            .filter(|h| !pushed.contains_key(*h))
            .cloned()
            .collect();
        if !leftover.is_empty() {
            let remote_name = args.remote_name.as_deref().unwrap_or("origin");
            for hex in on_target(&cwd, remote_name, &updates, &leftover)
                .map_err(|e| explain_partial_clone(e, &cwd))
                .context("checking staged content the push target already references")?
            {
                let size = markers.get(&hex).copied().flatten().ok_or_else(|| {
                    anyhow!(
                        "staged marker for {hex} has no size; run `git add` again to re-stage it"
                    )
                })?;
                staged.insert(hex, size);
            }
        }
    }
    // Files the push advertises that aren't staged: drained by an earlier push
    // to some other remote. Re-sourced from a remote that still holds them.
    let from_refs: BTreeMap<String, u64> = if hook_mode {
        pushed
            .into_iter()
            .filter(|(h, _)| !markers.contains_key(h))
            .collect()
    } else {
        BTreeMap::new()
    };

    if staged.is_empty() && from_refs.is_empty() {
        // Nothing cleaned and nothing new to this remote, or a prior run drained.
        // (No dir cleanup: unlocked, it could race a concurrent clean.)
        return Ok(());
    }

    let rt = XetRuntime::new().context("starting xet runtime")?;
    let raw_for_auth = raw.clone();
    let target_for_auth = target_remote.clone();
    let auth = rt
        .bridge_sync(async move {
            resolver::resolve_for_remote(&raw_for_auth, resolver::Scope::Write, target_for_auth)
                .await
        })
        .map_err(|e| anyhow!("xet runtime error during Bale auth resolution: {e:?}"))??;

    let online_cfg = default_config(
        auth.server_url.trim_end_matches('/').to_string(),
        Some((auth.token.clone(), auth.token_expiration)),
        Some(resolver::forge_refresher_for_remote(
            &raw,
            resolver::Scope::Write,
            target_remote.clone(),
        )),
        None,
    )
    .context("building online TranslatorConfig for push-pending")?;

    let source_remotes = if from_refs.is_empty() {
        Vec::new()
    } else {
        remote::parse_all_remotes(Some(&cwd))
    };

    let server_url = auth.server_url.clone();
    // See `file_registered_on_target`.
    let probe_server = auth.server_url.trim_end_matches('/').to_string();
    let probe_token = auth.token.clone();
    let total = staged.len() + from_refs.len();

    // The session is created inside the async block, so the progress poller
    // reads it through a shared slot (empty = "preparing").
    let session_slot: Arc<Mutex<Option<Arc<FileUploadSession>>>> = Arc::new(Mutex::new(None));
    let slot_for_poll = session_slot.clone();
    // Filled before finalize so the completion summary splits uploaded vs
    // deduped bytes; otherwise a fully deduped push reads as a full re-upload.
    let metrics_slot: Arc<Mutex<DeduplicationMetrics>> = Arc::new(Mutex::new(Default::default()));
    let metrics_for_poll = metrics_slot.clone();
    let progress = UploadProgress::start(total, move || {
        let session = slot_for_poll.lock().unwrap().clone();
        let Some(session) = session else {
            return UploadSnapshot::default();
        };
        let r = session.report();
        UploadSnapshot {
            bytes_uploaded: r.total_transfer_bytes_completed,
            bytes_total: r.total_transfer_bytes,
            rate_bytes_per_sec: r.total_transfer_bytes_completion_rate,
            bytes_deduped: metrics_for_poll.lock().unwrap().deduped_bytes,
        }
    });

    // The read/re-translate loop below runs without the store lock: it only reads
    // (staging or a source server), so a gc sweeping staging mid-drain just makes
    // this push fail (fail-closed), never corrupts. Only the final marker-removal
    // + sweep takes the lock.
    let slot_for_async = session_slot;
    let metrics_for_async = metrics_slot;
    let raw_for_async = raw.clone();
    let staging_for_async = staging.clone();
    let staged_for_async = staged.clone();
    let result = rt.bridge_sync(async move {
        let upload = FileUploadSession::new(Arc::new(online_cfg)).await?;
        *slot_for_async.lock().unwrap() = Some(upload.clone());

        let mut metrics = DeduplicationMetrics::default();

        // (1) staged files → reconstruct from staging.
        if !staged_for_async.is_empty() {
            let local_cfg = TranslatorConfig::local_config(&staging_for_async)
                .context("building local TranslatorConfig for staging reconstruction")?;
            let staging_dl = FileDownloadSession::new(Arc::new(local_cfg), None).await?;
            for (file_hex, file_size) in &staged_for_async {
                let m =
                    re_translate_one(&staging_dl, upload.clone(), file_hex, *file_size, "local")
                        .await
                        .with_context(|| format!("re-translating staged file {file_hex}"))?;
                metrics.merge_in(&m);
            }
        }

        // (2) already-pushed-elsewhere files → re-source from another remote,
        // skipping any the target already has (or a push to a fully populated
        // remote would re-download its whole history).
        if !from_refs.is_empty() {
            // No probe client → attempt every file (re-translate is idempotent).
            let probe = reqwest::Client::builder()
                .user_agent(concat!("git-bale/", env!("CARGO_PKG_VERSION")))
                .timeout(Duration::from_secs(15))
                .build()
                .ok();
            let mut sources = SourceSessions::new(raw_for_async, source_remotes);
            for (file_hex, file_size) in &from_refs {
                if let Some(probe) = probe.as_ref() {
                    if file_registered_on_target(probe, &probe_server, &probe_token, file_hex).await
                    {
                        tracing::debug!(
                            "push-pending: {file_hex} already on target repo; skipping"
                        );
                        continue;
                    }
                }
                let m = sources
                    .re_translate_from_any(upload.clone(), file_hex, *file_size)
                    .await
                    .with_context(|| {
                        format!("ensuring already-pushed file {file_hex} reaches the push target")
                    })?;
                metrics.merge_in(&m);
            }
        }

        // Publish for the completion summary before finalize() (shards upload there
        // and don't change the dedup split the summary reports).
        *metrics_for_async.lock().unwrap() = metrics;
        tracing::debug!(
            total_bytes = metrics.total_bytes,
            new_bytes = metrics.new_bytes,
            deduped_bytes = metrics.deduped_bytes,
            deduped_bytes_by_global_dedup = metrics.deduped_bytes_by_global_dedup,
            xorb_bytes_uploaded = metrics.xorb_bytes_uploaded,
            "push-pending dedup breakdown"
        );

        upload.finalize().await?;
        Ok::<(), anyhow::Error>(())
    });

    let outcome = result
        .map_err(|e| anyhow!("xet runtime error during push-pending: {e:?}"))
        .and_then(|inner| {
            inner.map_err(|e| {
                let e = explain_quota_exceeded(e, &server_url);
                explain_dedup_cache_mismatch(e, &server_url)
            })
        });
    match outcome {
        Ok(()) => progress.finish(),
        Err(e) => {
            drop(progress);
            return Err(e);
        }
    }

    // Drain only the staged markers we uploaded (under the store lock so a racing
    // `git add` isn't blanket-swept): remove each, then sweep shared objects only
    // if no marker remains. Objects are deduped across files, so per-file object
    // deletion is unsafe — hence the all-or-nothing sweep. The `from_refs` files
    // were never in staging, so there's nothing to drain for them.
    if !staged.is_empty() {
        match crate::store::StoreLock::acquire_exclusive(&staging) {
            Ok(_lock) => {
                for file_hex in staged.keys() {
                    if let Err(e) = remove_marker(&git_dir, file_hex) {
                        tracing::warn!("removing marker {file_hex} in {}: {e}", staging.display());
                    }
                }
                // Unreadable inventory → keep the objects (sweeping on a guess
                // could delete a concurrently staged file's only copy). A git op
                // in flight (a `git add` between files) may be about to dedup
                // against them; leave them for the next gc/drain.
                let busy = crate::gc::git_op_in_flight(&git_dir).unwrap_or(true);
                match list_staged_files(&git_dir) {
                    Ok(_) if busy => {}
                    Ok(remaining) if remaining.is_empty() => {
                        if let Err(e) = sweep_objects(&staging) {
                            tracing::warn!(
                                "removing staged objects under {}: {e}",
                                staging.display()
                            );
                        }
                    }
                    Ok(_) => {}
                    Err(e) => tracing::warn!(
                        "re-listing markers in {}: {e}; leaving staged objects",
                        staging.display()
                    ),
                }
                let _ = remove_empty_dirs(&staging);
            }
            Err(e) => {
                tracing::warn!(
                    "push-pending: could not lock store {} for cleanup: {e}; leaving staging intact",
                    staging.display()
                );
            }
        }
    }

    Ok(())
}

/// Download, re-clean through `upload_session`, and assert the round-tripped
/// hash matches. The session POSTs only new xorbs but always its reconstruction
/// shard, which registers the file under the upload token's repo.
async fn re_translate_one(
    download_session: &Arc<FileDownloadSession>,
    upload_session: Arc<FileUploadSession>,
    file_hex: &str,
    file_size: u64,
    // Where the bytes are sourced from ("local" staging or a remote name), woven
    // into the reconstruct-failure message — the corrupt-staging e2e phase keys
    // on "local reconstruct" to confirm a missing staged xorb fails *here*.
    source: &str,
) -> Result<DeduplicationMetrics> {
    // `clean_file` needs a path (it reads twice: hashing, then chunking), so the
    // download can't stream straight into the upload.
    let tmp = NamedTempFile::new().context("creating temp file for re-translation")?;
    let info_for_dl = XetFileInfo::new(file_hex.to_string(), file_size);
    let writer = tmp
        .reopen()
        .context("reopening temp file for download write")?;
    download_session
        .download_to_writer(&info_for_dl, 0..file_size, writer)
        .await
        .with_context(|| format!("{source} reconstruct of {file_hex} failed"))?;

    let (new_info, metrics) = clean_file(upload_session, tmp.path(), Sha256Policy::Compute)
        .await
        .with_context(|| format!("re-cleaning {file_hex} through online session"))?;

    if new_info.hash() != file_hex {
        bail!(
            "re-translation produced file_hash {} but expected {file_hex} \
             — aborting push to keep the server's view consistent with Git's",
            new_info.hash(),
        );
    }
    Ok(metrics)
}

/// Lazily-built read sessions for each configured remote, used to re-source the
/// bytes of a file that's reachable from the push but no longer in staging.
/// Tries remotes in order (`origin` first) and caches sessions; a remote whose
/// auth fails is marked dead so we don't re-resolve it per file.
struct SourceSessions {
    raw: RawConfig,
    remotes: Vec<(String, RemoteUrl)>,
    built: Vec<Option<Arc<FileDownloadSession>>>,
    dead: Vec<bool>,
}

impl SourceSessions {
    fn new(raw: RawConfig, remotes: Vec<(String, RemoteUrl)>) -> Self {
        let n = remotes.len();
        Self {
            raw,
            remotes,
            built: vec![None; n],
            dead: vec![false; n],
        }
    }

    async fn session(&mut self, i: usize) -> Option<Arc<FileDownloadSession>> {
        if self.dead[i] {
            return None;
        }
        if let Some(s) = &self.built[i] {
            return Some(s.clone());
        }
        match build_read_session(&self.raw, &self.remotes[i].1).await {
            Ok(s) => {
                self.built[i] = Some(s.clone());
                Some(s)
            }
            Err(e) => {
                tracing::debug!(
                    "push-pending: remote {} unusable as a source: {e:#}",
                    self.remotes[i].0
                );
                self.dead[i] = true;
                None
            }
        }
    }

    async fn re_translate_from_any(
        &mut self,
        upload_session: Arc<FileUploadSession>,
        file_hex: &str,
        file_size: u64,
    ) -> Result<DeduplicationMetrics> {
        for i in 0..self.remotes.len() {
            let Some(dl) = self.session(i).await else {
                continue;
            };
            // A failed download (file not in that remote's repo → 404) falls
            // through to the next source. Downloads are NOT content-verified;
            // the re-clean's hash check in `re_translate_one` is what rejects
            // corrupt bytes before they're registered on the target.
            let label = format!("remote '{}'", self.remotes[i].0);
            match re_translate_one(&dl, upload_session.clone(), file_hex, file_size, &label).await {
                Ok(metrics) => return Ok(metrics),
                Err(e) => tracing::debug!(
                    "push-pending: remote {} could not provide {file_hex}: {e:#}",
                    self.remotes[i].0
                ),
            }
        }
        bail!(
            "no configured remote can reconstruct already-committed bale file {file_hex}; \
             its bytes are on no reachable server. Push it to the remote that originally \
             received it first."
        )
    }
}

async fn build_read_session(
    raw: &RawConfig,
    remote: &RemoteUrl,
) -> Result<Arc<FileDownloadSession>> {
    let auth =
        resolver::resolve_for_remote(raw, resolver::Scope::Read, Some(remote.clone())).await?;
    let cfg = default_config(
        auth.server_url.trim_end_matches('/').to_string(),
        Some((auth.token.clone(), auth.token_expiration)),
        Some(resolver::forge_refresher_for_remote(
            raw,
            resolver::Scope::Read,
            Some(remote.clone()),
        )),
        None,
    )
    .context("building read TranslatorConfig for re-sourcing")?;
    Ok(FileDownloadSession::new(Arc::new(cfg), None).await?)
}

/// Whether `file_hex` is registered under the target repo: `GET
/// /v1/reconstructions/{hash}` with the target write token 404s unless the file
/// is in *this token's* repo. Any other failure returns false, so we re-translate
/// (idempotent) rather than wrongly skip a file the target lacks.
async fn file_registered_on_target(
    client: &reqwest::Client,
    server_url: &str,
    token: &str,
    file_hex: &str,
) -> bool {
    let url = format!("{server_url}/v1/reconstructions/{file_hex}");
    match client
        .get(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        // Scope check is the same; one byte keeps the response to the first
        // term instead of a huge file's whole term list.
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .await
    {
        // 416 comes after the scope check: a registered empty file.
        Ok(resp) => {
            resp.status().is_success()
                || resp.status() == reqwest::StatusCode::RANGE_NOT_SATISFIABLE
        }
        Err(_) => false,
    }
}

/// `HEAD` as a single ref update with nothing on the remote side (manual run).
fn head_as_update(cwd: &Path) -> Result<Vec<(ObjectId, Option<ObjectId>)>> {
    let repo = gix::discover(cwd).with_context(|| format!("opening repo at {}", cwd.display()))?;
    Ok(match repo.head_id() {
        Ok(id) => vec![(id.detach(), None)],
        Err(_) => Vec::new(), // unborn HEAD: nothing committed to push
    })
}

/// Parse pre-push stdin lines (`<local ref> <local sha> <remote ref> <remote
/// sha>`) into `(local_oid, remote_oid)`. Deletes (zero local sha) are skipped;
/// a zero/invalid remote sha (new ref) yields `None`.
fn read_ref_updates_from_stdin() -> Result<Vec<(ObjectId, Option<ObjectId>)>> {
    let mut buf = String::new();
    std::io::stdin()
        .read_to_string(&mut buf)
        .context("reading pre-push ref updates from stdin")?;
    let mut out = Vec::new();
    for line in buf.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 4 {
            continue;
        }
        let Some(local) = parse_oid(parts[1]) else {
            continue; // delete or unparseable — nothing to push
        };
        out.push((local, parse_oid(parts[3])));
    }
    Ok(out)
}

/// `ObjectId` from a 40/64-char hex sha, or `None` for the all-zero "no such
/// ref" sentinel git uses for creations/deletions.
fn parse_oid(s: &str) -> Option<ObjectId> {
    let oid = ObjectId::from_hex(s.as_bytes()).ok()?;
    if oid.is_null() {
        None
    } else {
        Some(oid)
    }
}

/// All bale pointers (`file_hex -> file_size`) the pushed commits introduce:
/// walk the local shas (tags peeled) hiding only the remote shas git reports on
/// stdin; a new ref hides nothing, so the full history is enumerated. Any read
/// error fails the push: under-counting advertises a pointer the target can't
/// reconstruct.
///
/// Deliberately does NOT hide `refs/remotes/<name>/*`: commits on a remote don't
/// prove their bale objects were registered under its repo (e.g. pushed by an
/// old client or with `--no-verify`). The per-file probe in `run` keeps the
/// over-walk cheap.
fn reachable_pointers(
    start_dir: &Path,
    updates: &[(ObjectId, Option<ObjectId>)],
) -> Result<BTreeMap<String, u64>> {
    if updates.is_empty() {
        return Ok(BTreeMap::new());
    }
    let repo = gix::discover(start_dir)
        .with_context(|| format!("opening repo at {}", start_dir.display()))?;
    let common = crate::store::common_git_dir(&repo);
    let partial = crate::gc::is_partial_clone(&repo, &common);
    let mut out = Found {
        pointers: BTreeMap::new(),
        missing: partial.then(Vec::new),
    };

    let mut tips: Vec<ObjectId> = Vec::new();
    for (local, _) in updates {
        let peeled = repo
            .find_object(*local)
            .and_then(|o| o.peel_tags_to_end())
            .with_context(|| format!("reading pushed object {local}"))?;
        match peeled.kind {
            gix::object::Kind::Commit => tips.push(peeled.id),
            gix::object::Kind::Tree => {
                let tree = repo.find_tree(peeled.id)?;
                collect_changed_pointers(&repo, &repo.empty_tree(), &tree, &mut out)?;
            }
            gix::object::Kind::Blob => consider_blob(&repo, peeled.id, &mut out)?,
            gix::object::Kind::Tag => {}
        }
    }

    // Hiding fewer commits only enumerates more, so drop any remote sha we
    // can't resolve to a local commit (someone else's push we never fetched).
    let hidden: Vec<ObjectId> = updates
        .iter()
        .filter_map(|(_, r)| *r)
        .filter_map(|id| {
            let peeled = repo.find_object(id).ok()?.peel_tags_to_end().ok()?;
            (peeled.kind == gix::object::Kind::Commit).then_some(peeled.id)
        })
        .collect();

    if !tips.is_empty() {
        collect_delta(&repo, &tips, &hidden, &mut out, None)?;
    }

    let missing = out.missing.take().unwrap_or_default();
    if !missing.is_empty() {
        lazy_fetch(start_dir, &missing)?;
        // Fresh handle: the ODB may have cached the pack list before the fetch.
        let repo = gix::discover(start_dir)
            .with_context(|| format!("reopening repo at {}", start_dir.display()))?;
        for oid in missing {
            consider_blob(&repo, oid, &mut out)?;
        }
    }
    Ok(out.pointers)
}

/// Subset of `want` reachable from what the target remote already has: the
/// remote shas git reported on stdin plus `refs/remotes/<remote>/*` (when
/// `remote_name` is a configured remote).
fn on_target(
    start_dir: &Path,
    remote_name: &str,
    updates: &[(ObjectId, Option<ObjectId>)],
    want: &BTreeSet<String>,
) -> Result<BTreeSet<String>> {
    let repo = gix::discover(start_dir)
        .with_context(|| format!("opening repo at {}", start_dir.display()))?;
    let mut tips: Vec<ObjectId> = updates.iter().filter_map(|(_, r)| *r).collect();
    // `git push <url>` passes the URL as the remote name: no tracking refs.
    let names: Vec<String> = repo.remote_names().iter().map(|n| n.to_string()).collect();
    if names.iter().any(|n| n == remote_name) {
        let prefix = format!("refs/remotes/{remote_name}/");
        // A remote named `<name>/x` has its tracking refs under our prefix too.
        let nested: Vec<String> = names
            .iter()
            .filter(|n| n.starts_with(&prefix["refs/remotes/".len()..]))
            .map(|n| format!("refs/remotes/{n}/"))
            .collect();
        let platform = repo.references().context("opening refs")?;
        for r in platform
            .prefixed(prefix.as_str())
            .context("listing remote-tracking refs")?
        {
            let r = r.map_err(|e| anyhow!("reading a remote-tracking ref: {e}"))?;
            let name = r.name().as_bstr().to_string();
            if nested.iter().any(|p| name.starts_with(p.as_str())) {
                continue;
            }
            if let gix::refs::TargetRef::Object(id) = r.target() {
                tips.push(id.to_owned());
            }
        }
    }
    // A remote sha we never fetched names nothing we could have staged.
    let tips: Vec<ObjectId> = tips
        .into_iter()
        .filter_map(|id| {
            let peeled = repo.find_object(id).ok()?.peel_tags_to_end().ok()?;
            (peeled.kind == gix::object::Kind::Commit).then_some(peeled.id)
        })
        .collect();
    if tips.is_empty() {
        return Ok(BTreeSet::new());
    }
    let common = crate::store::common_git_dir(&repo);
    let mut out = Found {
        pointers: BTreeMap::new(),
        missing: crate::gc::is_partial_clone(&repo, &common).then(Vec::new),
    };
    collect_delta(&repo, &tips, &[], &mut out, Some(want))?;
    let missing = out.missing.take().unwrap_or_default();
    if !missing.is_empty() {
        lazy_fetch(start_dir, &missing)?;
        let repo = gix::discover(start_dir)
            .with_context(|| format!("reopening repo at {}", start_dir.display()))?;
        for oid in missing {
            consider_blob(&repo, oid, &mut out)?;
        }
    }
    Ok(out
        .pointers
        .into_keys()
        .filter(|h| want.contains(h))
        .collect())
}

struct Found {
    pointers: BTreeMap<String, u64>,
    /// `Some` in a partial clone: blobs the walk needed but don't exist locally.
    missing: Option<Vec<ObjectId>>,
}

/// Have git fetch exactly `oids` from the promisor remote: in a partial clone
/// `cat-file` lazily fetches any object it's asked about.
fn lazy_fetch(cwd: &Path, oids: &[ObjectId]) -> Result<()> {
    use std::io::Write as _;
    let mut child = std::process::Command::new("git")
        .current_dir(cwd)
        .args(["cat-file", "--batch-check"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("spawning git cat-file to fetch missing blobs")?;
    {
        let mut stdin = child
            .stdin
            .take()
            .ok_or_else(|| anyhow!("git cat-file stdin unavailable"))?;
        for oid in oids {
            writeln!(stdin, "{oid}")?;
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!(
            "fetching {} missing blob(s) from the promisor remote failed: {}",
            oids.len(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Walk `tips` hiding `hidden`, recording pointers each commit introduces (diff
/// vs first parent; an unreadable parent diffs against the empty tree, which
/// only over-collects).
fn collect_delta(
    repo: &gix::Repository,
    tips: &[ObjectId],
    hidden: &[ObjectId],
    out: &mut Found,
    want: Option<&BTreeSet<String>>,
) -> Result<()> {
    let walk = repo
        .rev_walk(tips.iter().copied())
        .with_hidden(hidden.iter().copied())
        .all()
        .context("setting up history walk")?;
    for info in walk {
        let info = info.context("walking pushed history")?;
        let commit = info
            .object()
            .with_context(|| format!("reading commit {}", info.id))?;
        let commit_tree = commit
            .tree()
            .with_context(|| format!("reading tree of {}", info.id))?;
        let parent_tree = info
            .parent_ids()
            .next()
            .and_then(|pid| pid.object().ok())
            .and_then(|o| o.peel_to_commit().ok())
            .and_then(|c| c.tree().ok())
            .unwrap_or_else(|| repo.empty_tree());
        collect_changed_pointers(repo, &parent_tree, &commit_tree, out)?;
        if want.is_some_and(|w| w.iter().all(|h| out.pointers.contains_key(h))) {
            break;
        }
    }
    Ok(())
}

fn collect_changed_pointers(
    repo: &gix::Repository,
    parent_tree: &gix::Tree<'_>,
    commit_tree: &gix::Tree<'_>,
    out: &mut Found,
) -> Result<()> {
    let mut platform = parent_tree.changes().context("preparing tree diff")?;
    // Skip rename tracking (O(N²) similarity): a moved pointer still surfaces as
    // an Addition carrying the same blob id.
    platform.options(|opts| {
        opts.track_rewrites(None);
    });
    let mut failure: Option<anyhow::Error> = None;
    let result = platform.for_each_to_obtain_tree(
        commit_tree,
        |change| -> Result<gix::object::tree::diff::Action, std::convert::Infallible> {
            use gix::object::tree::diff::Change;
            if let Change::Addition { entry_mode, id, .. }
            | Change::Modification { entry_mode, id, .. } = change
            {
                if entry_mode.is_blob() {
                    if let Err(e) = consider_blob(repo, id.detach(), out) {
                        failure = Some(e);
                        return Ok(std::ops::ControlFlow::Break(()));
                    }
                }
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    );
    if let Some(e) = failure {
        return Err(e);
    }
    result.context("diffing trees")?;
    Ok(())
}

/// Record `oid` as a pointer (`hash -> file_size`) if it's a small blob that
/// parses as one. Header pre-filters keep non-pointer blobs from being read.
fn consider_blob(repo: &gix::Repository, oid: ObjectId, out: &mut Found) -> Result<()> {
    let header = match repo.find_header(oid) {
        Ok(h) => h,
        Err(e) => match out.missing.as_mut() {
            // Partial clone: fetched lazily in one batch after the walk.
            Some(missing) => {
                missing.push(oid);
                return Ok(());
            }
            None => {
                return Err(e)
                    .with_context(|| format!("blob {oid} is missing from the object database"))
            }
        },
    };
    if header.kind() != gix::object::Kind::Blob
        || header.size() == 0
        || header.size() > pointer::POINTER_MAX_BYTES as u64
    {
        return Ok(());
    }
    let obj = repo
        .find_object(oid)
        .with_context(|| format!("reading blob {oid}"))?;
    if let Ok(info) = pointer::parse_pointer(&obj.data) {
        if !pointer::is_safe_file_id(info.hash()) {
            // Small JSON that happens to have a `hash` key: never ours.
            tracing::debug!("push-pending: blob {oid} has a non-hex `hash`; not a bale pointer");
            return Ok(());
        }
        if let Some(size) = info.file_size() {
            out.pointers.insert(info.hash().to_string(), size);
        }
    }
    Ok(())
}

fn explain_partial_clone(err: anyhow::Error, cwd: &Path) -> anyhow::Error {
    let partial = gix::discover(cwd).is_ok_and(|repo| {
        let common = crate::store::common_git_dir(&repo);
        crate::gc::is_partial_clone(&repo, &common)
    });
    if !partial {
        return err;
    }
    err.context(
        "this is a partial clone (promisor remote) and a blob the pushed history needs is \
         not available locally; git-bale can't tell which bale files the push references. \
         Fetch the missing blobs (e.g. `git fetch --refetch` or `git rev-list --objects --all \
         --missing=print`) or push from a full clone",
    )
}

// The bale server answers over-quota with 413 (see `quota_exceeded` in
// bale-server-http). xet drops the response body, so key on the parenthesised
// status in reqwest's Display ("HTTP status client error (413) for url ..") —
// never a bare "413", which a hex hash in the URL can contain.
fn explain_quota_exceeded(err: anyhow::Error, server_url: &str) -> anyhow::Error {
    let chain = format!("{err:#}");
    let is_quota = chain.contains("(413")
        || chain.contains("Payload Too Large")
        || chain.contains("quota exceeded");
    if !is_quota {
        return err;
    }
    err.context(format!(
        "push to {server_url} was rejected: you are over your storage quota. Free up \
         space by removing large tracked files from history (or ask an administrator \
         to raise your quota), then push again."
    ))
}

// The server 400s a shard naming a xorb it doesn't hold; here that means the
// local xet dedup cache skipped re-sending a xorb the server has since lost
// (storage reset or gc'd). xet erases the body, so key on status + URL — a
// freshly round-tripped shard can't be malformed.
fn explain_dedup_cache_mismatch(err: anyhow::Error, server_url: &str) -> anyhow::Error {
    let chain = format!("{err:#}");
    let is_shards_400 =
        chain.contains("shards") && (chain.contains("400") || chain.contains("Bad Request"));
    if !is_shards_400 {
        return err;
    }
    // main()'s set_default_xet_cache_root() pins HF_XET_CACHE before any work,
    // so this is the directory xet actually used for this session's dedup.
    let current_cache_dir =
        std::env::var("HF_XET_CACHE").unwrap_or_else(|_| "~/.cache/bale/xet".to_string());
    err.context(format!(
        "push to {server_url} was rejected: the server is missing content this \
         push depends on. This almost always means your local cache is incompatible \
         with the server. Either clear the cache to continue or set a new cache directory. \
         Active cache directory: {current_cache_dir}. Set env var \"$BALE_XET_CACHE\" to override."
    ))
}
