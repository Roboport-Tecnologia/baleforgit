//! `git-bale push-pending` — ensure every bale file the push advertises is
//! present on (and scoped to) the remote being pushed to.
//!
//! Invoked by the pre-push hook as `git-bale push-pending <remote> <url>` with
//! git's ref-update lines on stdin. Two classes of file must reach the target:
//!
//!   1. **Freshly staged** files (`git add` cleaned them offline into
//!      `.git/bale/staging/`, no server has them yet) — reconstructed from
//!      staging and re-translated through an online session to the target.
//!   2. **Already-pushed-elsewhere** files reachable from the refs being pushed
//!      but no longer in staging (a prior push to a *different* remote drained
//!      them). The server scopes uploads per-repo, so the target repo doesn't
//!      know about them yet and a clone of the target would 404 on checkout.
//!      We re-source their bytes from whichever remote still holds them and
//!      re-translate through the target session, which registers the file under
//!      the target repo (the per-session reconstruction shard is always
//!      uploaded; xorbs dedup against the server, so this is cheap when the
//!      remotes share a server).
//!
//! Re-translating (rather than POSTing staged xorbs/shards verbatim) keeps the
//! server's global dedup intact: the online `FileUploadSession` queries
//! server-known chunks and only POSTs genuinely new xorbs. Clean stays offline;
//! the contract holds. xet's CDC is deterministic, so the merkle hash out of the
//! online session must equal the file hash we sourced for — we assert that and
//! bail on mismatch (version skew or corruption).

use std::collections::BTreeMap;
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
    list_staged_files, remove_all_staged_objects, remove_empty_dirs, remove_marker, staging_root,
};

/// Positional args from the pre-push hook (`$1` remote name, `$2` remote URL).
/// Both `None` when invoked by hand: auth falls back to `origin` and only
/// staging is drained (no ref set to reconcile against).
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

    // Freshly staged files (hex -> size). A size-less marker can't drive
    // download_to_writer, so erroring here beats advertising a backless pointer.
    let mut staged: BTreeMap<String, u64> = BTreeMap::new();
    for (hex, size) in list_staged_files(&git_dir)
        .with_context(|| format!("listing staged files in {}", staging.display()))?
    {
        let size = size.ok_or_else(|| {
            anyhow!(
                "staged marker for {hex} has no size — was it written by an older client? \
                 Run `git add` again to re-stage with a size."
            )
        })?;
        staged.insert(hex, size);
    }

    // Files the push advertises that aren't in staging: they were pushed to some
    // other remote and drained. Only computed in hook mode (stdin tells us what's
    // being pushed). Re-sourced from another remote that still holds them.
    let from_refs: BTreeMap<String, u64> = if args.remote_name.is_some() {
        let updates = read_ref_updates_from_stdin()?;
        reachable_pointers(&cwd, &updates)
            .into_iter()
            .filter(|(h, _)| !staged.contains_key(h))
            .collect()
    } else {
        BTreeMap::new()
    };

    if staged.is_empty() && from_refs.is_empty() {
        // Nothing cleaned and nothing new to this remote, or a prior run drained.
        let _ = remove_empty_dirs(&staging);
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

    // Remotes to source already-pushed files from. Empty when there are none to
    // source (nothing but staged files), to skip the discovery walk.
    let source_remotes = if from_refs.is_empty() {
        Vec::new()
    } else {
        remote::parse_all_remotes(Some(&cwd))
    };

    let server_url = auth.server_url.clone();
    // For the per-file "already registered on the target?" probe (below): the
    // target's server + write token. A write token is accepted on GET
    // reconstruction, and reconstruction 404s unless the file is registered
    // under *this* token's repo — exactly the signal we want.
    let probe_server = auth.server_url.trim_end_matches('/').to_string();
    let probe_token = auth.token.clone();
    let total = staged.len() + from_refs.len();

    // Reports upload progress once work runs past ~200ms. The session is created
    // inside the async block below, so the poller reads it through a shared slot
    // (empty = "preparing", before the session exists).
    let session_slot: Arc<Mutex<Option<Arc<FileUploadSession>>>> = Arc::new(Mutex::new(None));
    let slot_for_poll = session_slot.clone();
    // Dedup breakdown, filled in once all files are re-cleaned (before finalize).
    // The live bar ignores it; the completion summary reads it to split the bytes
    // into uploaded-vs-deduped, so a push whose content the server already had
    // doesn't read as a full re-upload of the whole file.
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
        // skipping any the target already has registered (so a push to a remote
        // that's already fully populated doesn't re-download its whole history).
        if !from_refs.is_empty() {
            // One client for all probes; if it can't be built, skip probing and
            // attempt every file (re-translate is idempotent — just less cheap).
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
                let remaining = list_staged_files(&git_dir).map(|v| v.len()).unwrap_or(0);
                if remaining == 0 {
                    if let Err(e) = remove_all_staged_objects(&staging) {
                        tracing::warn!("removing staged objects under {}: {e}", staging.display());
                    }
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

/// Download `file_hex` (size `file_size`) through `download_session`, re-clean it
/// through `upload_session`, and assert the round-tripped hash matches. The
/// online upload session POSTs only genuinely-new xorbs and always its
/// per-session reconstruction shard, so this both uploads new content and
/// registers the file under the upload token's repo scope. Returns the dedup
/// metrics so the caller can report uploaded-vs-deduped bytes.
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
    // Via a temp file because `clean_file` takes a path (it reads twice —
    // hashing then chunking — and needs random access), so we can't stream
    // download straight into upload.
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
            // through to the next source; download verifies content against the
            // merkle hash, so a *successful* download then cleanly round-trips.
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

/// True iff `file_hex` is already registered under the target repo, via
/// `GET /v1/reconstructions/{hash}` with the target write token. The server 404s
/// unless the file is in *this token's* repo (the per-repo scope check), so a 200
/// means "already here, no need to re-source." Any non-200 — 404, an auth hiccup,
/// a network error — returns false so we attempt the (idempotent) re-translate
/// rather than wrongly skip a file the target lacks.
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
        .send()
        .await
    {
        Ok(resp) => resp.status().is_success(),
        Err(_) => false,
    }
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

/// All bale pointers (`file_hex -> file_size`) introduced by the commits being
/// pushed: walk `tips` (local shas) hiding only the *remote shas git reports on
/// stdin* (what the pushed ref currently points to on the remote), and for each
/// commit collect Added/Modified blobs that parse as pointers. A new ref (remote
/// sha = zero) hides nothing → the full history is enumerated.
///
/// Deliberately does NOT hide the remote's `refs/remotes/<name>/*`: git refs
/// being present on a remote says nothing about whether the *bale objects* were
/// ever registered under that remote's repo (the server scopes registration
/// per-repo, and an old client — or this very bug — could have pushed the
/// commits without the objects). Hiding them would skip exactly the files this
/// drain must register. The per-file server probe in `run` keeps the resulting
/// over-walk cheap by not re-uploading files already registered on the target.
fn reachable_pointers(
    start_dir: &Path,
    updates: &[(ObjectId, Option<ObjectId>)],
) -> BTreeMap<String, u64> {
    let mut out = BTreeMap::new();
    let repo = match gix::discover(start_dir) {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!("push-pending: not in a git repo ({e}); no refs to reconcile");
            return out;
        }
    };

    let tips: Vec<ObjectId> = updates
        .iter()
        .map(|(l, _)| *l)
        .filter(|id| is_commit(&repo, *id))
        .collect();
    if tips.is_empty() {
        return out;
    }

    let hidden: Vec<ObjectId> = updates.iter().filter_map(|(_, r)| *r).collect();

    // A bad hidden tip (remote sha not present locally) would abort the walk; if
    // hidden-walk fails, retry with none hidden so we over-upload rather than
    // strand a pointer the target can't reconstruct.
    if !collect_delta(&repo, &tips, &hidden, &mut out) && !hidden.is_empty() {
        out.clear();
        collect_delta(&repo, &tips, &[], &mut out);
    }
    out
}

/// Walk `tips` hiding `hidden`, recording pointers each commit introduces (diff
/// vs first parent). Returns false if the rev walk couldn't be set up.
fn collect_delta(
    repo: &gix::Repository,
    tips: &[ObjectId],
    hidden: &[ObjectId],
    out: &mut BTreeMap<String, u64>,
) -> bool {
    let walk = match repo
        .rev_walk(tips.iter().copied())
        .with_hidden(hidden.iter().copied())
        .all()
    {
        Ok(w) => w,
        Err(e) => {
            tracing::debug!("push-pending: rev walk failed ({e})");
            return false;
        }
    };
    for info in walk {
        let Ok(info) = info else { continue };
        let Ok(commit) = info.object() else { continue };
        let Ok(commit_tree) = commit.tree() else {
            continue;
        };
        let parent_tree = info
            .parent_ids()
            .next()
            .and_then(|pid| pid.object().ok())
            .and_then(|o| o.peel_to_commit().ok())
            .and_then(|c| c.tree().ok())
            .unwrap_or_else(|| repo.empty_tree());
        collect_changed_pointers(repo, &parent_tree, &commit_tree, out);
    }
    true
}

fn collect_changed_pointers(
    repo: &gix::Repository,
    parent_tree: &gix::Tree<'_>,
    commit_tree: &gix::Tree<'_>,
    out: &mut BTreeMap<String, u64>,
) {
    let mut platform = match parent_tree.changes() {
        Ok(p) => p,
        Err(_) => return,
    };
    // Skip rename tracking (O(N²) similarity): a moved pointer still surfaces as
    // a Deletion + Addition carrying the same blob id.
    platform.options(|opts| {
        opts.track_rewrites(None);
    });
    let _ = platform.for_each_to_obtain_tree(
        commit_tree,
        |change| -> Result<gix::object::tree::diff::Action, std::convert::Infallible> {
            use gix::object::tree::diff::Change;
            if let Change::Addition { entry_mode, id, .. }
            | Change::Modification { entry_mode, id, .. } = change
            {
                if entry_mode.is_blob() {
                    consider_blob(repo, id.detach(), out);
                }
            }
            Ok(std::ops::ControlFlow::Continue(()))
        },
    );
}

/// Record `oid` as a pointer (`hash -> file_size`) if it's a small blob that
/// parses as one. Header pre-filters keep non-pointer blobs from being read.
fn consider_blob(repo: &gix::Repository, oid: ObjectId, out: &mut BTreeMap<String, u64>) {
    let header = match repo.find_header(oid) {
        Ok(h) => h,
        Err(_) => return,
    };
    if header.kind() != gix::object::Kind::Blob
        || header.size() == 0
        || header.size() > pointer::POINTER_MAX_BYTES as u64
    {
        return;
    }
    let Ok(obj) = repo.find_object(oid) else {
        return;
    };
    if let Ok(info) = pointer::parse_pointer(&obj.data) {
        if let Some(size) = info.file_size() {
            out.insert(info.hash().to_string(), size);
        }
    }
}

fn is_commit(repo: &gix::Repository, oid: ObjectId) -> bool {
    repo.find_header(oid)
        .is_ok_and(|h| h.kind() == gix::object::Kind::Commit)
}

// Over-quota uploads surface from xet as a noisy HTTP error: the bale server
// returns 429, xet treats 429 as transient and retries it to exhaustion, so the
// chain we finally see is long. Collapse it to one actionable line. xet drops
// the response body before we ever see it, so the only reliable signal is the
// status code in reqwest's Display ("HTTP status client error (429) for url ..").
// Match the parenthesised status, not a bare "429" — a hex hash in the request
// URL can contain those digits. ("quota exceeded"/"Too Many Requests" are kept
// as harmless future-proofing if a later xet ever surfaces body/reason.) A 429
// from a bale server only ever means over-quota; no other endpoint returns it.
fn explain_quota_exceeded(err: anyhow::Error, server_url: &str) -> anyhow::Error {
    let chain = format!("{err:#}");
    let is_quota = chain.contains("(429")
        || chain.contains("Too Many Requests")
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

// Turn the opaque "400 Bad Request on /shards" that xet surfaces into an
// actionable diagnosis. The server rejects a shard whose CAS blocks name a xorb
// it doesn't hold; in push-pending that happens when our local xet dedup cache
// recorded a xorb as already uploaded and so skipped re-sending it, but the
// server no longer has it (its storage was reset or gc'd). xet erases the
// response body and hands us only status + URL, so we key on those — a /shards
// 400 here is overwhelmingly this case (a freshly round-tripped shard can't be
// malformed or oversized).
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
