//! In-memory virtual filesystem for the mount backends.
//!
//! Two construction modes:
//! - *Diff* (`build`) flattens a pre-walked diff entry list into a fully
//!   populated tree at construction time. Each leaf has the rev label folded
//!   into the basename (`foo.txt` on side A → `foo__<labelA>.txt`), with
//!   directories deduplicated across both sides.
//! - *Lazy single-rev* (`build_single_lazy`) defers tree population: each
//!   directory starts unresolved and reads its gix tree object the first time
//!   FUSE looks inside it. Pays for nothing the user never touches.
//!
//! Inode IDs are stable for the life of the mount, including ones allocated
//! lazily — `lookup_child` memoizes per `(parent, name)`.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::{Arc, Mutex};

use crate::mount::diff::DiffEntry;
use crate::mount::reader::{BlobSource, Reader};

pub const ROOT_INODE: u64 = 1;

#[derive(Clone, Debug)]
pub enum NodeKind {
    Dir,
    File { size: u64, source: Arc<BlobSource> },
}

#[derive(Clone, Debug)]
pub struct Node {
    pub inode: u64,
    pub kind: NodeKind,
}

#[derive(Debug)]
struct DirState {
    /// child name → inode
    children: HashMap<OsString, u64>,
    /// Some(...) until the dir has been resolved against its git tree object.
    /// Eager (diff) dirs skip the lazy state entirely (`None`).
    lazy: Option<LazyDir>,
}

#[derive(Debug, Clone)]
struct LazyDir {
    tree_oid: gix::ObjectId,
    /// Repo-relative directory path, "" at the root. Used for pathspec matching.
    path_prefix: String,
}

/// Per-VFS state needed to populate lazy directories. Absent in diff/eager
/// constructions so `lookup_child` skips the lazy code path entirely.
struct LazyContext {
    repo: Arc<gix::ThreadSafeRepository>,
    pathspec: Vec<String>,
}

struct VfsState {
    nodes: HashMap<u64, Node>,
    dirs: HashMap<u64, DirState>,
    next_inode: u64,
}

pub struct DiffVfs {
    state: Mutex<VfsState>,
    lazy: Option<LazyContext>,
    reader: Arc<Reader>,
}

impl DiffVfs {
    /// Two-sided diff view: each side's path is labelled (`foo__main.rs` vs
    /// `foo__feature.rs`) so a single mount point can show both versions
    /// without overwriting each other.
    pub fn build(entries: &[DiffEntry], label_a: &str, label_b: &str, reader: Arc<Reader>) -> Self {
        let mut state = empty_state();
        add_eager_root(&mut state);
        for entry in entries {
            if let (Some(path), Some(oid)) = (&entry.path_a, &entry.oid_a) {
                eager_insert(&mut state, path, oid, Some(label_a));
            }
            if let (Some(path), Some(oid)) = (&entry.path_b, &entry.oid_b) {
                eager_insert(&mut state, path, oid, Some(label_b));
            }
        }
        DiffVfs {
            state: Mutex::new(state),
            lazy: None,
            reader,
        }
    }

    /// Lazy single-rev view: only the root inode is allocated up front. The
    /// first `lookup_child` / `readdir` on any directory reads the
    /// corresponding tree object and populates its children. Pathspec entries
    /// (literal prefix match, same semantics as the eager walker) prune
    /// subtrees we never descend into.
    pub fn build_single_lazy(
        repo: Arc<gix::ThreadSafeRepository>,
        root_tree: gix::ObjectId,
        pathspec: Vec<String>,
        reader: Arc<Reader>,
    ) -> Self {
        let mut state = empty_state();
        state.nodes.insert(
            ROOT_INODE,
            Node {
                inode: ROOT_INODE,
                kind: NodeKind::Dir,
            },
        );
        state.dirs.insert(
            ROOT_INODE,
            DirState {
                children: HashMap::new(),
                lazy: Some(LazyDir {
                    tree_oid: root_tree,
                    path_prefix: String::new(),
                }),
            },
        );
        DiffVfs {
            state: Mutex::new(state),
            lazy: Some(LazyContext { repo, pathspec }),
            reader,
        }
    }

    pub fn reader(&self) -> &Arc<Reader> {
        &self.reader
    }

    pub fn lookup_by_inode(&self, inode: u64) -> Option<Node> {
        self.state.lock().unwrap().nodes.get(&inode).cloned()
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<Node> {
        let mut state = self.state.lock().unwrap();
        self.populate_if_lazy(&mut state, parent);
        let dir = state.dirs.get(&parent)?;
        let inode = *dir.children.get(std::ffi::OsStr::new(name))?;
        state.nodes.get(&inode).cloned()
    }

    pub fn readdir(&self, parent: u64) -> Option<Vec<(String, Node)>> {
        let mut state = self.state.lock().unwrap();
        self.populate_if_lazy(&mut state, parent);
        let dir = state.dirs.get(&parent)?;
        let mut entries: Vec<(String, Node)> = dir
            .children
            .iter()
            .filter_map(|(name, inode)| {
                state
                    .nodes
                    .get(inode)
                    .cloned()
                    .map(|n| (name.to_string_lossy().into_owned(), n))
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Some(entries)
    }

    fn populate_if_lazy(&self, state: &mut VfsState, parent: u64) {
        let Some(ctx) = &self.lazy else { return };
        let needs_pop = state
            .dirs
            .get(&parent)
            .map(|d| d.lazy.is_some())
            .unwrap_or(false);
        if !needs_pop {
            return;
        }
        if let Err(e) = populate_dir_locked(state, parent, ctx) {
            // Surface as warn; callers see ENOENT for the lookup. We don't
            // want to keep retrying — clear the lazy flag so a broken tree
            // entry doesn't hammer the ODB on every FUSE call.
            tracing::warn!("populate_dir({parent}) failed: {e:#}");
            if let Some(d) = state.dirs.get_mut(&parent) {
                d.lazy = None;
            }
        }
    }
}

fn empty_state() -> VfsState {
    VfsState {
        nodes: HashMap::new(),
        dirs: HashMap::new(),
        next_inode: ROOT_INODE + 1,
    }
}

fn add_eager_root(state: &mut VfsState) {
    state.nodes.insert(
        ROOT_INODE,
        Node {
            inode: ROOT_INODE,
            kind: NodeKind::Dir,
        },
    );
    state.dirs.insert(
        ROOT_INODE,
        DirState {
            children: HashMap::new(),
            lazy: None,
        },
    );
}

fn alloc_inode(state: &mut VfsState) -> u64 {
    let i = state.next_inode;
    state.next_inode += 1;
    i
}

fn ensure_dir(state: &mut VfsState, parent: u64, name: &str) -> u64 {
    let key = OsString::from(name);
    if let Some(&existing) = state
        .dirs
        .get(&parent)
        .and_then(|d| d.children.get(&key))
        .filter(|inode| matches!(state.nodes.get(inode).map(|n| &n.kind), Some(NodeKind::Dir)))
    {
        return existing;
    }
    let inode = alloc_inode(state);
    state.nodes.insert(
        inode,
        Node {
            inode,
            kind: NodeKind::Dir,
        },
    );
    state.dirs.insert(
        inode,
        DirState {
            children: HashMap::new(),
            lazy: None,
        },
    );
    state
        .dirs
        .get_mut(&parent)
        .expect("parent dir exists")
        .children
        .insert(key, inode);
    inode
}

fn eager_insert(state: &mut VfsState, path: &str, oid: &str, label: Option<&str>) {
    let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
    let Some((file_component, dir_components)) = components.split_last() else {
        return;
    };

    let mut parent = ROOT_INODE;
    for dir in dir_components {
        parent = ensure_dir(state, parent, dir);
    }

    let final_name = match label {
        Some(l) => label_filename(file_component, l),
        None => (*file_component).to_string(),
    };
    let key = OsString::from(&final_name);
    // First write wins on collision — we never overwrite an existing entry
    // because that would silently lose data (e.g. two different OIDs at the
    // same labeled name).
    if let Some(dir) = state.dirs.get(&parent) {
        if dir.children.contains_key(&key) {
            return;
        }
    }
    let inode = alloc_inode(state);
    let source = Arc::new(BlobSource {
        oid: oid.to_string(),
    });
    // Size is unknown until we peek the blob; defer with a sentinel. The
    // reader's `peek_size` is what `getattr` ultimately calls.
    state.nodes.insert(
        inode,
        Node {
            inode,
            kind: NodeKind::File {
                size: u64::MAX,
                source,
            },
        },
    );
    state
        .dirs
        .get_mut(&parent)
        .expect("parent dir exists")
        .children
        .insert(key, inode);
}

enum PendingKind {
    Dir {
        tree_oid: gix::ObjectId,
        full_path: String,
    },
    File {
        oid_hex: String,
    },
}

struct PendingChild {
    name: String,
    kind: PendingKind,
}

fn populate_dir_locked(state: &mut VfsState, parent: u64, ctx: &LazyContext) -> anyhow::Result<()> {
    use anyhow::Context;

    let lazy_dir = match state.dirs.get(&parent).and_then(|d| d.lazy.clone()) {
        Some(l) => l,
        None => return Ok(()),
    };

    let repo = ctx.repo.to_thread_local();
    let tree = repo
        .find_object(lazy_dir.tree_oid)
        .with_context(|| format!("loading tree object {}", lazy_dir.tree_oid))?
        .into_tree();

    let mut pending: Vec<PendingChild> = Vec::new();
    for entry in tree.iter() {
        let entry = entry.context("decoding tree entry")?;
        let name = entry.filename().to_string();
        let full_path = if lazy_dir.path_prefix.is_empty() {
            name.clone()
        } else {
            format!("{}/{}", lazy_dir.path_prefix, name)
        };
        let mode = entry.mode();
        if mode.is_tree() {
            if !pathspec_intersects_dir(&full_path, &ctx.pathspec) {
                continue;
            }
            pending.push(PendingChild {
                name,
                kind: PendingKind::Dir {
                    tree_oid: entry.object_id(),
                    full_path,
                },
            });
        } else if mode.is_blob() {
            if !pathspec_matches_file(&full_path, &ctx.pathspec) {
                continue;
            }
            pending.push(PendingChild {
                name,
                kind: PendingKind::File {
                    oid_hex: entry.oid().to_string(),
                },
            });
        }
        // Symlinks and submodules are intentionally skipped — same scope
        // restriction the eager walker had (it only emitted is_blob entries).
    }

    for PendingChild { name, kind } in pending {
        let inode = alloc_inode(state);
        match kind {
            PendingKind::Dir {
                tree_oid,
                full_path,
            } => {
                state.nodes.insert(
                    inode,
                    Node {
                        inode,
                        kind: NodeKind::Dir,
                    },
                );
                state.dirs.insert(
                    inode,
                    DirState {
                        children: HashMap::new(),
                        lazy: Some(LazyDir {
                            tree_oid,
                            path_prefix: full_path,
                        }),
                    },
                );
            }
            PendingKind::File { oid_hex } => {
                state.nodes.insert(
                    inode,
                    Node {
                        inode,
                        kind: NodeKind::File {
                            size: u64::MAX,
                            source: Arc::new(BlobSource { oid: oid_hex }),
                        },
                    },
                );
            }
        }
        state
            .dirs
            .get_mut(&parent)
            .expect("parent dir exists")
            .children
            .insert(OsString::from(name), inode);
    }

    state.dirs.get_mut(&parent).expect("parent dir exists").lazy = None;
    Ok(())
}

/// File-leaf pathspec match. Same semantics as the eager walker's
/// `any_filter_matches`: literal prefix, no globbing. Empty filter list lets
/// everything through.
fn pathspec_matches_file(path: &str, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters.iter().any(|f| {
        let f = f.trim_end_matches('/');
        path == f || path.starts_with(&format!("{f}/"))
    })
}

/// Dir match: descend if the directory might *contain* or *be contained by*
/// a filter. Three legal shapes:
/// - filter equals the dir (we want the whole subtree),
/// - dir is under the filter (we're inside a matched area),
/// - filter is under the dir (must keep descending to reach the match).
fn pathspec_intersects_dir(path: &str, filters: &[String]) -> bool {
    if filters.is_empty() {
        return true;
    }
    filters.iter().any(|f| {
        let f = f.trim_end_matches('/');
        path == f || path.starts_with(&format!("{f}/")) || f.starts_with(&format!("{path}/"))
    })
}

/// `foo.tar.gz` + `main` -> `foo.tar__main.gz`. We split on the *last* dot so
/// multi-suffix names still look reasonable to diff tools.
fn label_filename(name: &str, label: &str) -> String {
    if let Some(dot) = name.rfind('.') {
        // Don't break dotfiles like `.gitignore`.
        if dot > 0 {
            let (stem, ext) = name.split_at(dot);
            return format!("{stem}__{label}{ext}");
        }
    }
    format!("{name}__{label}")
}
