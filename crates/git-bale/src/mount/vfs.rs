//! In-memory virtual filesystem assembled from the diff result.
//!
//! Each leaf is a file at the original repo path, but with the rev label
//! folded into the basename: `parent/foo.txt` on side A becomes
//! `parent/foo__<labelA>.txt`. Directories are deduplicated across both
//! sides. Inode IDs are assigned at build time and are stable for the life
//! of the mount.

use std::collections::HashMap;
use std::ffi::OsString;
use std::sync::Arc;

use crate::mount::diff::DiffEntry;
use crate::mount::reader::{BlobSource, Reader};
use crate::mount::tree::TreeEntry;

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
}

pub struct DiffVfs {
    nodes: HashMap<u64, Node>,
    dirs: HashMap<u64, DirState>,
    reader: Arc<Reader>,
}

impl DiffVfs {
    /// Two-sided diff view: each side's path is labelled (`foo__main.rs` vs
    /// `foo__feature.rs`) so a single mount point can show both versions
    /// without overwriting each other.
    pub fn build(entries: &[DiffEntry], label_a: &str, label_b: &str, reader: Arc<Reader>) -> Self {
        let mut builder = Builder::new();
        builder.add_root();
        for entry in entries {
            if let (Some(path), Some(oid)) = (&entry.path_a, &entry.oid_a) {
                builder.insert(path, oid, Some(label_a));
            }
            if let (Some(path), Some(oid)) = (&entry.path_b, &entry.oid_b) {
                builder.insert(path, oid, Some(label_b));
            }
        }
        DiffVfs {
            nodes: builder.nodes,
            dirs: builder.dirs,
            reader,
        }
    }

    /// Single-rev view: every file keeps its original name. Used by
    /// `git-bale mount <rev>`.
    pub fn build_single(entries: &[TreeEntry], reader: Arc<Reader>) -> Self {
        let mut builder = Builder::new();
        builder.add_root();
        for entry in entries {
            builder.insert(&entry.path, &entry.oid, None);
        }
        DiffVfs {
            nodes: builder.nodes,
            dirs: builder.dirs,
            reader,
        }
    }

    pub fn reader(&self) -> &Arc<Reader> {
        &self.reader
    }

    pub fn lookup_by_inode(&self, inode: u64) -> Option<&Node> {
        self.nodes.get(&inode)
    }

    pub fn lookup_child(&self, parent: u64, name: &str) -> Option<&Node> {
        let dir = self.dirs.get(&parent)?;
        let inode = dir.children.get(std::ffi::OsStr::new(name))?;
        self.nodes.get(inode)
    }

    pub fn readdir(&self, parent: u64) -> Option<Vec<(String, Node)>> {
        let dir = self.dirs.get(&parent)?;
        let mut entries: Vec<(String, Node)> = dir
            .children
            .iter()
            .filter_map(|(name, inode)| {
                self.nodes
                    .get(inode)
                    .cloned()
                    .map(|n| (name.to_string_lossy().into_owned(), n))
            })
            .collect();
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        Some(entries)
    }
}

struct Builder {
    nodes: HashMap<u64, Node>,
    dirs: HashMap<u64, DirState>,
    next_inode: u64,
}

impl Builder {
    fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            dirs: HashMap::new(),
            next_inode: ROOT_INODE + 1,
        }
    }

    fn add_root(&mut self) {
        self.nodes.insert(
            ROOT_INODE,
            Node {
                inode: ROOT_INODE,
                kind: NodeKind::Dir,
            },
        );
        self.dirs.insert(
            ROOT_INODE,
            DirState {
                children: HashMap::new(),
            },
        );
    }

    fn alloc_inode(&mut self) -> u64 {
        let i = self.next_inode;
        self.next_inode += 1;
        i
    }

    fn ensure_dir(&mut self, parent: u64, name: &str) -> u64 {
        let key = OsString::from(name);
        if let Some(&existing) = self
            .dirs
            .get(&parent)
            .and_then(|d| d.children.get(&key))
            .filter(|inode| matches!(self.nodes.get(inode).map(|n| &n.kind), Some(NodeKind::Dir)))
        {
            return existing;
        }
        let inode = self.alloc_inode();
        self.nodes.insert(
            inode,
            Node {
                inode,
                kind: NodeKind::Dir,
            },
        );
        self.dirs.insert(
            inode,
            DirState {
                children: HashMap::new(),
            },
        );
        self.dirs
            .get_mut(&parent)
            .expect("parent dir exists")
            .children
            .insert(key, inode);
        inode
    }

    fn insert(&mut self, path: &str, oid: &str, label: Option<&str>) {
        let components: Vec<&str> = path.split('/').filter(|c| !c.is_empty()).collect();
        let Some((file_component, dir_components)) = components.split_last() else {
            return;
        };

        let mut parent = ROOT_INODE;
        for dir in dir_components {
            parent = self.ensure_dir(parent, dir);
        }

        let final_name = match label {
            Some(l) => label_filename(file_component, l),
            None => (*file_component).to_string(),
        };
        let key = OsString::from(&final_name);
        // First write wins on collision — we never overwrite an existing entry
        // because that would silently lose data (e.g. two different OIDs at
        // the same labeled name).
        if let Some(dir) = self.dirs.get(&parent) {
            if dir.children.contains_key(&key) {
                return;
            }
        }
        let inode = self.alloc_inode();
        let source = Arc::new(BlobSource {
            oid: oid.to_string(),
        });
        // Size is unknown until we peek the blob; defer with a sentinel. The
        // reader's `peek_size` is what `getattr` ultimately calls.
        self.nodes.insert(
            inode,
            Node {
                inode,
                kind: NodeKind::File {
                    size: u64::MAX,
                    source,
                },
            },
        );
        self.dirs
            .get_mut(&parent)
            .expect("parent dir exists")
            .children
            .insert(key, inode);
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mount::diff::{DiffEntry, DiffStatus};
    use crate::mount::reader::Reader;
    use std::path::PathBuf;

    fn dummy_reader() -> Arc<Reader> {
        // Construction must not fail when no real git context is available;
        // tests that only exercise the VFS shape never call .read().
        Arc::new(Reader::for_test_only(PathBuf::from("/tmp")))
    }

    #[test]
    fn labels_into_basename_keeping_extension() {
        assert_eq!(label_filename("foo.txt", "main"), "foo__main.txt");
        assert_eq!(label_filename("README", "dev"), "README__dev");
        assert_eq!(label_filename("a.tar.gz", "x"), "a.tar__x.gz");
        // Dotfile: leading dot must not be treated as the extension separator.
        assert_eq!(label_filename(".gitignore", "x"), ".gitignore__x");
    }

    #[test]
    fn build_creates_dirs_for_modified_file() {
        let entries = vec![DiffEntry {
            path_a: Some("src/foo.rs".into()),
            path_b: Some("src/foo.rs".into()),
            oid_a: Some("a".repeat(40)),
            oid_b: Some("b".repeat(40)),
            status: DiffStatus::Modified,
        }];
        let vfs = DiffVfs::build(&entries, "A", "B", dummy_reader());
        let src = vfs.lookup_child(ROOT_INODE, "src").unwrap();
        let foo_a = vfs.lookup_child(src.inode, "foo__A.rs");
        let foo_b = vfs.lookup_child(src.inode, "foo__B.rs");
        assert!(foo_a.is_some());
        assert!(foo_b.is_some());
        assert!(matches!(foo_a.unwrap().kind, NodeKind::File { .. }));
    }

    #[test]
    fn added_file_only_appears_on_side_b() {
        let entries = vec![DiffEntry {
            path_a: None,
            path_b: Some("new.txt".into()),
            oid_a: None,
            oid_b: Some("c".repeat(40)),
            status: DiffStatus::Added,
        }];
        let vfs = DiffVfs::build(&entries, "A", "B", dummy_reader());
        assert!(vfs.lookup_child(ROOT_INODE, "new__A.txt").is_none());
        assert!(vfs.lookup_child(ROOT_INODE, "new__B.txt").is_some());
    }

    #[test]
    fn deleted_file_only_appears_on_side_a() {
        let entries = vec![DiffEntry {
            path_a: Some("gone.txt".into()),
            path_b: None,
            oid_a: Some("d".repeat(40)),
            oid_b: None,
            status: DiffStatus::Deleted,
        }];
        let vfs = DiffVfs::build(&entries, "A", "B", dummy_reader());
        assert!(vfs.lookup_child(ROOT_INODE, "gone__A.txt").is_some());
        assert!(vfs.lookup_child(ROOT_INODE, "gone__B.txt").is_none());
    }

    #[test]
    fn renamed_file_keeps_each_label_at_its_own_path() {
        let entries = vec![DiffEntry {
            path_a: Some("old/name.rs".into()),
            path_b: Some("new/name.rs".into()),
            oid_a: Some("a".repeat(40)),
            oid_b: Some("b".repeat(40)),
            status: DiffStatus::Renamed,
        }];
        let vfs = DiffVfs::build(&entries, "A", "B", dummy_reader());
        let old = vfs.lookup_child(ROOT_INODE, "old").unwrap();
        let new = vfs.lookup_child(ROOT_INODE, "new").unwrap();
        assert!(vfs.lookup_child(old.inode, "name__A.rs").is_some());
        assert!(vfs.lookup_child(new.inode, "name__B.rs").is_some());
    }
}
