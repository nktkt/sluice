//! Canonical serialized objects making up the repository data model
//! (see `DESIGN.md` §3). Encoded as CBOR; equal values must encode to identical
//! bytes, because tree and snapshot IDs are the hash of these bytes.

use serde::{Deserialize, Serialize};

use crate::{EntryKind, Id};

/// Current on-disk version of a [`Tree`] object.
pub const TREE_VERSION: u8 = 1;

/// Current on-disk version of a [`Snapshot`] object.
pub const SNAPSHOT_VERSION: u8 = 1;

/// A directory tree object: a name-sorted list of entries (see `DESIGN.md` §3).
///
/// An unchanged directory serializes to identical bytes and therefore the same
/// tree ID, giving subtree deduplication across snapshots for free.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tree {
    /// Format version; see [`TREE_VERSION`].
    pub version: u8,
    /// Child entries, sorted by `name` for determinism.
    pub nodes: Vec<Node>,
}

/// A single filesystem entry within a [`Tree`].
///
/// `name` and `link_target` are raw bytes so non-UTF-8 names round-trip
/// faithfully. Extended attributes are added in a later milestone; the format
/// is not yet frozen.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    /// Entry name as raw `OsStr` bytes.
    pub name: Vec<u8>,
    /// The kind of filesystem entry.
    pub kind: EntryKind,
    /// Unix mode bits.
    pub mode: u32,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Modification time, nanoseconds since the Unix epoch.
    pub mtime_ns: i64,
    /// Change time, nanoseconds since the Unix epoch.
    pub ctime_ns: i64,
    /// Logical size in bytes.
    pub size: u64,
    /// File: the ordered content chunk IDs.
    pub content: Vec<Id>,
    /// Directory: the child tree object ID (a Merkle edge).
    pub subtree: Option<Id>,
    /// Symlink: the raw link-target bytes.
    pub link_target: Option<Vec<u8>>,
    /// Source device id, recorded only for hardlinked regular files (`nlink > 1`);
    /// `0` otherwise. With [`ino`](Self::ino) it identifies a hardlink group so
    /// restore can recreate the links instead of duplicating content.
    #[serde(default)]
    pub dev: u64,
    /// Source inode number, recorded only for hardlinked regular files
    /// (`nlink > 1`); `0` otherwise. See [`dev`](Self::dev).
    #[serde(default)]
    pub ino: u64,
    /// Extended attributes as raw `(name, value)` byte pairs, sorted by name.
    /// Captured without following symlinks; empty for entries with none.
    #[serde(default)]
    pub xattrs: Vec<(Vec<u8>, Vec<u8>)>,
    /// Represented device number for `CharDevice`/`BlockDevice` nodes (the
    /// `st_rdev` major/minor); `0` for every other kind. Restore feeds it to
    /// `mknod`. Appended last so older snapshots without it still decode.
    #[serde(default)]
    pub rdev: u64,
    /// Whether the source file had holes (fewer allocated blocks than its
    /// logical size). When set, restore recreates the holes instead of writing
    /// the zero regions, so a sparse file stays sparse. Appended last so older
    /// snapshots without it still decode.
    #[serde(default)]
    pub sparse: bool,
}

/// A point-in-time snapshot: the single commit object of a backup run
/// (see `DESIGN.md` §3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Snapshot {
    /// Format version; see [`SNAPSHOT_VERSION`].
    pub version: u8,
    /// Creation time, nanoseconds since the Unix epoch (UTC).
    pub time_ns: i64,
    /// Root tree object ID.
    pub tree: Id,
    /// The backup source paths, as raw bytes.
    pub paths: Vec<Vec<u8>>,
    /// Host the snapshot was taken on.
    pub hostname: String,
    /// User that took the snapshot.
    pub username: String,
    /// Owner user ID.
    pub uid: u32,
    /// Owner group ID.
    pub gid: u32,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Parent snapshot ID, if this run was incremental.
    pub parent: Option<Id>,
    /// The sluice version that wrote this snapshot.
    pub program_version: String,
    /// Summary counters for the run.
    pub summary: SnapshotStats,
}

/// Summary counters describing a backup run.
///
/// `#[serde(default)]` lets a snapshot written by a future sluice — which may
/// add more counters — still decode here, and lets an older snapshot decode in
/// a future build, with any absent counter reading as zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct SnapshotStats {
    /// Files seen for the first time.
    pub files_new: u64,
    /// Files whose content changed since the parent snapshot.
    pub files_changed: u64,
    /// Files unchanged since the parent snapshot.
    pub files_unmodified: u64,
    /// Directories processed.
    pub dirs: u64,
    /// Total logical bytes processed.
    pub bytes_processed: u64,
    /// Bytes actually stored after deduplication and compression.
    pub bytes_added: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_cbor, to_cbor};
    use proptest::prelude::*;

    fn sample_tree() -> Tree {
        Tree {
            version: TREE_VERSION,
            nodes: vec![
                Node {
                    name: b"file.txt".to_vec(),
                    kind: EntryKind::File,
                    mode: 0o644,
                    uid: 1000,
                    gid: 1000,
                    mtime_ns: 1_700_000_000_000_000_000,
                    ctime_ns: 1_700_000_000_000_000_000,
                    size: 12,
                    content: vec![Id::from_bytes([7u8; 32])],
                    subtree: None,
                    link_target: None,
                    dev: 0,
                    ino: 0,
                    xattrs: vec![(b"user.tag".to_vec(), b"v".to_vec())],
                    rdev: 0,
                    sparse: false,
                },
                Node {
                    name: b"subdir".to_vec(),
                    kind: EntryKind::Dir,
                    mode: 0o755,
                    uid: 1000,
                    gid: 1000,
                    mtime_ns: 0,
                    ctime_ns: 0,
                    size: 0,
                    content: vec![],
                    subtree: Some(Id::from_bytes([9u8; 32])),
                    link_target: None,
                    dev: 0,
                    ino: 0,
                    xattrs: Vec::new(),
                    rdev: 0,
                    sparse: false,
                },
            ],
        }
    }

    fn sample_snapshot() -> Snapshot {
        Snapshot {
            version: SNAPSHOT_VERSION,
            time_ns: 1_700_000_000_000_000_000,
            tree: Id::from_bytes([1u8; 32]),
            paths: vec![b"/home/user/docs".to_vec()],
            hostname: "host".into(),
            username: "user".into(),
            uid: 1000,
            gid: 1000,
            tags: vec!["daily".into()],
            parent: Some(Id::from_bytes([2u8; 32])),
            program_version: "0.0.0".into(),
            summary: SnapshotStats {
                files_new: 3,
                bytes_processed: 4096,
                ..Default::default()
            },
        }
    }

    #[test]
    fn tree_cbor_roundtrips() {
        let tree = sample_tree();
        let bytes = to_cbor(&tree).unwrap();
        let back: Tree = from_cbor(&bytes).unwrap();
        assert_eq!(tree, back);
    }

    #[test]
    fn equal_trees_encode_to_identical_bytes() {
        // Determinism is load-bearing: the tree ID is the hash of these bytes.
        assert_eq!(
            to_cbor(&sample_tree()).unwrap(),
            to_cbor(&sample_tree()).unwrap()
        );
    }

    #[test]
    fn snapshot_cbor_roundtrips() {
        let snap = sample_snapshot();
        let bytes = to_cbor(&snap).unwrap();
        let back: Snapshot = from_cbor(&bytes).unwrap();
        assert_eq!(snap, back);
    }

    // A `Node`/`Tree` exactly as a pre-hardlink, pre-xattr sluice would have
    // written it: no `dev`, `ino`, or `xattrs` fields. The current code must
    // still decode such objects (so existing repositories keep opening), with
    // the added fields falling back to their `#[serde(default)]` values. This
    // pins down the `serde(default)` + ciborium back-compat guarantee that three
    // format extensions have relied on.
    #[test]
    fn legacy_tree_without_new_node_fields_still_decodes() {
        #[derive(serde::Serialize)]
        struct OldNode {
            name: Vec<u8>,
            kind: EntryKind,
            mode: u32,
            uid: u32,
            gid: u32,
            mtime_ns: i64,
            ctime_ns: i64,
            size: u64,
            content: Vec<Id>,
            subtree: Option<Id>,
            link_target: Option<Vec<u8>>,
        }
        #[derive(serde::Serialize)]
        struct OldTree {
            version: u8,
            nodes: Vec<OldNode>,
        }

        let old = OldTree {
            version: TREE_VERSION,
            nodes: vec![
                OldNode {
                    name: b"legacy.txt".to_vec(),
                    kind: EntryKind::File,
                    mode: 0o644,
                    uid: 1000,
                    gid: 1000,
                    mtime_ns: 1_700_000_000_000_000_000,
                    ctime_ns: 0,
                    size: 7,
                    content: vec![Id::from_bytes([3u8; 32])],
                    subtree: None,
                    link_target: None,
                },
                OldNode {
                    name: b"old-link".to_vec(),
                    kind: EntryKind::Symlink,
                    mode: 0o777,
                    uid: 0,
                    gid: 0,
                    mtime_ns: 0,
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: None,
                    link_target: Some(b"legacy.txt".to_vec()),
                },
            ],
        };

        let bytes = to_cbor(&old).unwrap();
        let tree: Tree = from_cbor(&bytes).expect("legacy tree must still decode");

        assert_eq!(tree.version, TREE_VERSION);
        assert_eq!(tree.nodes.len(), 2);

        let file = &tree.nodes[0];
        assert_eq!(file.name, b"legacy.txt");
        assert_eq!(file.kind, EntryKind::File);
        assert_eq!(file.uid, 1000);
        assert_eq!(file.content, vec![Id::from_bytes([3u8; 32])]);
        // The new fields fall back to their defaults.
        assert_eq!(file.dev, 0);
        assert_eq!(file.ino, 0);
        assert!(file.xattrs.is_empty());
        assert_eq!(file.rdev, 0);
        assert!(!file.sparse);

        let link = &tree.nodes[1];
        assert_eq!(link.kind, EntryKind::Symlink);
        assert_eq!(link.link_target.as_deref(), Some(b"legacy.txt".as_slice()));
        assert!(link.xattrs.is_empty());
    }

    // A `SnapshotStats` from a build that tracked fewer counters must still
    // decode, with the absent counters reading as zero (guards the container
    // `#[serde(default)]`).
    #[test]
    fn stats_with_fewer_counters_still_decodes() {
        #[derive(serde::Serialize)]
        struct OldStats {
            files_new: u64,
            files_changed: u64,
            files_unmodified: u64,
            dirs: u64,
        }

        let bytes = to_cbor(&OldStats {
            files_new: 5,
            files_changed: 2,
            files_unmodified: 9,
            dirs: 3,
        })
        .unwrap();
        let stats: SnapshotStats = from_cbor(&bytes).expect("legacy stats must still decode");

        assert_eq!(stats.files_new, 5);
        assert_eq!(stats.dirs, 3);
        // Counters added later default to zero.
        assert_eq!(stats.bytes_processed, 0);
        assert_eq!(stats.bytes_added, 0);
    }

    fn arb_id() -> impl Strategy<Value = Id> {
        proptest::collection::vec(any::<u8>(), 32..=32)
            .prop_map(|v| Id::from_bytes(v.try_into().unwrap()))
    }

    fn arb_node() -> impl Strategy<Value = Node> {
        (
            proptest::collection::vec(any::<u8>(), 0..16),
            any::<u32>(),
            any::<u32>(),
            any::<u32>(),
            any::<i64>(),
            any::<i64>(),
            any::<u64>(),
            proptest::collection::vec(arb_id(), 0..4),
            any::<u64>(),
            any::<u64>(),
        )
            .prop_map(
                |(name, mode, uid, gid, mtime, ctime, size, content, dev, ino)| Node {
                    name,
                    kind: EntryKind::File,
                    mode,
                    uid,
                    gid,
                    mtime_ns: mtime,
                    ctime_ns: ctime,
                    size,
                    content,
                    subtree: None,
                    link_target: None,
                    dev,
                    ino,
                    xattrs: Vec::new(),
                    rdev: 0,
                    sparse: false,
                },
            )
    }

    proptest! {
        #[test]
        fn tree_cbor_roundtrips_and_is_deterministic(
            nodes in proptest::collection::vec(arb_node(), 0..8)
        ) {
            let tree = Tree { version: TREE_VERSION, nodes };
            let bytes = to_cbor(&tree).unwrap();
            // Roundtrip.
            prop_assert_eq!(from_cbor::<Tree>(&bytes).unwrap(), tree.clone());
            // Deterministic: tree IDs are the hash of these bytes.
            prop_assert_eq!(to_cbor(&tree).unwrap(), bytes);
        }
    }
}
