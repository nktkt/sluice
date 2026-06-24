//! Canonical serialized objects making up the repository data model
//! (see `DESIGN.md` §3). Encoded as CBOR; equal values must encode to identical
//! bytes, because tree and snapshot IDs are the hash of these bytes.

use serde::{Deserialize, Serialize};

use crate::{EntryKind, Id};

/// Current on-disk version of a [`Tree`] object.
pub const TREE_VERSION: u8 = 1;

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
/// faithfully. Extended attributes, hardlink, and device fields are added in a
/// later milestone; the format is not yet frozen.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{from_cbor, to_cbor};

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
                },
            ],
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
}
