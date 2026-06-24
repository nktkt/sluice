//! `sluice-core` — pure types, identifiers, errors, and canonical CBOR format
//! constants shared across the workspace.
//!
//! This crate has **no I/O or UI dependencies**; it defines the seam that keeps
//! the engine and CLI separable (see `DESIGN.md` §4).
#![forbid(unsafe_code)]

mod config;
mod error;
mod format;
mod id;

pub use config::{CONFIG_VERSION, ChunkerConfig, CipherSuite, REPO_MAGIC, RepoConfig};
pub use error::{Error, Result};
pub use format::{Node, SNAPSHOT_VERSION, Snapshot, SnapshotStats, TREE_VERSION, Tree};
pub use id::{Id, IdParseError};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Serialize `value` to canonical CBOR bytes.
///
/// Encoding uses fixed struct-field order and definite lengths, so equal values
/// encode to identical bytes — the property that makes tree and snapshot IDs
/// stable (see `DESIGN.md` §3).
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    ciborium::into_writer(value, &mut buf).map_err(|e| Error::Encode(e.to_string()))?;
    Ok(buf)
}

/// Deserialize CBOR `bytes` into a value of type `T`.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    ciborium::from_reader(bytes).map_err(|e| Error::Decode(e.to_string()))
}

/// The kind of object carried by a stored blob (see `DESIGN.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum BlobKind {
    /// A chunk of file content.
    Data,
    /// A serialized directory-tree object.
    Tree,
}

/// The kind of filesystem entry recorded by a tree node (see `DESIGN.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum EntryKind {
    /// A regular file.
    File,
    /// A directory.
    Dir,
    /// A symbolic link.
    Symlink,
    /// A named pipe (FIFO).
    Fifo,
    /// A unix-domain socket.
    Socket,
    /// A character device.
    CharDevice,
    /// A block device.
    BlockDevice,
}
