//! `sluice-core` — pure types, identifiers, errors, and canonical CBOR format
//! constants shared across the workspace.
//!
//! This crate has **no I/O or UI dependencies**; it defines the seam that keeps
//! the engine and CLI separable (see `DESIGN.md` §4).
#![forbid(unsafe_code)]

mod id;

pub use id::{Id, IdParseError};

/// The kind of object carried by a stored blob (see `DESIGN.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlobKind {
    /// A chunk of file content.
    Data,
    /// A serialized directory-tree object.
    Tree,
}

/// The kind of filesystem entry recorded by a tree node (see `DESIGN.md` §3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
