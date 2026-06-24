//! `sluice-core` — pure types, identifiers, errors, and canonical CBOR format
//! constants shared across the workspace.
//!
//! This crate has **no I/O or UI dependencies**; it defines the seam that keeps
//! the engine and CLI separable (see `DESIGN.md` §4). Implementation begins at
//! milestone M0.
#![forbid(unsafe_code)]
