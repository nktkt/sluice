//! `sluice-store` — the `StorageBackend` trait and its implementations (local
//! filesystem, S3-compatible object store, S3 WORM), plus the packer.
//!
//! The repository is treated as an untrusted, append-only, content-addressed
//! object store (see `DESIGN.md` §5.5). Pre-alpha skeleton (milestone M1; object
//! storage at M4).
