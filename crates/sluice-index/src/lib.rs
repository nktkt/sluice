//! `sluice-index` — the deduplication index: an in-memory memtable and
//! membership filters, a local `redb` cache, and immutable on-repo index
//! segments.
//!
//! Designed so resident memory stays bounded independent of repository size
//! (see `DESIGN.md` §5.2 and §5.6). Pre-alpha skeleton (milestone M2).
