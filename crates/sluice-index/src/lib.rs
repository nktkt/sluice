//! `sluice-index` — placeholder for a standalone deduplication-index crate.
//!
//! The deduplication index the design envisaged here — an in-memory map of chunk
//! id → pack location, rebuilt from pack footers on open, plus the on-disk stat
//! cache — is **already implemented and shipped**, but inside other crates rather
//! than this one: the index map and `rebuild_index` live in [`sluice-repo`]'s
//! `Repository`, and the redb-backed stat cache lives in `sluice-engine` (see
//! `DESIGN.md` §5.2 and §5.6). This crate is intentionally empty, reserving the
//! name should that index ever be extracted into a standalone module.
//!
//! [`sluice-repo`]: https://docs.rs/sluice-repo
