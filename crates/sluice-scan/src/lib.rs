//! `sluice-scan` — placeholder for a standalone filesystem-scanner crate.
//!
//! The filesystem discovery the design envisaged here — the parallel directory
//! walk, ignore/exclude rules, incremental change detection against the parent
//! snapshot or the stat cache, and bounded-memory tree assembly — is **already
//! implemented and shipped**, but inside `sluice-engine`'s backup walk rather than
//! this crate (see `DESIGN.md` §5.1). This crate is intentionally empty, reserving
//! the name should that scanner ever be extracted into a standalone module.
