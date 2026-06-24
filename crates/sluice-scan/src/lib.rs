//! `sluice-scan` — parallel filesystem discovery, ignore rules, incremental
//! change detection, and bounded-memory tree assembly.
//!
//! Unchanged files are detected from a local stat-cache and bypass the CPU
//! pipeline entirely (see `DESIGN.md` §5.1). Pre-alpha skeleton (milestone M1).
