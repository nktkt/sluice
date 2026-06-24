//! `sluice-engine` — backup, restore, verify, and prune orchestration over the
//! staged `rayon` (CPU) / `tokio` (I/O) pipeline.
//!
//! Bounded channels provide backpressure so peak memory is a tunable constant;
//! the snapshot is written last for crash consistency (see `DESIGN.md` §6 and
//! §8). UI-agnostic: progress is emitted as events. Pre-alpha skeleton.
