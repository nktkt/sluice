# sluice

> Encrypted, deduplicating, incremental backup & disaster-recovery tool, written in Rust.

**Status: pre-alpha / design phase.** The architecture is fully specified in
[`DESIGN.md`](./DESIGN.md); implementation is just beginning (milestone **M0**,
the workspace skeleton). The on-disk format is **not yet frozen**.

`sluice` backs up a large number of *your own* files to an **untrusted** storage
backend — a local disk, a NAS, or any S3-compatible object store — as a
repository of immutable, content-addressed, encrypted objects. The backend only
ever sees ciphertext. It is in the same family as
[restic](https://restic.net), [BorgBackup](https://www.borgbackup.org),
[Kopia](https://kopia.io), and [Duplicacy](https://duplicacy.com).

## Goals

- **Scale** — millions of files / multi-TB repositories, with resident memory
  bounded to a tunable constant *independent of repository size*.
- **Incremental** — after the first run, only new or changed data is read and stored.
- **Deduplication** — content-defined chunking (FastCDC) stores identical data once.
- **Compression** — per-chunk `zstd` (skipped for incompressible data).
- **Encryption at rest** — you hold the keys; XChaCha20-Poly1305 by default.
- **Snapshots, restore & verify** — point-in-time snapshots, full and selective
  restore, and integrity verification.
- **Pluggable backends** — local filesystem and S3-compatible object storage for
  offsite disaster recovery.
- **Crash-consistent** — an interrupted backup never corrupts the repository
  (append-only; the snapshot is written last as the single commit point).

## Security model

`sluice` treats the storage backend as **untrusted**. Data is compressed and then
sealed with an AEAD; object and chunk identifiers use *keyed* BLAKE3 to resist
confirmation attacks. Cryptography **detects** tampering, rollback, and
corruption; durability and anti-ransomware (WORM object lock, erasure coding) are
layered on top to **prevent and repair**. See [`DESIGN.md` §9](./DESIGN.md).

## Architecture

A staged pipeline bridges a CPU pool (`rayon`) and an async I/O runtime
(`tokio`) with bounded channels for backpressure:

```
SCAN → READ + FastCDC + keyed-BLAKE3 + dedup-probe → COMPRESS + ENCRYPT → PACK → UPLOAD
```

The full design — repository format, data model, deduplication index,
concurrency model, CLI surface, and threat model — lives in
[`DESIGN.md`](./DESIGN.md).

### Workspace layout

| Crate | Responsibility |
|-------|----------------|
| `sluice-core`   | Pure types, IDs, errors, canonical CBOR format constants (no I/O) |
| `sluice-crypto` | Key hierarchy, AEAD, KDFs (Argon2id), single seal/open path |
| `sluice-chunk`  | FastCDC content-defined chunking + chunk IDs |
| `sluice-index`  | Dedup index: memtable + filters + redb cache + repo segments |
| `sluice-store`  | `StorageBackend` trait + local / object-store / S3-WORM backends |
| `sluice-scan`   | Parallel filesystem walk, ignore rules, incremental change detection |
| `sluice-engine` | Backup/restore/verify/prune orchestration & pipeline |
| `sluice-repo`   | Repository handle (init/open, save/load) |
| `sluice-cli`    | The `sluice` command-line binary |

## Roadmap

- **M0** — workspace skeleton, core types, `StorageBackend` trait *(current)*
- **M1** — MVP: local backup + restore (no encryption/dedup yet)
- **M2** — deduplication (FastCDC) + `zstd` compression + on-disk index
- **M3** — encryption: Argon2id key hierarchy, AEAD, keyed IDs, anti-rollback
- **M4** — object storage / offsite DR (S3, WORM, cold tier)
- **M5** — prune/GC + verify
- **M6** — performance, cross-platform, FUSE mount

## Building

Requires a recent stable Rust toolchain and a C compiler (used to build the
bundled `zstd`). TLS for object-storage backends uses `rustls`, so no OpenSSL or
other system libraries are required.

```sh
cargo build
cargo test
```

## Caveats

This is **pre-alpha software under active design**. The on-disk format will
change without migration until v0.1. **Do not use it for data you cannot afford
to lose.**

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or
[MIT license](./LICENSE-MIT) at your option.
