# sluice

> Encrypted, deduplicating, incremental backup & disaster-recovery tool, written in Rust.

**Status: alpha.** `sluice` creates encrypted repositories and performs
deduplicated, compressed, **incremental** backups and restores — of files,
directories, and symlinks, with mode and mtime preserved — to a local path **or
any S3-compatible object store**, with integrity verification, snapshot diffs,
retention, and pruning. Backed by 98 tests across the workspace. The full
architecture is in [`DESIGN.md`](./DESIGN.md). **The on-disk format is not yet
frozen; do not use it for data you cannot afford to lose.**

`sluice` backs up a large number of *your own* files to an **untrusted** storage
backend — a local disk, a NAS, or any S3-compatible object store (S3, GCS,
Azure, MinIO, ...) — as a repository of immutable, content-addressed, encrypted
objects. The backend only ever sees ciphertext. It is in the same family as
[restic](https://restic.net), [BorgBackup](https://www.borgbackup.org),
[Kopia](https://kopia.io), and [Duplicacy](https://duplicacy.com).

## Usage

The passphrase comes from the `SLUICE_PASSWORD` environment variable, or an
interactive no-echo prompt. A repository is a local path or an object-store URL.

```sh
export SLUICE_PASSWORD='correct horse battery staple'

# Local repository
sluice init      ./repo
sluice backup    ./repo ~/documents --exclude '*.log' --exclude node_modules
sluice snapshots ./repo                    # <id>  <time>  <N files>  <paths>
sluice ls        ./repo <snapshot>         # list a snapshot's entries
sluice diff      ./repo <snap-a> <snap-b>  # +/-/M changes between snapshots
sluice verify    ./repo                    # read & authenticate every object
sluice restore   ./repo <snapshot> ./out   # a unique id prefix is accepted
sluice forget    ./repo --keep-last 7      # retention (or: forget ./repo <snapshot>)
sluice prune     ./repo                    # reclaim unreferenced storage

# Offsite: any object-store URL (s3://, gs://, az://, file://, ...)
sluice init   s3://my-bucket/backups
sluice backup s3://my-bucket/backups ~/documents
```

Backups are **incremental**: a file whose size and mtime are unchanged reuses its
stored chunks without being re-read. The Argon2id work factor is tunable with
`SLUICE_KDF_MEMORY_KIB` and `SLUICE_KDF_PASSES`.

## Goals

- **Scale** — millions of files / multi-TB repositories, with resident memory
  bounded to a tunable constant *independent of repository size*.
- **Incremental** — after the first run, only new or changed data is read and stored.
- **Deduplication** — content-defined chunking (FastCDC) stores identical data once.
- **Compression** — per-chunk `zstd` (skipped for incompressible data).
- **Encryption at rest** — you hold the keys; XChaCha20-Poly1305 and Argon2id.
- **Snapshots, restore, verify, diff** — point-in-time snapshots, full restore,
  read-data integrity verification, and snapshot diffs.
- **Retention** — keep-last-N `forget` plus mark-and-sweep `prune`.
- **Pluggable backends** — local filesystem and S3-compatible object storage.
- **Crash-consistent** — append-only; the snapshot is written last as the single
  commit point.

## Security model

`sluice` treats the storage backend as **untrusted**. Data is compressed and then
sealed with an AEAD (XChaCha20-Poly1305); object and chunk identifiers use *keyed*
BLAKE3 to resist confirmation attacks. The master key is derived from your
passphrase with Argon2id and wraps a random repository key. Because every blob is
authenticated, a single flipped byte in a stored pack is caught by `verify` as an
authentication failure. See [`DESIGN.md` §9](./DESIGN.md).

## Architecture

A blob write path bridges chunking, compression, and encryption:

```
SCAN → READ + FastCDC + keyed-BLAKE3 + dedup-probe → COMPRESS (zstd) → ENCRYPT (AEAD) → PACK → STORE
```

The full design — repository format, data model, deduplication index,
concurrency model, CLI surface, and threat model — lives in
[`DESIGN.md`](./DESIGN.md).

### Workspace layout

| Crate | Responsibility |
|-------|----------------|
| `sluice-core`   | Pure types, IDs, errors, canonical CBOR format constants (no I/O) |
| `sluice-crypto` | Key hierarchy, AEAD, KDFs (Argon2id), hashing, compression, RNG |
| `sluice-chunk`  | FastCDC content-defined chunking + chunk IDs |
| `sluice-index`  | Dedup index *(in-progress; today the index is rebuilt from pack footers)* |
| `sluice-store`  | `StorageBackend` trait; in-memory, local, and object-store backends; pack codec |
| `sluice-scan`   | Filesystem walk *(in-progress; the engine currently walks directly)* |
| `sluice-engine` | Backup / restore / verify / diff / forget / prune orchestration |
| `sluice-repo`   | Repository handle: init/open, blobs, files, trees, snapshots |
| `sluice-cli`    | The `sluice` command-line binary |

## Roadmap

- **M0** — workspace skeleton, core types, `StorageBackend` trait — ✅
- **M1** — local backup + restore — ✅
- **M2** — deduplication (FastCDC) + zstd compression — ✅ *(persistent on-disk
  index is a follow-up; the index is currently rebuilt from pack footers on open)*
- **M3** — encryption: Argon2id key hierarchy, XChaCha20-Poly1305, keyed BLAKE3 — ✅
  *(anti-rollback head and key-derived chunk gear still pending)*
- **M4** — object storage / offsite DR (S3, GCS, Azure, MinIO) — ✅
- **M5** — verify, retention (`forget --keep-last`), and `prune` — ✅
  *(richer retention policies still to come)*
- extras shipped: incremental backups, symlinks, mode/mtime, exclude globs,
  `ls`, `diff`
- **M6** — parallel pipeline, special files, FUSE mount, cross-platform polish — planned

## Building

Requires a recent stable Rust toolchain and a C compiler (used to build the
bundled `zstd`). TLS for object-storage backends uses `rustls`, so no OpenSSL or
other system libraries are required.

```sh
cargo build
cargo test     # 98 tests
```

## Caveats

This is **alpha software under active development**. The on-disk format will
change without migration until v0.1. **Do not use it for data you cannot afford
to lose.**

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or
[MIT license](./LICENSE-MIT) at your option.
