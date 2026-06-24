# sluice

> Encrypted, deduplicating, incremental backup & disaster-recovery tool, written in Rust.

**Status: early, but working.** `sluice` already creates encrypted repositories
and performs deduplicated, compressed, **incremental** backups and restores of
local directories, with integrity verification — backed by 83 tests across the
workspace. The full architecture is specified in [`DESIGN.md`](./DESIGN.md).
**The on-disk format is not yet frozen; do not use it for data you cannot afford
to lose.**

`sluice` backs up a large number of *your own* files to an **untrusted** storage
backend — a local disk, a NAS, or (planned) any S3-compatible object store — as a
repository of immutable, content-addressed, encrypted objects. The backend only
ever sees ciphertext. It is in the same family as
[restic](https://restic.net), [BorgBackup](https://www.borgbackup.org),
[Kopia](https://kopia.io), and [Duplicacy](https://duplicacy.com).

## Usage

The passphrase is read from the `SLUICE_PASSWORD` environment variable.

```sh
export SLUICE_PASSWORD='correct horse battery staple'

sluice init      ./repo                   # create an encrypted repository
sluice backup    ./repo ~/documents       # snapshot a directory (prints a snapshot id)
sluice snapshots ./repo                    # list snapshot ids
sluice verify    ./repo                    # read & authenticate every stored object
sluice restore   ./repo <snapshot> ./out   # restore (a unique id prefix is accepted)
```

Backups are **incremental**: a file whose size and mtime are unchanged reuses its
stored chunks without being re-read. The Argon2id work factor can be tuned with
`SLUICE_KDF_MEMORY_KIB` and `SLUICE_KDF_PASSES`.

## Goals

- **Scale** — millions of files / multi-TB repositories, with resident memory
  bounded to a tunable constant *independent of repository size*.
- **Incremental** — after the first run, only new or changed data is read and stored.
- **Deduplication** — content-defined chunking (FastCDC) stores identical data once.
- **Compression** — per-chunk `zstd` (skipped for incompressible data).
- **Encryption at rest** — you hold the keys; XChaCha20-Poly1305 by default.
- **Snapshots, restore & verify** — point-in-time snapshots, full restore, and
  read-data integrity verification.
- **Pluggable backends** — local filesystem today; S3-compatible object storage
  for offsite disaster recovery is planned.
- **Crash-consistent** — an interrupted backup never corrupts the repository
  (append-only; the snapshot is written last as the single commit point).

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
| `sluice-store`  | `StorageBackend` trait, local + in-memory backends, pack codec |
| `sluice-scan`   | Filesystem walk *(in-progress; the engine currently walks directly)* |
| `sluice-engine` | Backup / restore / verify orchestration |
| `sluice-repo`   | Repository handle: init/open, blobs, files, trees, snapshots |
| `sluice-cli`    | The `sluice` command-line binary |

## Roadmap

- **M0** — workspace skeleton, core types, `StorageBackend` trait — ✅
- **M1** — local backup + restore — ✅
- **M2** — deduplication (FastCDC) + zstd compression — ✅ *(persistent on-disk
  index is a follow-up; the index is currently rebuilt from pack footers on open)*
- **M3** — encryption: Argon2id key hierarchy, XChaCha20-Poly1305, keyed BLAKE3 — ✅
  *(anti-rollback head and key-derived chunk gear still pending)*
- **verify** (read-data integrity) and **incremental** backups — ✅
- **M4** — object storage / offsite DR (S3, WORM, cold tier) — planned
- **M5** — prune / GC + retention policy — planned (`verify` done)
- **M6** — performance, cross-platform, FUSE mount, metadata replay — planned

## Building

Requires a recent stable Rust toolchain and a C compiler (used to build the
bundled `zstd`). TLS for future object-storage backends uses `rustls`, so no
OpenSSL or other system libraries are required.

```sh
cargo build
cargo test     # 83 tests
```

## Caveats

This is **pre-alpha software under active development**. The on-disk format will
change without migration until v0.1. **Do not use it for data you cannot afford
to lose.**

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or
[MIT license](./LICENSE-MIT) at your option.
