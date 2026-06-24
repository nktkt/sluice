# sluice

> Encrypted, deduplicating, incremental backup & disaster-recovery tool, written in Rust.

**Status: alpha.** `sluice` creates encrypted repositories and performs
deduplicated, compressed, **incremental** backups and restores — of files,
directories, and symlinks, with mode and mtime preserved — to a local path **or
any S3-compatible object store**. It offers point-in-time snapshots (of one or
many source directories), full and partial restore, two tiers of integrity
checking, restic-style retention with space-reclaiming prune, tag editing and
cross-snapshot search, cross-repository copy (re-encrypting under the target's
keys), advisory locking for safe concurrent use, multiple passphrases, a
persisted index for fast repository open, machine-readable JSON output, and
stable exit codes. Backed by 153 tests across the workspace. The full
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
```

### Create and back up

```sh
sluice init   ./repo
sluice backup ./repo ~/documents --exclude '*.log' --exclude node_modules --tag daily
sluice backup ./repo ~/documents --exclude-from .sluiceignore   # exclude globs from a file
sluice backup ./repo ~/documents ~/photos        # several sources -> one snapshot
sluice backup ./repo ~/documents --dry-run       # preview, writing nothing
```

Backups are **incremental**: a file whose size and mtime are unchanged reuses its
stored chunks without being re-read. `--exclude` (glob, by entry name) and `--tag`
are repeatable, and `--exclude-from` reads exclude globs from a file (one per
line; `#` comments and blank lines ignored). Multiple source directories go into
a single snapshot under a synthetic root named by each source's final path
component. The Argon2id work factor is tunable with `SLUICE_KDF_MEMORY_KIB` and
`SLUICE_KDF_PASSES`.

### Inspect and restore

```sh
sluice snapshots ./repo [--tag daily]          # <id> <time> <N files> <paths>
sluice ls        ./repo <snapshot>             # list a snapshot's entries
sluice find      ./repo '**/*.pdf'             # locate a glob across all snapshots
sluice diff      ./repo <snap-a> <snap-b>      # +/-/M changes between snapshots
sluice dump      ./repo <snapshot> path/to/f   # one file's contents to stdout
sluice tag       ./repo <snapshot> --add keep --remove daily   # edit a snapshot's tags
sluice info      ./repo                         # repository metadata
sluice stats     ./repo                         # logical vs stored bytes, dedup %
sluice cat       ./repo snapshot <id>           # decrypted object as JSON (config|snapshot|tree)
sluice restore   ./repo <snapshot> ./out        # full restore (unique id prefix ok)
sluice restore   ./repo <snapshot> ./out --path sub/dir   # restore a subtree only
```

The listing and result commands (`snapshots`, `stats`, `ls`, `find`, `diff`,
`prune`, `forget`) accept `--json` for machine-readable output, and commands
return stable exit codes (10 repo not found, 11 wrong passphrase, 12 lock held,
13 corruption) for scripting.

### Integrity

```sh
sluice check  ./repo   # fast: authenticate trees, confirm referenced blobs exist
sluice verify ./repo   # thorough: read & authenticate every blob (read-data check)
```

`check` decrypts only the tree objects and confirms each referenced blob is
present via the index, without reading file data — much cheaper than `verify`,
which authenticates all stored data. Both exit non-zero on any integrity failure.

### Retention and pruning

```sh
# Keep rules combine as a union (restic semantics); a snapshot kept by any rule survives.
sluice forget ./repo --keep-last 7 --keep-daily 14 --keep-weekly 8 \
                     --keep-monthly 12 --keep-yearly 5
sluice forget ./repo --keep-last 7 --keep-tag important   # protect tagged snapshots
sluice forget ./repo --keep-daily 30 --keep-within 7d      # also keep everything from the last week
sluice forget ./repo --keep-last 7 --group-by host         # apply the rules per host
sluice forget ./repo --tag daily          # or forget by tag
sluice forget ./repo <snapshot>           # or a single snapshot
sluice forget ./repo --keep-last 7 --dry-run   # preview without removing
sluice forget ./repo --keep-last 7 --prune     # forget, then reclaim in one step

sluice prune ./repo                  # mark-and-sweep GC: drop dead packs, repack partial ones
sluice prune ./repo --max-unused 5   # leave packs that are <=5% dead instead of repacking
sluice prune ./repo --dry-run        # report reclaimable bytes without touching storage
```

`forget` only removes snapshots; `prune` reclaims the now-unreferenced storage,
deleting fully-dead packs and repacking partially-dead ones to recover space.

### Keys (passphrases)

A repository can have several passphrases, each unwrapping the same master key.

```sh
sluice key list   ./repo                  # list key ids
sluice key add    ./repo                  # add a passphrase (SLUICE_NEW_PASSWORD or prompt)
sluice key passwd ./repo                  # rotate the current passphrase
sluice key remove ./repo <key-id>         # remove a key (the last one is refused)
```

### Maintenance

```sh
sluice unlock        ./repo   # clear advisory locks left by an interrupted run
sluice rebuild-index ./repo   # rescan packs to repair a damaged/stale index
```

### Replicate to another repository

`copy` re-encrypts a snapshot under the destination's keys, so the two
repositories can use different passphrases — useful for migrating or replicating
to an offsite repo, or rotating keys by re-encryption.

```sh
sluice copy ./repo s3://my-bucket/backups <snapshot>   # one snapshot
sluice copy ./repo s3://my-bucket/backups               # every snapshot (idempotent)
```

The destination passphrase comes from `SLUICE_DEST_PASSWORD` (defaulting to the
source's). Re-running copies only what is missing.

### Offsite: object storage

Any object-store URL works in place of a local path:

```sh
sluice init   s3://my-bucket/backups
sluice backup s3://my-bucket/backups ~/documents
# gs://…, az://…, file://… are also supported
```

## Concurrency and safety

Operations coordinate through **advisory locks**: a backup takes a shared lock and
a prune takes an exclusive one, so a prune will not delete data while a backup is
running, while two backups can still run together. A crashed run can leave a stale
lock behind; clear it with `sluice unlock`. Writes are crash-consistent: objects
are immutable and append-only, and the snapshot — written last — is the single
commit point, so an interrupted backup never corrupts the repository.

## Security model

`sluice` treats the storage backend as **untrusted**. Data is compressed and then
sealed with an AEAD (XChaCha20-Poly1305); object and chunk identifiers use *keyed*
BLAKE3 to resist confirmation attacks. The master key is random; it is wrapped
with a key-encryption key derived from your passphrase via Argon2id, and several
passphrases can wrap it independently (`key add`/`passwd`/`remove`). Because every
blob is authenticated, a single flipped byte in a stored pack is caught by `verify`
(or `check`, for the metadata it reads) as an authentication failure. See
[`DESIGN.md` §9](./DESIGN.md).

## Goals

- **Scale** — millions of files / multi-TB repositories, with resident memory
  bounded to a tunable constant *independent of repository size*.
- **Incremental** — after the first run, only new or changed data is read and stored.
- **Deduplication** — content-defined chunking (FastCDC) stores identical data once.
- **Compression** — per-chunk `zstd` (skipped for incompressible data).
- **Encryption at rest** — you hold the keys; XChaCha20-Poly1305 and Argon2id,
  with multiple passphrases and rotation.
- **Snapshots, restore, verify, diff** — point-in-time snapshots of one or many
  source directories, full or partial restore, fast structural `check` and
  thorough read-data `verify`, snapshot diffs, cross-snapshot `find`, and `tag`
  editing.
- **Retention** — restic-style keep-last/daily/weekly/monthly/yearly plus
  keep-tag and keep-within `forget`, optionally grouped by host or paths (with
  `--dry-run` and `--prune`), plus mark-and-sweep `prune` with repacking and a
  `--max-unused` tolerance.
- **Replication** — `copy` a snapshot (or all) to another repository,
  re-encrypting under its keys, even across different passphrases.
- **Fast open** — a persisted per-pack index avoids rescanning storage on open;
  `rebuild-index` repairs it.
- **Scriptable** — machine-readable `--json` output and stable exit codes.
- **Pluggable backends** — local filesystem and S3-compatible object storage.
- **Crash-consistent** — append-only; the snapshot is written last as the single
  commit point.

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
| `sluice-store`  | `StorageBackend` trait; in-memory, local, and object-store backends; pack codec |
| `sluice-repo`   | Repository handle: init/open, blobs/files/trees/snapshots, keys, locks, index segments, prune |
| `sluice-engine` | Backup / restore / verify / check / diff / forget / prune / rebuild-index orchestration |
| `sluice-cli`    | The `sluice` command-line binary |
| `sluice-index`  | Bounded-memory dedup index *(skeleton; today index segments live in `sluice-repo`)* |
| `sluice-scan`   | Parallel filesystem discovery *(skeleton; the engine currently walks directly)* |

## Roadmap

- **M0** — workspace skeleton, core types, `StorageBackend` trait — ✅
- **M1** — local backup + restore (incremental, symlinks, mode/mtime, excludes) — ✅
- **M2** — deduplication (FastCDC) + zstd compression + persisted per-pack index — ✅
- **M3** — encryption: Argon2id key hierarchy, XChaCha20-Poly1305, keyed BLAKE3 — ✅
- **M4** — object storage / offsite DR (S3, GCS, Azure, MinIO) — ✅
- **M5** — integrity (`verify`, `check`), retention (`forget` keep-last/daily/weekly/
  monthly/yearly, `--dry-run`, `--prune`), and repacking `prune` — ✅
- **M6** — operations: advisory locking (`unlock`), multiple passphrases
  (`key add`/`list`/`remove`/`passwd`), `rebuild-index` — ✅
- **M7** — UX & scripting: multi-source backups, `backup --dry-run`/`--exclude-from`,
  `find`, `tag`, `--keep-tag`/`--keep-within`/`--group-by`, `prune --max-unused`,
  `cat`, `copy`, `--json` output, stable exit codes — ✅
- **M8** — parallel pipeline, special files, FUSE mount, cross-platform polish — planned

## Building

Requires a recent stable Rust toolchain and a C compiler (used to build the
bundled `zstd`). TLS for object-storage backends uses `rustls`, so no OpenSSL or
other system libraries are required.

```sh
cargo build
cargo test     # 153 tests
```

## Caveats

This is **alpha software under active development**. The on-disk format will
change without migration until v0.1. **Do not use it for data you cannot afford
to lose.**

## License

Licensed under either of [Apache License, Version 2.0](./LICENSE-APACHE) or
[MIT license](./LICENSE-MIT) at your option.
