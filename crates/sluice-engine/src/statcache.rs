//! An optional on-disk cache mapping a file's identity `(device, inode)` to the
//! chunk ids it last backed up. When enabled (`backup --cache <PATH>`) it is the
//! incremental oracle: an unchanged file is reused from its cached chunk ids
//! without re-reading it *and* without loading the previous snapshot's trees —
//! the latter being a per-directory round trip on an object-store backend. The
//! cache is only ever an optimization: every reuse is still gated on the chunks
//! actually being present in the repository (see `Repository::has_blob`), so a
//! stale or foreign cache can never corrupt a backup, only slow it down.

use std::path::Path;

use redb::{Database, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use sluice_core::{Id, from_cbor, to_cbor};

/// `(dev ++ ino)` little-endian bytes → CBOR([`CacheEntry`]).
const TABLE: TableDefinition<&[u8], &[u8]> = TableDefinition::new("stat_cache_v1");

/// What a file looked like the last time it was backed up.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// File size in bytes at that time.
    pub size: u64,
    /// Modification time, nanoseconds since the Unix epoch, at that time.
    pub mtime_ns: i64,
    /// The content chunk ids the file's bytes hashed to.
    pub ids: Vec<Id>,
}

/// A persistent `(device, inode) → CacheEntry` map backed by an embedded redb
/// database. Lookups are cheap (a read snapshot, no fsync); writes are batched
/// by the caller and committed once via [`commit`](Self::commit) so a backup
/// pays a single fsync rather than one per file.
#[derive(Debug)]
pub struct StatCache {
    db: Database,
}

/// The 16-byte key for a file identity.
fn key(dev: u64, ino: u64) -> [u8; 16] {
    let mut k = [0u8; 16];
    k[..8].copy_from_slice(&dev.to_le_bytes());
    k[8..].copy_from_slice(&ino.to_le_bytes());
    k
}

/// Flatten any redb error into an `io::Error` so callers can fold it into their
/// existing I/O error path.
fn to_io<E: std::fmt::Display>(e: E) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

impl StatCache {
    /// Open the cache database at `path`, creating it (and its table) if absent.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let db = Database::create(path).map_err(to_io)?;
        // Materialize the table so later read-only transactions can open it even
        // on a freshly created database.
        let w = db.begin_write().map_err(to_io)?;
        w.open_table(TABLE).map_err(to_io)?;
        w.commit().map_err(to_io)?;
        Ok(Self { db })
    }

    /// The cached entry for `(dev, ino)`, if any. Best-effort: any read error is
    /// treated as a miss, so a damaged cache degrades to re-reading files.
    #[must_use]
    pub fn lookup(&self, dev: u64, ino: u64) -> Option<CacheEntry> {
        let txn = self.db.begin_read().ok()?;
        let table = txn.open_table(TABLE).ok()?;
        let value = table.get(key(dev, ino).as_slice()).ok()??;
        from_cbor::<CacheEntry>(value.value()).ok()
    }

    /// Persist a batch of `(dev, ino, entry)` updates in one transaction.
    /// Best-effort: errors are swallowed so a cache failure never fails a backup
    /// (the cache is an optimization, never a source of truth).
    pub fn commit(&self, updates: &[(u64, u64, CacheEntry)]) {
        if updates.is_empty() {
            return;
        }
        let Ok(w) = self.db.begin_write() else {
            return;
        };
        {
            let Ok(mut table) = w.open_table(TABLE) else {
                return;
            };
            for (dev, ino, entry) in updates {
                if let Ok(bytes) = to_cbor(entry) {
                    let _ = table.insert(key(*dev, *ino).as_slice(), bytes.as_slice());
                }
            }
        }
        let _ = w.commit();
    }

    /// The number of cached entries (for tests and `info`-style reporting).
    #[must_use]
    pub fn len(&self) -> usize {
        let count = || -> Option<u64> {
            let txn = self.db.begin_read().ok()?;
            let table = txn.open_table(TABLE).ok()?;
            table.len().ok()
        };
        count().unwrap_or(0) as usize
    }

    /// Whether the cache holds no entries.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(size: u64, mtime: i64, ids: &[u8]) -> CacheEntry {
        CacheEntry {
            size,
            mtime_ns: mtime,
            ids: ids.iter().map(|b| Id::from_bytes([*b; 32])).collect(),
        }
    }

    #[test]
    fn roundtrips_through_a_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache.redb");
        {
            let cache = StatCache::open(&path).unwrap();
            assert!(cache.is_empty());
            cache.commit(&[
                (1, 100, entry(10, 111, &[1, 2])),
                (1, 200, entry(20, 222, &[3])),
            ]);
            assert_eq!(cache.len(), 2);
            assert_eq!(cache.lookup(1, 100).unwrap(), entry(10, 111, &[1, 2]));
            assert!(cache.lookup(1, 999).is_none());
        }
        // A reopened database still has the committed entries.
        let cache = StatCache::open(&path).unwrap();
        assert_eq!(cache.len(), 2);
        assert_eq!(cache.lookup(1, 200).unwrap(), entry(20, 222, &[3]));
    }

    #[test]
    fn commit_overwrites_an_existing_key() {
        let dir = tempfile::tempdir().unwrap();
        let cache = StatCache::open(&dir.path().join("c.redb")).unwrap();
        cache.commit(&[(7, 7, entry(1, 1, &[9]))]);
        cache.commit(&[(7, 7, entry(2, 2, &[8]))]);
        assert_eq!(cache.len(), 1, "same key replaced, not duplicated");
        assert_eq!(cache.lookup(7, 7).unwrap(), entry(2, 2, &[8]));
    }
}
