//! A local-filesystem [`StorageBackend`].

use std::io::ErrorKind;
use std::path::PathBuf;

use async_trait::async_trait;
use bytes::Bytes;
use sluice_core::Id;
use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::{FileType, Result, StorageBackend, StoreError};

/// Every object category, used to pre-create the directory layout.
const ALL_TYPES: [FileType; 6] = [
    FileType::Config,
    FileType::Key,
    FileType::Pack,
    FileType::Index,
    FileType::Snapshot,
    FileType::Lock,
];

/// The subdirectory name for each object category.
const fn type_dir(ty: FileType) -> &'static str {
    match ty {
        FileType::Config => "config",
        FileType::Key => "keys",
        FileType::Pack => "data",
        FileType::Index => "index",
        FileType::Snapshot => "snapshots",
        FileType::Lock => "locks",
    }
}

/// A [`StorageBackend`] backed by a local directory tree.
///
/// Writes are crash-consistent: payload is written to a temp file, fsynced,
/// atomically renamed into place, then the parent directory is fsynced
/// (see `DESIGN.md` §5.5). Objects are immutable, so `put` is create-only.
#[derive(Debug, Clone)]
pub struct LocalBackend {
    root: PathBuf,
}

impl LocalBackend {
    /// Open `root`, creating the directory layout if necessary.
    pub async fn create(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        for ty in ALL_TYPES {
            fs::create_dir_all(root.join(type_dir(ty)))
                .await
                .map_err(io)?;
        }
        Ok(Self { root })
    }

    /// Open an existing repository `root` without creating anything.
    #[must_use]
    pub fn open(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    fn dir(&self, ty: FileType) -> PathBuf {
        self.root.join(type_dir(ty))
    }

    fn path(&self, ty: FileType, id: &Id) -> PathBuf {
        self.dir(ty).join(id.to_hex())
    }
}

/// Map a low-level I/O error into a backend error.
fn io(e: std::io::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[async_trait]
impl StorageBackend for LocalBackend {
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes> {
        match fs::read(self.path(ty, id)).await {
            Ok(v) => Ok(Bytes::from(v)),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::NotFound { ty, id: *id }),
            Err(e) => Err(io(e)),
        }
    }

    async fn put(&self, ty: FileType, id: &Id, data: Bytes) -> Result<()> {
        let final_path = self.path(ty, id);
        if fs::try_exists(&final_path).await.map_err(io)? {
            return Err(StoreError::AlreadyExists { ty, id: *id });
        }
        let dir = self.dir(ty);
        fs::create_dir_all(&dir).await.map_err(io)?;
        let tmp = dir.join(format!(".tmp.{}", id.to_hex()));

        let mut f = fs::File::create(&tmp).await.map_err(io)?;
        f.write_all(&data).await.map_err(io)?;
        f.sync_all().await.map_err(io)?;
        drop(f);

        fs::rename(&tmp, &final_path).await.map_err(io)?;
        // Best-effort directory fsync so the rename itself is durable (Linux).
        if let Ok(d) = fs::File::open(&dir).await {
            let _ = d.sync_all().await;
        }
        Ok(())
    }

    async fn exists(&self, ty: FileType, id: &Id) -> Result<bool> {
        fs::try_exists(self.path(ty, id)).await.map_err(io)
    }

    async fn list(&self, ty: FileType) -> Result<Vec<Id>> {
        let mut rd = match fs::read_dir(self.dir(ty)).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io(e)),
        };
        let mut ids = Vec::new();
        while let Some(entry) = rd.next_entry().await.map_err(io)? {
            // Object files are named by 64-hex id; temp files (".tmp.*") and
            // anything else simply fail to parse and are skipped.
            if let Some(name) = entry.file_name().to_str() {
                if let Ok(id) = name.parse::<Id>() {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    async fn remove(&self, ty: FileType, id: &Id) -> Result<()> {
        match fs::remove_file(self.path(ty, id)).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == ErrorKind::NotFound => Err(StoreError::NotFound { ty, id: *id }),
            Err(e) => Err(io(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Id {
        Id::from_bytes([b; 32])
    }

    #[tokio::test]
    async fn put_get_roundtrips_and_is_durable() {
        let dir = tempfile::tempdir().unwrap();
        {
            let be = LocalBackend::create(dir.path()).await.unwrap();
            be.put(FileType::Pack, &id(1), Bytes::from_static(b"pack-bytes"))
                .await
                .unwrap();
        }
        // A fresh handle sees the data: it really hit the disk.
        let be = LocalBackend::open(dir.path());
        assert_eq!(
            be.get(FileType::Pack, &id(1)).await.unwrap(),
            Bytes::from_static(b"pack-bytes")
        );
    }

    #[tokio::test]
    async fn put_is_create_only() {
        let dir = tempfile::tempdir().unwrap();
        let be = LocalBackend::create(dir.path()).await.unwrap();
        be.put(FileType::Snapshot, &id(2), Bytes::from_static(b"a"))
            .await
            .unwrap();
        assert!(matches!(
            be.put(FileType::Snapshot, &id(2), Bytes::from_static(b"b"))
                .await,
            Err(StoreError::AlreadyExists { .. })
        ));
        assert_eq!(
            be.get(FileType::Snapshot, &id(2)).await.unwrap(),
            Bytes::from_static(b"a")
        );
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let dir = tempfile::tempdir().unwrap();
        let be = LocalBackend::create(dir.path()).await.unwrap();
        assert!(matches!(
            be.get(FileType::Index, &id(7)).await,
            Err(StoreError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn list_and_remove_work() {
        let dir = tempfile::tempdir().unwrap();
        let be = LocalBackend::create(dir.path()).await.unwrap();
        be.put(FileType::Pack, &id(1), Bytes::new()).await.unwrap();
        be.put(FileType::Pack, &id(2), Bytes::new()).await.unwrap();

        let mut ids = be.list(FileType::Pack).await.unwrap();
        ids.sort();
        assert_eq!(ids, vec![id(1), id(2)]);

        be.remove(FileType::Pack, &id(1)).await.unwrap();
        assert!(!be.exists(FileType::Pack, &id(1)).await.unwrap());
        assert!(matches!(
            be.remove(FileType::Pack, &id(1)).await,
            Err(StoreError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn list_of_empty_type_is_empty() {
        let dir = tempfile::tempdir().unwrap();
        let be = LocalBackend::create(dir.path()).await.unwrap();
        assert!(be.list(FileType::Lock).await.unwrap().is_empty());
    }
}
