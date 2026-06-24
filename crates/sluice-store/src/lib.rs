//! `sluice-store` — the [`StorageBackend`] trait and its implementations.
//!
//! A repository is an append-only, content-addressed, encrypted object store.
//! This crate abstracts the backend (local filesystem, S3-compatible object
//! store, S3 WORM) behind one trait so the engine is backend-agnostic
//! (see `DESIGN.md` §5.5). Objects are immutable: [`StorageBackend::put`] has
//! create-only semantics.
//!
//! [`MemoryBackend`] is an in-memory implementation used by the fast,
//! deterministic test lane; [`LocalBackend`] is the on-disk one. The
//! [`PackBuilder`]/[`PackReader`] pair implements the pack-file container.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use sluice_core::Id;

mod local;
mod objstore;
mod pack;
pub use local::LocalBackend;
pub use objstore::ObjectStoreBackend;
pub use pack::{BlobEntry, PackBuilder, PackReader};

/// The category of object stored in a repository; determines its path prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FileType {
    /// The repository config object.
    Config,
    /// A key object (wrapped master key).
    Key,
    /// A pack file holding sealed blobs.
    Pack,
    /// An index segment.
    Index,
    /// A snapshot object.
    Snapshot,
    /// A lock object.
    Lock,
}

/// The repository subdirectory / object-path prefix for each file type.
pub(crate) const fn type_dir(ty: FileType) -> &'static str {
    match ty {
        FileType::Config => "config",
        FileType::Key => "keys",
        FileType::Pack => "data",
        FileType::Index => "index",
        FileType::Snapshot => "snapshots",
        FileType::Lock => "locks",
    }
}

/// Errors produced by a [`StorageBackend`] or pack codec.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The requested object does not exist.
    #[error("object not found: {ty:?}/{id}")]
    NotFound {
        /// The object's type.
        ty: FileType,
        /// The object's id.
        id: Id,
    },
    /// A create-only `put` targeted an id that already exists.
    #[error("object already exists: {ty:?}/{id}")]
    AlreadyExists {
        /// The object's type.
        ty: FileType,
        /// The object's id.
        id: Id,
    },
    /// A backend-specific failure (I/O, network, etc.).
    #[error("backend error: {0}")]
    Backend(String),
    /// A pack file's structure or trailing directory is invalid.
    #[error("malformed pack: {0}")]
    MalformedPack(String),
}

/// Convenience alias for fallible store operations.
pub type Result<T> = std::result::Result<T, StoreError>;

/// Abstraction over an append-only, content-addressed object store.
///
/// Implementations are cheap to share (`Send + Sync`) and object-safe, so the
/// engine can hold a `dyn StorageBackend` chosen at runtime.
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Fetch an object's full contents.
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes>;

    /// Store a new object.
    ///
    /// Objects are content-addressed and immutable, so writing an id that
    /// already exists is an [`StoreError::AlreadyExists`] (create semantics).
    async fn put(&self, ty: FileType, id: &Id, data: Bytes) -> Result<()>;

    /// Whether an object exists.
    async fn exists(&self, ty: FileType, id: &Id) -> Result<bool>;

    /// List the ids of all objects of a given type.
    async fn list(&self, ty: FileType) -> Result<Vec<Id>>;

    /// Remove an object (used only by prune).
    async fn remove(&self, ty: FileType, id: &Id) -> Result<()>;

    /// The stored size of an object in bytes.
    async fn size(&self, ty: FileType, id: &Id) -> Result<u64>;
}

/// Lets an `Arc<dyn StorageBackend>` (or any `Arc<B>`) be used as a backend, so
/// the engine can hold a runtime-selected backend.
#[async_trait]
impl<B: StorageBackend + ?Sized> StorageBackend for Arc<B> {
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes> {
        (**self).get(ty, id).await
    }

    async fn put(&self, ty: FileType, id: &Id, data: Bytes) -> Result<()> {
        (**self).put(ty, id, data).await
    }

    async fn exists(&self, ty: FileType, id: &Id) -> Result<bool> {
        (**self).exists(ty, id).await
    }

    async fn list(&self, ty: FileType) -> Result<Vec<Id>> {
        (**self).list(ty).await
    }

    async fn remove(&self, ty: FileType, id: &Id) -> Result<()> {
        (**self).remove(ty, id).await
    }

    async fn size(&self, ty: FileType, id: &Id) -> Result<u64> {
        (**self).size(ty, id).await
    }
}

/// An in-memory [`StorageBackend`] for tests and the in-memory test lane.
#[derive(Debug, Default)]
pub struct MemoryBackend {
    objects: Mutex<HashMap<(FileType, Id), Bytes>>,
}

impl MemoryBackend {
    /// Create an empty in-memory backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of stored objects.
    #[must_use]
    pub fn len(&self) -> usize {
        self.objects.lock().expect("store mutex poisoned").len()
    }

    /// Whether the backend holds no objects.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[async_trait]
impl StorageBackend for MemoryBackend {
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes> {
        self.objects
            .lock()
            .expect("store mutex poisoned")
            .get(&(ty, *id))
            .cloned()
            .ok_or(StoreError::NotFound { ty, id: *id })
    }

    async fn put(&self, ty: FileType, id: &Id, data: Bytes) -> Result<()> {
        let mut map = self.objects.lock().expect("store mutex poisoned");
        if map.contains_key(&(ty, *id)) {
            return Err(StoreError::AlreadyExists { ty, id: *id });
        }
        map.insert((ty, *id), data);
        Ok(())
    }

    async fn exists(&self, ty: FileType, id: &Id) -> Result<bool> {
        Ok(self
            .objects
            .lock()
            .expect("store mutex poisoned")
            .contains_key(&(ty, *id)))
    }

    async fn list(&self, ty: FileType) -> Result<Vec<Id>> {
        Ok(self
            .objects
            .lock()
            .expect("store mutex poisoned")
            .keys()
            .filter(|(t, _)| *t == ty)
            .map(|(_, id)| *id)
            .collect())
    }

    async fn remove(&self, ty: FileType, id: &Id) -> Result<()> {
        self.objects
            .lock()
            .expect("store mutex poisoned")
            .remove(&(ty, *id))
            .map(|_| ())
            .ok_or(StoreError::NotFound { ty, id: *id })
    }

    async fn size(&self, ty: FileType, id: &Id) -> Result<u64> {
        self.objects
            .lock()
            .expect("store mutex poisoned")
            .get(&(ty, *id))
            .map(|b| b.len() as u64)
            .ok_or(StoreError::NotFound { ty, id: *id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(b: u8) -> Id {
        Id::from_bytes([b; 32])
    }

    #[tokio::test]
    async fn put_then_get_roundtrips() {
        let be = MemoryBackend::new();
        let data = Bytes::from_static(b"hello pack");
        be.put(FileType::Pack, &id(1), data.clone()).await.unwrap();
        assert_eq!(be.get(FileType::Pack, &id(1)).await.unwrap(), data);
        assert_eq!(be.len(), 1);
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let be = MemoryBackend::new();
        assert!(matches!(
            be.get(FileType::Pack, &id(9)).await,
            Err(StoreError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn put_is_create_only() {
        let be = MemoryBackend::new();
        be.put(FileType::Snapshot, &id(2), Bytes::from_static(b"a"))
            .await
            .unwrap();
        let dup = be
            .put(FileType::Snapshot, &id(2), Bytes::from_static(b"b"))
            .await;
        assert!(matches!(dup, Err(StoreError::AlreadyExists { .. })));
        // The original object is left untouched.
        assert_eq!(
            be.get(FileType::Snapshot, &id(2)).await.unwrap(),
            Bytes::from_static(b"a")
        );
    }

    #[tokio::test]
    async fn list_filters_by_type_and_remove_works() {
        let be = MemoryBackend::new();
        be.put(FileType::Pack, &id(1), Bytes::new()).await.unwrap();
        be.put(FileType::Pack, &id(2), Bytes::new()).await.unwrap();
        be.put(FileType::Index, &id(3), Bytes::new()).await.unwrap();

        let mut packs = be.list(FileType::Pack).await.unwrap();
        packs.sort();
        assert_eq!(packs, vec![id(1), id(2)]);
        assert_eq!(be.list(FileType::Index).await.unwrap(), vec![id(3)]);

        be.remove(FileType::Pack, &id(1)).await.unwrap();
        assert!(!be.exists(FileType::Pack, &id(1)).await.unwrap());
        assert!(matches!(
            be.remove(FileType::Pack, &id(1)).await,
            Err(StoreError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn usable_as_a_trait_object() {
        let be: Box<dyn StorageBackend> = Box::new(MemoryBackend::new());
        be.put(FileType::Config, &id(0), Bytes::from_static(b"cfg"))
            .await
            .unwrap();
        assert!(be.exists(FileType::Config, &id(0)).await.unwrap());
    }

    #[tokio::test]
    async fn arc_dyn_backend_delegates() {
        let be: Arc<dyn StorageBackend> = Arc::new(MemoryBackend::new());
        be.put(FileType::Pack, &id(7), Bytes::from_static(b"x"))
            .await
            .unwrap();
        assert!(be.exists(FileType::Pack, &id(7)).await.unwrap());
        assert_eq!(be.list(FileType::Pack).await.unwrap(), vec![id(7)]);
    }

    #[tokio::test]
    async fn size_returns_stored_length() {
        let be = MemoryBackend::new();
        be.put(FileType::Pack, &id(1), Bytes::from_static(b"twelve bytes"))
            .await
            .unwrap();
        assert_eq!(be.size(FileType::Pack, &id(1)).await.unwrap(), 12);
        assert!(matches!(
            be.size(FileType::Pack, &id(2)).await,
            Err(StoreError::NotFound { .. })
        ));
    }
}
