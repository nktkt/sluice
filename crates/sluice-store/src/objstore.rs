//! A [`StorageBackend`] over any [`object_store::ObjectStore`] — S3, GCS, Azure,
//! MinIO, and more — for offsite disaster recovery (see `DESIGN.md` §5.5).
//!
//! The concrete store (e.g. an `AmazonS3` built with object_store's `aws`
//! feature) is supplied as a trait object, so this backend is store-agnostic.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use futures::StreamExt;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutMode, PutOptions};
use sluice_core::Id;

use crate::{FileType, Result, StorageBackend, StoreError, type_dir};

/// A [`StorageBackend`] backed by an object store. Objects are immutable, so
/// `put` uses conditional-create semantics.
#[derive(Clone)]
pub struct ObjectStoreBackend {
    store: Arc<dyn ObjectStore>,
}

impl ObjectStoreBackend {
    /// Wrap an object store.
    #[must_use]
    pub fn new(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }

    fn object_path(&self, ty: FileType, id: &Id) -> ObjectPath {
        ObjectPath::from(format!("{}/{}", type_dir(ty), id.to_hex()))
    }
}

fn os_err(e: object_store::Error) -> StoreError {
    StoreError::Backend(e.to_string())
}

#[async_trait]
impl StorageBackend for ObjectStoreBackend {
    async fn get(&self, ty: FileType, id: &Id) -> Result<Bytes> {
        match self.store.get(&self.object_path(ty, id)).await {
            Ok(result) => result.bytes().await.map_err(os_err),
            Err(object_store::Error::NotFound { .. }) => Err(StoreError::NotFound { ty, id: *id }),
            Err(e) => Err(os_err(e)),
        }
    }

    async fn put(&self, ty: FileType, id: &Id, data: Bytes) -> Result<()> {
        let opts = PutOptions {
            mode: PutMode::Create,
            ..Default::default()
        };
        match self
            .store
            .put_opts(&self.object_path(ty, id), data.into(), opts)
            .await
        {
            Ok(_) => Ok(()),
            Err(object_store::Error::AlreadyExists { .. }) => {
                Err(StoreError::AlreadyExists { ty, id: *id })
            }
            Err(e) => Err(os_err(e)),
        }
    }

    async fn exists(&self, ty: FileType, id: &Id) -> Result<bool> {
        match self.store.head(&self.object_path(ty, id)).await {
            Ok(_) => Ok(true),
            Err(object_store::Error::NotFound { .. }) => Ok(false),
            Err(e) => Err(os_err(e)),
        }
    }

    async fn list(&self, ty: FileType) -> Result<Vec<Id>> {
        let prefix = ObjectPath::from(type_dir(ty));
        let mut stream = self.store.list(Some(&prefix));
        let mut ids = Vec::new();
        while let Some(meta) = stream.next().await {
            let meta = meta.map_err(os_err)?;
            if let Some(name) = meta.location.filename() {
                if let Ok(id) = name.parse::<Id>() {
                    ids.push(id);
                }
            }
        }
        Ok(ids)
    }

    async fn remove(&self, ty: FileType, id: &Id) -> Result<()> {
        match self.store.delete(&self.object_path(ty, id)).await {
            Ok(()) => Ok(()),
            Err(object_store::Error::NotFound { .. }) => Err(StoreError::NotFound { ty, id: *id }),
            Err(e) => Err(os_err(e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use object_store::memory::InMemory;

    fn backend() -> ObjectStoreBackend {
        ObjectStoreBackend::new(Arc::new(InMemory::new()))
    }

    fn id(b: u8) -> Id {
        Id::from_bytes([b; 32])
    }

    #[tokio::test]
    async fn put_get_roundtrips() {
        let be = backend();
        be.put(FileType::Pack, &id(1), Bytes::from_static(b"data"))
            .await
            .unwrap();
        assert_eq!(
            be.get(FileType::Pack, &id(1)).await.unwrap(),
            Bytes::from_static(b"data")
        );
    }

    #[tokio::test]
    async fn put_is_create_only() {
        let be = backend();
        be.put(FileType::Snapshot, &id(2), Bytes::from_static(b"a"))
            .await
            .unwrap();
        assert!(matches!(
            be.put(FileType::Snapshot, &id(2), Bytes::from_static(b"b"))
                .await,
            Err(StoreError::AlreadyExists { .. })
        ));
    }

    #[tokio::test]
    async fn get_missing_is_not_found() {
        let be = backend();
        assert!(matches!(
            be.get(FileType::Index, &id(9)).await,
            Err(StoreError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn list_and_remove_work() {
        let be = backend();
        be.put(FileType::Pack, &id(1), Bytes::new()).await.unwrap();
        be.put(FileType::Pack, &id(2), Bytes::new()).await.unwrap();
        be.put(FileType::Index, &id(3), Bytes::new()).await.unwrap();

        let mut packs = be.list(FileType::Pack).await.unwrap();
        packs.sort();
        assert_eq!(packs, vec![id(1), id(2)]);

        be.remove(FileType::Pack, &id(1)).await.unwrap();
        assert!(!be.exists(FileType::Pack, &id(1)).await.unwrap());
    }
}
