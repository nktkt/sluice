//! The pack-file container.
//!
//! A pack is the unit actually written to a backend: a run of blobs followed by
//! a CBOR *blob directory* and a little-endian `u32` directory length
//! (see `DESIGN.md` §3):
//!
//! ```text
//! [blob_0][blob_1]...[blob_n][directory: CBOR][dir_len: u32 LE]
//! ```
//!
//! The directory lets a reader locate any blob from the pack alone (the
//! disaster-recovery path). Blob sealing (compression + encryption) is layered
//! on top once `sluice-crypto` is wired in; for now blobs are stored verbatim.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use sluice_core::{BlobKind, Id, from_cbor, to_cbor};

use crate::StoreError;

/// A blob directory entry: where a blob lives within a pack body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlobEntry {
    /// The blob's content-address id.
    pub id: Id,
    /// Whether the blob is file data or a serialized tree.
    pub kind: BlobKind,
    /// Byte offset of the blob within the pack body.
    pub offset: u32,
    /// Blob length in bytes.
    pub length: u32,
}

/// Accumulates blobs into a pack.
#[derive(Debug, Default)]
pub struct PackBuilder {
    body: Vec<u8>,
    entries: Vec<BlobEntry>,
}

impl PackBuilder {
    /// Create an empty pack builder.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a blob, returning the directory entry that was recorded.
    pub fn add(&mut self, id: Id, kind: BlobKind, data: &[u8]) -> BlobEntry {
        let entry = BlobEntry {
            id,
            kind,
            offset: self.body.len() as u32,
            length: data.len() as u32,
        };
        self.body.extend_from_slice(data);
        self.entries.push(entry);
        entry
    }

    /// Number of blobs added so far.
    #[must_use]
    pub fn blob_count(&self) -> usize {
        self.entries.len()
    }

    /// Whether no blobs have been added.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Current pack body size in bytes (used to decide when to flush a pack).
    #[must_use]
    pub fn body_len(&self) -> usize {
        self.body.len()
    }

    /// Sealed bytes of a blob recorded by [`PackBuilder::add`], read from the
    /// in-progress body. Used to serve blobs not yet flushed to a pack.
    #[must_use]
    pub fn blob_at(&self, entry: &BlobEntry) -> &[u8] {
        &self.body[entry.offset as usize..entry.offset as usize + entry.length as usize]
    }

    /// Finish the pack, returning its bytes and the blob directory.
    pub fn finish(self) -> Result<(Vec<u8>, Vec<BlobEntry>), StoreError> {
        let directory =
            to_cbor(&self.entries).map_err(|e| StoreError::MalformedPack(e.to_string()))?;
        let dir_len = u32::try_from(directory.len())
            .map_err(|_| StoreError::MalformedPack("directory too large".into()))?;
        let mut bytes = self.body;
        bytes.extend_from_slice(&directory);
        bytes.extend_from_slice(&dir_len.to_le_bytes());
        Ok((bytes, self.entries))
    }
}

/// Reads blobs from a finished pack by parsing its trailing directory.
pub struct PackReader<'a> {
    body: &'a [u8],
    entries: Vec<BlobEntry>,
    index: HashMap<Id, BlobEntry>,
}

impl<'a> PackReader<'a> {
    /// Parse a pack's trailing directory, validating that every entry lies
    /// within the body. Rejects truncated or inconsistent packs.
    pub fn parse(pack: &'a [u8]) -> Result<Self, StoreError> {
        if pack.len() < 4 {
            return Err(StoreError::MalformedPack(
                "pack shorter than its length suffix".into(),
            ));
        }
        let suffix_at = pack.len() - 4;
        let dir_len = u32::from_le_bytes(
            pack[suffix_at..]
                .try_into()
                .expect("slice of length 4 is a [u8; 4]"),
        ) as usize;
        let dir_start = suffix_at
            .checked_sub(dir_len)
            .ok_or_else(|| StoreError::MalformedPack("directory length exceeds pack".into()))?;

        let entries: Vec<BlobEntry> = from_cbor(&pack[dir_start..suffix_at])
            .map_err(|e| StoreError::MalformedPack(e.to_string()))?;
        let body = &pack[..dir_start];

        for e in &entries {
            let end = (e.offset as usize)
                .checked_add(e.length as usize)
                .ok_or_else(|| StoreError::MalformedPack("blob offset/length overflow".into()))?;
            if end > body.len() {
                return Err(StoreError::MalformedPack(
                    "blob extends past the pack body".into(),
                ));
            }
        }

        let index = entries.iter().map(|e| (e.id, *e)).collect();
        Ok(Self {
            body,
            entries,
            index,
        })
    }

    /// Fetch a blob's bytes by id, or `None` if it is not in this pack.
    #[must_use]
    pub fn blob(&self, id: &Id) -> Option<&'a [u8]> {
        let e = self.index.get(id)?;
        Some(&self.body[e.offset as usize..e.offset as usize + e.length as usize])
    }

    /// The blob directory.
    #[must_use]
    pub fn entries(&self) -> &[BlobEntry] {
        &self.entries
    }

    /// Number of blobs in the pack.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the pack holds no blobs.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn id(b: u8) -> Id {
        Id::from_bytes([b; 32])
    }

    #[test]
    fn build_and_read_roundtrips() {
        let mut b = PackBuilder::new();
        b.add(id(1), BlobKind::Data, b"first blob");
        b.add(id(2), BlobKind::Tree, b"second");
        assert_eq!(b.blob_count(), 2);
        let (bytes, dir) = b.finish().unwrap();

        let r = PackReader::parse(&bytes).unwrap();
        assert_eq!(r.len(), 2);
        assert_eq!(r.blob(&id(1)).unwrap(), b"first blob");
        assert_eq!(r.blob(&id(2)).unwrap(), b"second");
        assert!(r.blob(&id(3)).is_none());
        assert_eq!(r.entries(), dir.as_slice());
    }

    #[test]
    fn entries_record_offset_and_length() {
        let mut b = PackBuilder::new();
        let e1 = b.add(id(1), BlobKind::Data, b"abc");
        let e2 = b.add(id(2), BlobKind::Data, b"de");
        assert_eq!((e1.offset, e1.length), (0, 3));
        assert_eq!((e2.offset, e2.length), (3, 2));
    }

    #[test]
    fn empty_pack_roundtrips() {
        let (bytes, _) = PackBuilder::new().finish().unwrap();
        let r = PackReader::parse(&bytes).unwrap();
        assert!(r.is_empty());
    }

    #[test]
    fn truncated_pack_is_rejected() {
        assert!(matches!(
            PackReader::parse(&[0u8; 2]),
            Err(StoreError::MalformedPack(_))
        ));
    }

    #[test]
    fn corrupt_directory_length_is_rejected() {
        let mut bytes = {
            let mut b = PackBuilder::new();
            b.add(id(1), BlobKind::Data, b"x");
            b.finish().unwrap().0
        };
        // Overwrite the trailing length with an absurd value.
        let n = bytes.len();
        bytes[n - 4..].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(matches!(
            PackReader::parse(&bytes),
            Err(StoreError::MalformedPack(_))
        ));
    }

    proptest! {
        // The directory is parsed from an untrusted backend, so arbitrary bytes
        // must never panic — only Ok or a MalformedPack error.
        #[test]
        fn parse_never_panics_on_arbitrary_bytes(
            bytes in proptest::collection::vec(any::<u8>(), 0..2000)
        ) {
            let _ = PackReader::parse(&bytes);
        }

        // Any well-formed pack parses and yields its blobs back.
        #[test]
        fn build_then_parse_roundtrips(
            blobs in proptest::collection::vec(
                proptest::collection::vec(any::<u8>(), 0..200),
                0..10,
            )
        ) {
            let mut builder = PackBuilder::new();
            for (i, data) in blobs.iter().enumerate() {
                builder.add(id(i as u8), BlobKind::Data, data);
            }
            let (bytes, _) = builder.finish().unwrap();
            let reader = PackReader::parse(&bytes).unwrap();
            prop_assert_eq!(reader.len(), blobs.len());
            for (i, data) in blobs.iter().enumerate() {
                prop_assert_eq!(reader.blob(&id(i as u8)).unwrap(), data.as_slice());
            }
        }
    }
}
