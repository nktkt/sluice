//! `sluice-engine` — backup and restore orchestration (see `DESIGN.md` §6, §8).
//!
//! This first cut walks a directory tree, storing each regular file as
//! deduplicated chunks and each directory as a `Tree`, then commits a snapshot;
//! restore rebuilds the tree. Files and directories are handled; symlinks,
//! special files, and metadata replay (mode/mtime) are follow-up work. The walk
//! uses blocking `std::fs` for now; offloading to a thread pool is a later
//! refinement.

use std::ffi::OsString;
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;

use sluice_core::{
    EntryKind, Id, Node, SNAPSHOT_VERSION, Snapshot, SnapshotStats, TREE_VERSION, Tree,
};
use sluice_repo::{RepoError, Repository};
use sluice_store::StorageBackend;

/// Errors from engine operations.
#[derive(Debug, thiserror::Error)]
pub enum EngineError {
    /// An underlying repository error.
    #[error("repository error: {0}")]
    Repo(#[from] RepoError),
    /// A filesystem error, annotated with the offending path.
    #[error("io error at {path}: {source}")]
    Io {
        /// The path being operated on.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },
}

/// Convenience alias for fallible engine operations.
pub type Result<T> = std::result::Result<T, EngineError>;

fn io_err(path: &Path, source: std::io::Error) -> EngineError {
    EngineError::Io {
        path: path.display().to_string(),
        source,
    }
}

/// Back up the directory `source` into `repo`, returning the new snapshot id.
pub async fn backup<B: StorageBackend>(repo: &mut Repository<B>, source: &Path) -> Result<Id> {
    let root_tree = backup_dir(repo, source.to_path_buf()).await?;
    let snapshot = Snapshot {
        version: SNAPSHOT_VERSION,
        time_ns: now_ns(),
        tree: root_tree,
        paths: vec![source.as_os_str().as_encoded_bytes().to_vec()],
        hostname: env_or("HOSTNAME", "localhost"),
        username: env_or("USER", "unknown"),
        uid: 0,
        gid: 0,
        tags: Vec::new(),
        parent: None,
        program_version: env!("CARGO_PKG_VERSION").to_string(),
        summary: SnapshotStats::default(),
    };
    Ok(repo.commit_snapshot(&snapshot).await?)
}

/// Restore the snapshot `snapshot` from `repo` into the directory `target`.
pub async fn restore<B: StorageBackend>(
    repo: &Repository<B>,
    snapshot: &Id,
    target: &Path,
) -> Result<()> {
    let snap = repo.load_snapshot(snapshot).await?;
    std::fs::create_dir_all(target).map_err(|e| io_err(target, e))?;
    restore_tree(repo, snap.tree, target.to_path_buf()).await
}

/// A summary produced by [`verify`].
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct VerifyReport {
    /// Number of snapshots checked.
    pub snapshots: usize,
    /// Number of tree objects read and authenticated.
    pub trees: usize,
    /// Number of content (file chunk) blobs read and authenticated.
    pub blobs: usize,
}

/// Verify every snapshot in `repo` by reading and authenticating all reachable
/// trees and content blobs (a full read-data check; see `DESIGN.md` §5.7).
///
/// Returns the counts on success, or the first error identifying a missing or
/// corrupt object.
pub async fn verify<B: StorageBackend>(repo: &Repository<B>) -> Result<VerifyReport> {
    let mut report = VerifyReport::default();
    for snapshot in repo.list_snapshots().await? {
        let snap = repo.load_snapshot(&snapshot).await?;
        report.snapshots += 1;
        verify_tree(repo, snap.tree, &mut report).await?;
    }
    Ok(report)
}

/// Recursively read and authenticate the tree `tree_id` and its content blobs.
fn verify_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    report: &'a mut VerifyReport,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        report.trees += 1;
        for node in &tree.nodes {
            match node.kind {
                EntryKind::Dir => {
                    if let Some(subtree) = node.subtree {
                        verify_tree(repo, subtree, report).await?;
                    }
                }
                EntryKind::File => {
                    for id in &node.content {
                        // load_blob authenticates (AEAD) and decompresses.
                        repo.load_blob(id).await?;
                        report.blobs += 1;
                    }
                }
                _ => {}
            }
        }
        Ok(())
    })
}

/// Recursively back up `dir`, returning the id of its `Tree` object.
fn backup_dir<'a, B: StorageBackend>(
    repo: &'a mut Repository<B>,
    dir: PathBuf,
) -> Pin<Box<dyn Future<Output = Result<Id>> + 'a>> {
    Box::pin(async move {
        let mut entries: Vec<_> = std::fs::read_dir(&dir)
            .map_err(|e| io_err(&dir, e))?
            .collect::<std::io::Result<Vec<_>>>()
            .map_err(|e| io_err(&dir, e))?;
        // Sort by name for a deterministic, dedup-friendly tree.
        entries.sort_by_key(std::fs::DirEntry::file_name);

        let mut nodes = Vec::with_capacity(entries.len());
        for entry in entries {
            let path = entry.path();
            let meta = std::fs::symlink_metadata(&path).map_err(|e| io_err(&path, e))?;
            let name = entry.file_name().as_encoded_bytes().to_vec();
            let kind = meta.file_type();

            let node = if kind.is_dir() {
                let subtree = backup_dir(repo, path.clone()).await?;
                Node {
                    name,
                    kind: EntryKind::Dir,
                    mode: mode_of(&meta),
                    uid: 0,
                    gid: 0,
                    mtime_ns: mtime_ns(&meta),
                    ctime_ns: 0,
                    size: 0,
                    content: Vec::new(),
                    subtree: Some(subtree),
                    link_target: None,
                }
            } else if kind.is_file() {
                let data = std::fs::read(&path).map_err(|e| io_err(&path, e))?;
                let content = repo.save_file(&data).await?;
                Node {
                    name,
                    kind: EntryKind::File,
                    mode: mode_of(&meta),
                    uid: 0,
                    gid: 0,
                    mtime_ns: mtime_ns(&meta),
                    ctime_ns: 0,
                    size: data.len() as u64,
                    content,
                    subtree: None,
                    link_target: None,
                }
            } else {
                continue; // symlinks and special files: follow-up work
            };
            nodes.push(node);
        }

        let tree = Tree {
            version: TREE_VERSION,
            nodes,
        };
        Ok(repo.save_tree(&tree).await?)
    })
}

/// Recursively restore the tree `tree_id` into the directory `dir`.
fn restore_tree<'a, B: StorageBackend>(
    repo: &'a Repository<B>,
    tree_id: Id,
    dir: PathBuf,
) -> Pin<Box<dyn Future<Output = Result<()>> + 'a>> {
    Box::pin(async move {
        let tree = repo.load_tree(&tree_id).await?;
        for node in &tree.nodes {
            let path = dir.join(osstring_from_bytes(&node.name));
            match node.kind {
                EntryKind::Dir => {
                    std::fs::create_dir_all(&path).map_err(|e| io_err(&path, e))?;
                    if let Some(subtree) = node.subtree {
                        restore_tree(repo, subtree, path).await?;
                    }
                }
                EntryKind::File => {
                    let data = repo.load_file(&node.content).await?;
                    std::fs::write(&path, &data).map_err(|e| io_err(&path, e))?;
                }
                _ => continue, // symlinks and special files: follow-up work
            }
        }
        Ok(())
    })
}

/// Reconstruct an `OsString` from bytes produced by `OsStr::as_encoded_bytes`.
fn osstring_from_bytes(bytes: &[u8]) -> OsString {
    // SAFETY: `bytes` were produced by `OsStr::as_encoded_bytes` during backup,
    // which is exactly the precondition of `from_encoded_bytes_unchecked`.
    unsafe { OsString::from_encoded_bytes_unchecked(bytes.to_vec()) }
}

#[cfg(unix)]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode()
}

#[cfg(not(unix))]
fn mode_of(meta: &std::fs::Metadata) -> u32 {
    if meta.is_dir() { 0o755 } else { 0o644 }
}

fn mtime_ns(meta: &std::fs::Metadata) -> i64 {
    meta.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn now_ns() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_crypto::KdfParams;
    use sluice_store::{FileType, MemoryBackend};

    fn fast() -> KdfParams {
        KdfParams {
            m_cost_kib: 16,
            t_cost: 1,
            p_cost: 1,
        }
    }

    #[tokio::test]
    async fn backup_restore_roundtrips_a_directory_tree() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("sub")).unwrap();
        std::fs::write(src.path().join("sub/b.txt"), b"bravo bravo").unwrap();
        std::fs::write(src.path().join("sub/c.bin"), vec![7u8; 1000]).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();

        let dst = tempfile::tempdir().unwrap();
        restore(&repo, &snap, dst.path()).await.unwrap();

        assert_eq!(std::fs::read(dst.path().join("a.txt")).unwrap(), b"alpha");
        assert_eq!(
            std::fs::read(dst.path().join("sub/b.txt")).unwrap(),
            b"bravo bravo"
        );
        assert_eq!(
            std::fs::read(dst.path().join("sub/c.bin")).unwrap(),
            vec![7u8; 1000]
        );
    }

    #[tokio::test]
    async fn backup_deduplicates_identical_files() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("x"), b"same content here").unwrap();
        std::fs::write(src.path().join("y"), b"same content here").unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        // Two identical files share one Data blob; plus one Tree blob => 2 packs.
        let packs = repo.backend().list(FileType::Pack).await.unwrap().len();
        assert!(packs <= 2, "expected dedup, got {packs} packs");
    }

    #[tokio::test]
    async fn restored_snapshot_lists_in_repo() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("f"), b"data").unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        let snap = backup(&mut repo, src.path()).await.unwrap();
        assert_eq!(repo.list_snapshots().await.unwrap(), vec![snap]);
    }

    #[tokio::test]
    async fn verify_passes_after_backup() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), b"alpha").unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/b"), vec![1u8; 5000]).unwrap();

        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let report = verify(&repo).await.unwrap();
        assert_eq!(report.snapshots, 1);
        assert!(report.trees >= 2, "root + subdir trees");
        assert!(report.blobs >= 2, "two file chunks");
    }

    #[tokio::test]
    async fn verify_fails_when_a_pack_is_missing() {
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a"), vec![9u8; 5000]).unwrap();
        let mut repo = Repository::init(MemoryBackend::new(), b"pw", fast())
            .await
            .unwrap();
        backup(&mut repo, src.path()).await.unwrap();

        let packs = repo.backend().list(FileType::Pack).await.unwrap();
        repo.backend()
            .remove(FileType::Pack, &packs[0])
            .await
            .unwrap();
        assert!(verify(&repo).await.is_err());
    }
}
