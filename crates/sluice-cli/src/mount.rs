//! `sluice mount` — expose a snapshot as a read-only FUSE filesystem so its
//! files can be browsed and copied without a full restore. Compiled only with
//! the `fuse` feature (which links libfuse); the default build needs no system
//! libraries.
//!
//! The whole directory tree is loaded into an in-memory inode table at mount
//! time (cheap — trees are small); file *contents* are fetched and decrypted
//! lazily on `read`, with the most-recently-read file cached so a sequential
//! `cat` does not re-fetch its chunks.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::io;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fuser::{
    FileAttr, FileType, Filesystem, MountOption, ReplyAttr, ReplyData, ReplyDirectory, ReplyEntry,
    Request,
};
use sluice_core::{EntryKind, Id, Node};
use sluice_repo::Repository;
use sluice_store::StorageBackend;
use tokio::runtime::Runtime;

/// The fixed FUSE inode of the snapshot root.
const ROOT: u64 = fuser::FUSE_ROOT_ID;

/// A snapshot is immutable, so kernel caches never go stale — use a long TTL.
const TTL: Duration = Duration::from_secs(86_400);

/// Per-inode payload beyond the `FileAttr`.
enum Body {
    /// Directory: `(name, child inode)` pairs.
    Dir(Vec<(std::ffi::OsString, u64)>),
    /// Regular file: its ordered content chunk ids.
    File(Vec<Id>),
    /// Symlink: the raw target bytes.
    Link(Vec<u8>),
    /// Anything else (special files have no readable content here).
    Other,
}

/// One entry in the in-memory tree.
struct Inode {
    attr: FileAttr,
    body: Body,
}

/// A read-only view of one snapshot.
struct SnapshotFs<B: StorageBackend> {
    rt: Runtime,
    repo: Repository<B>,
    inodes: HashMap<u64, Inode>,
    /// The most-recently-read file `(inode, bytes)`, so sequential reads of one
    /// file fetch its chunks only once.
    cached: Option<(u64, Vec<u8>)>,
}

/// A `SystemTime` from nanoseconds since the Unix epoch (clamped at the epoch).
fn systime(ns: i64) -> SystemTime {
    if ns >= 0 {
        UNIX_EPOCH + Duration::from_nanos(ns as u64)
    } else {
        UNIX_EPOCH
    }
}

/// Map a stored entry kind to a FUSE file type.
fn file_type(kind: EntryKind) -> FileType {
    match kind {
        EntryKind::File => FileType::RegularFile,
        EntryKind::Dir => FileType::Directory,
        EntryKind::Symlink => FileType::Symlink,
        EntryKind::Fifo => FileType::NamedPipe,
        EntryKind::Socket => FileType::Socket,
        EntryKind::CharDevice => FileType::CharDevice,
        EntryKind::BlockDevice => FileType::BlockDevice,
    }
}

/// Build the `FileAttr` for a node at inode `ino`.
fn node_attr(node: &Node, ino: u64) -> FileAttr {
    FileAttr {
        ino,
        size: node.size,
        blocks: node.size.div_ceil(512),
        atime: systime(node.mtime_ns),
        mtime: systime(node.mtime_ns),
        ctime: systime(node.ctime_ns),
        crtime: UNIX_EPOCH,
        kind: file_type(node.kind),
        perm: (node.mode & 0o7777) as u16,
        nlink: 1,
        uid: node.uid,
        gid: node.gid,
        rdev: node.rdev as u32,
        blksize: 512,
        flags: 0,
    }
}

/// Flatten an error into an `io::Error`.
fn to_io<E: std::fmt::Display>(e: E) -> io::Error {
    io::Error::other(e.to_string())
}

/// Walk the snapshot's trees, assigning a FUSE inode to every node and returning
/// the resulting inode table (root at [`ROOT`]).
fn build_inodes<B: StorageBackend>(
    rt: &Runtime,
    repo: &Repository<B>,
    snap_id: Id,
) -> io::Result<HashMap<u64, Inode>> {
    let snap = rt.block_on(repo.load_snapshot(&snap_id)).map_err(to_io)?;
    let mut inodes = HashMap::new();
    // The root directory is synthesized from the snapshot (it has no Node).
    inodes.insert(
        ROOT,
        Inode {
            attr: FileAttr {
                ino: ROOT,
                size: 0,
                blocks: 0,
                atime: systime(snap.time_ns),
                mtime: systime(snap.time_ns),
                ctime: systime(snap.time_ns),
                crtime: UNIX_EPOCH,
                kind: FileType::Directory,
                perm: 0o555,
                nlink: 2,
                uid: snap.uid,
                gid: snap.gid,
                rdev: 0,
                blksize: 512,
                flags: 0,
            },
            body: Body::Dir(Vec::new()),
        },
    );
    let mut next = ROOT + 1;
    add_dir(rt, repo, snap.tree, ROOT, &mut inodes, &mut next)?;
    Ok(inodes)
}

/// Load the tree `tree_id`, inserting an inode for each child of directory
/// `dir_ino` and recursing into subdirectories.
fn add_dir<B: StorageBackend>(
    rt: &Runtime,
    repo: &Repository<B>,
    tree_id: Id,
    dir_ino: u64,
    inodes: &mut HashMap<u64, Inode>,
    next: &mut u64,
) -> io::Result<()> {
    let tree = rt.block_on(repo.load_tree(&tree_id)).map_err(to_io)?;
    let mut children = Vec::with_capacity(tree.nodes.len());
    for node in &tree.nodes {
        let ino = *next;
        *next += 1;
        children.push((std::ffi::OsString::from_vec(node.name.clone()), ino));
        let body = match node.kind {
            EntryKind::Dir => Body::Dir(Vec::new()),
            EntryKind::File => Body::File(node.content.clone()),
            EntryKind::Symlink => Body::Link(node.link_target.clone().unwrap_or_default()),
            _ => Body::Other,
        };
        inodes.insert(
            ino,
            Inode {
                attr: node_attr(node, ino),
                body,
            },
        );
        if node.kind == EntryKind::Dir {
            if let Some(sub) = node.subtree {
                add_dir(rt, repo, sub, ino, inodes, next)?;
            }
        }
    }
    if let Some(dir) = inodes.get_mut(&dir_ino) {
        dir.body = Body::Dir(children);
    }
    Ok(())
}

impl<B: StorageBackend> SnapshotFs<B> {
    /// The children of a directory inode, or `None` if it is not a directory.
    fn children(&self, ino: u64) -> Option<&[(std::ffi::OsString, u64)]> {
        match self.inodes.get(&ino)?.body {
            Body::Dir(ref c) => Some(c),
            _ => None,
        }
    }
}

impl<B: StorageBackend> Filesystem for SnapshotFs<B> {
    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let child = self.children(parent).and_then(|c| {
            c.iter()
                .find(|(n, _)| n.as_os_str() == name)
                .map(|(_, i)| *i)
        });
        match child.and_then(|i| self.inodes.get(&i)) {
            Some(inode) => reply.entry(&TTL, &inode.attr, 0),
            None => reply.error(libc::ENOENT),
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        match self.inodes.get(&ino) {
            Some(inode) => reply.attr(&TTL, &inode.attr),
            None => reply.error(libc::ENOENT),
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        match self.inodes.get(&ino).map(|i| &i.body) {
            Some(Body::Link(target)) => reply.data(target),
            _ => reply.error(libc::EINVAL),
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let Some(children) = self.children(ino) else {
            reply.error(libc::ENOTDIR);
            return;
        };
        // "." and ".." first, then the directory's children.
        let mut entries: Vec<(u64, FileType, std::ffi::OsString)> = vec![
            (ino, FileType::Directory, ".".into()),
            (ino, FileType::Directory, "..".into()),
        ];
        for (name, cino) in children {
            let kind = self
                .inodes
                .get(cino)
                .map_or(FileType::RegularFile, |i| i.attr.kind);
            entries.push((*cino, kind, name.clone()));
        }
        for (i, (cino, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            // `add` returns true once the reply buffer is full.
            if reply.add(cino, (i + 1) as i64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let ids = match self.inodes.get(&ino).map(|i| &i.body) {
            Some(Body::File(ids)) => ids.clone(),
            Some(Body::Dir(_)) => {
                reply.error(libc::EISDIR);
                return;
            }
            _ => {
                reply.error(libc::ENOENT);
                return;
            }
        };
        // Reconstruct (and cache) the whole file the first time it is read.
        if self.cached.as_ref().map(|(c, _)| *c) != Some(ino) {
            let mut bytes = Vec::new();
            for id in &ids {
                match self.rt.block_on(self.repo.load_blob(id)) {
                    Ok(chunk) => bytes.extend_from_slice(&chunk),
                    Err(_) => {
                        reply.error(libc::EIO);
                        return;
                    }
                }
            }
            self.cached = Some((ino, bytes));
        }
        let data = &self.cached.as_ref().unwrap().1;
        let start = (offset.max(0) as usize).min(data.len());
        let end = start.saturating_add(size as usize).min(data.len());
        reply.data(&data[start..end]);
    }
}

/// Mount the snapshot `snap_id` of `repo` read-only at `mountpoint`, blocking
/// until the filesystem is unmounted. Builds its own Tokio runtime, so it must
/// be called from a thread with no ambient runtime.
pub fn run_mount<B: StorageBackend + Send + 'static>(
    repo: Repository<B>,
    snap_id: Id,
    mountpoint: &Path,
) -> io::Result<()> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let inodes = build_inodes(&rt, &repo, snap_id)?;
    let fs = SnapshotFs {
        rt,
        repo,
        inodes,
        cached: None,
    };
    let options = [
        MountOption::RO,
        MountOption::FSName("sluice".to_string()),
        MountOption::Subtype("sluice".to_string()),
        MountOption::AutoUnmount,
    ];
    fuser::mount2(fs, mountpoint, &options)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sluice_engine::backup_sources_with_options;
    use sluice_store::MemoryBackend;

    #[test]
    fn inode_table_reflects_the_snapshot() {
        let rt = Runtime::new().unwrap();
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("a.txt"), b"hello world").unwrap();
        std::fs::create_dir(src.path().join("d")).unwrap();
        std::fs::write(src.path().join("d/b.bin"), vec![9u8; 4096]).unwrap();
        std::os::unix::fs::symlink("a.txt", src.path().join("link")).unwrap();

        let (repo, snap) = rt.block_on(async {
            let kdf = sluice_crypto::KdfParams {
                m_cost_kib: 16,
                t_cost: 1,
                p_cost: 1,
            };
            let mut repo = Repository::init(MemoryBackend::new(), b"pw", kdf)
                .await
                .unwrap();
            let outcome = backup_sources_with_options(
                &mut repo,
                &[src.path().to_path_buf()],
                &[],
                &Default::default(),
                None,
            )
            .await
            .unwrap();
            (repo, outcome.snapshot.unwrap())
        });

        let inodes = build_inodes(&rt, &repo, snap).unwrap();

        // The root is a directory listing a.txt, d, and link.
        let root = inodes.get(&ROOT).unwrap();
        let Body::Dir(children) = &root.body else {
            panic!("root must be a directory");
        };
        let names: Vec<&str> = children.iter().map(|(n, _)| n.to_str().unwrap()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"d"));
        assert!(names.contains(&"link"));

        // a.txt is an 11-byte regular file with content chunks.
        let (_, a_ino) = children.iter().find(|(n, _)| n == "a.txt").unwrap();
        let a = inodes.get(a_ino).unwrap();
        assert_eq!(a.attr.kind, FileType::RegularFile);
        assert_eq!(a.attr.size, 11);
        assert!(matches!(&a.body, Body::File(ids) if !ids.is_empty()));

        // The symlink records its target.
        let (_, l_ino) = children.iter().find(|(n, _)| n == "link").unwrap();
        match &inodes.get(l_ino).unwrap().body {
            Body::Link(t) => assert_eq!(t, b"a.txt"),
            _ => panic!("link must be a symlink"),
        }

        // The subdirectory d contains b.bin (4096 bytes).
        let (_, d_ino) = children.iter().find(|(n, _)| n == "d").unwrap();
        let Body::Dir(dchildren) = &inodes.get(d_ino).unwrap().body else {
            panic!("d must be a directory");
        };
        let (_, b_ino) = dchildren.iter().find(|(n, _)| n == "b.bin").unwrap();
        assert_eq!(inodes.get(b_ino).unwrap().attr.size, 4096);
    }
}
