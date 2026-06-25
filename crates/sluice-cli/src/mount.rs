//! `sluice mount` — expose a snapshot as a read-only FUSE filesystem so its
//! files can be browsed and copied without a full restore. Compiled only with
//! the `fuse` feature (which links libfuse); the default build needs no system
//! libraries.
//!
//! The whole directory tree is loaded into an in-memory inode table at mount
//! time (cheap — trees are small); file *contents* are fetched and decrypted
//! lazily on `read`, streaming one chunk at a time with the current chunk cached,
//! so reading even a file larger than memory never holds more than one chunk.

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
    /// Per-file cumulative plaintext chunk offsets, grown lazily as a file is read
    /// (a chunk's decompressed length is only known once it is decoded, so the
    /// table is built on demand). `offsets[ino][i]` is the byte at which chunk `i`
    /// starts; the final element is the size known so far.
    offsets: HashMap<u64, Vec<u64>>,
    /// The single most-recently-decoded chunk `(inode, chunk index, bytes)`, so a
    /// sequential read walks through a chunk without re-fetching it. Bounds peak
    /// memory to one chunk rather than a whole file.
    chunk: Option<(u64, usize, Vec<u8>)>,
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
        // Take the per-inode offset table and single-chunk cache out of `self`
        // for the duration of the read (disjoint from the `rt`/`repo` borrows the
        // helper needs), then put the grown state back.
        let mut table = self.offsets.remove(&ino).unwrap_or_else(|| vec![0]);
        let mut cache = match self.chunk.take() {
            Some((cino, idx, bytes)) if cino == ino => Some((idx, bytes)),
            _ => None,
        };
        let result = read_file_range(
            &self.rt,
            &self.repo,
            &ids,
            &mut table,
            &mut cache,
            offset.max(0) as u64,
            size as usize,
        );
        self.offsets.insert(ino, table);
        self.chunk = cache.map(|(idx, bytes)| (ino, idx, bytes));
        match result {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(libc::EIO),
        }
    }
}

/// Read up to `size` bytes at `offset` from the file whose ordered chunks are
/// `ids`, loading only the chunks that overlap the requested range. `table` is
/// the file's growing cumulative-offset table (`table[i]` = start of chunk `i`,
/// last element = size known so far) and `cache` holds the most recently decoded
/// chunk, so a sequential read fetches each chunk once and never holds more than
/// one chunk in memory. Reads past end-of-file return the available bytes.
fn read_file_range<B: StorageBackend>(
    rt: &Runtime,
    repo: &Repository<B>,
    ids: &[Id],
    table: &mut Vec<u64>,
    cache: &mut Option<(usize, Vec<u8>)>,
    offset: u64,
    size: usize,
) -> io::Result<Vec<u8>> {
    let want_end = offset.saturating_add(size as u64);
    // Grow the offset table until it reaches the end of the request (or the whole
    // file), decoding one chunk at a time and keeping the last one.
    while table.len() - 1 < ids.len() && *table.last().unwrap() < want_end {
        let idx = table.len() - 1;
        let bytes = rt.block_on(repo.load_blob(&ids[idx])).map_err(to_io)?;
        let start = *table.last().unwrap();
        table.push(start + bytes.len() as u64);
        *cache = Some((idx, bytes));
    }
    let total = *table.last().unwrap();
    let end = want_end.min(total);
    let mut out = Vec::new();
    if offset >= end {
        return Ok(out);
    }
    // The first chunk overlapping `offset` is the largest `i` with `table[i] <= offset`.
    let mut idx = table.partition_point(|&o| o <= offset).saturating_sub(1);
    while idx < ids.len() {
        let cstart = table[idx];
        if cstart >= end {
            break;
        }
        let cend = table[idx + 1];
        if cend > offset {
            if cache.as_ref().map(|(i, _)| *i) != Some(idx) {
                let bytes = rt.block_on(repo.load_blob(&ids[idx])).map_err(to_io)?;
                *cache = Some((idx, bytes));
            }
            let bytes = &cache.as_ref().unwrap().1;
            let lo = (offset.max(cstart) - cstart) as usize;
            let hi = (end.min(cend) - cstart) as usize;
            out.extend_from_slice(&bytes[lo..hi]);
        }
        idx += 1;
    }
    Ok(out)
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
        offsets: HashMap::new(),
        chunk: None,
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

    #[test]
    fn read_file_range_matches_at_any_offset() {
        let rt = Runtime::new().unwrap();
        // ~3 MiB of incompressible data, so it spans several chunks.
        let mut data = vec![0u8; 3 * 1024 * 1024];
        let mut x = 0x9e37_79b9u32;
        for b in data.iter_mut() {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            *b = (x >> 24) as u8;
        }
        let src = tempfile::tempdir().unwrap();
        std::fs::write(src.path().join("big.bin"), &data).unwrap();

        let (repo, ids) = rt.block_on(async {
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
            let snap = repo
                .load_snapshot(&outcome.snapshot.unwrap())
                .await
                .unwrap();
            let tree = repo.load_tree(&snap.tree).await.unwrap();
            let node = tree.nodes.iter().find(|n| n.name == b"big.bin").unwrap();
            (repo, node.content.clone())
        });
        assert!(ids.len() > 1, "the test file must span multiple chunks");

        // A full read reconstructs the file exactly.
        let mut table = vec![0u64];
        let mut cache = None;
        let whole =
            read_file_range(&rt, &repo, &ids, &mut table, &mut cache, 0, data.len()).unwrap();
        assert_eq!(whole, data);

        // An arbitrary mid-file range that crosses chunk boundaries (fresh state).
        let mut t2 = vec![0u64];
        let mut c2 = None;
        let mid =
            read_file_range(&rt, &repo, &ids, &mut t2, &mut c2, 1_000_000, 1_500_000).unwrap();
        assert_eq!(mid, &data[1_000_000..2_500_000]);

        // Sequential 128 KiB reads reusing the grown table/cache cover the file.
        let mut t3 = vec![0u64];
        let mut c3 = None;
        let step = 128 * 1024;
        for off in (0..data.len()).step_by(step) {
            let n = step.min(data.len() - off);
            let got = read_file_range(&rt, &repo, &ids, &mut t3, &mut c3, off as u64, n).unwrap();
            assert_eq!(got, &data[off..off + n], "mismatch at offset {off}");
        }

        // A read past end-of-file yields nothing; a read straddling EOF is clamped.
        let past =
            read_file_range(&rt, &repo, &ids, &mut t3, &mut c3, data.len() as u64, 100).unwrap();
        assert!(past.is_empty());
        let tail = read_file_range(
            &rt,
            &repo,
            &ids,
            &mut t3,
            &mut c3,
            data.len() as u64 - 10,
            999,
        )
        .unwrap();
        assert_eq!(tail, &data[data.len() - 10..]);
    }
}
