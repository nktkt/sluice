//! `sluice` — command-line interface for the encrypted, deduplicating backup
//! and disaster-recovery tool (see `DESIGN.md` §7).
//!
//! The passphrase comes from the `SLUICE_PASSWORD` environment variable, or an
//! interactive no-echo prompt when a terminal is attached. A repository is a
//! local path or an object-store URL such as `s3://bucket/prefix`.

use std::collections::HashSet;
use std::error::Error;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sluice_core::{EntryKind, Id};
use sluice_crypto::KdfParams;
use sluice_engine::{
    DiffKind, EngineError, RetentionPolicy, backup_dry_run, backup_excluding, check, diff, dump,
    forget, forget_tagged, forget_with_policy, list_files, prune, prune_excluding, rebuild_index,
    restore_subpath, verify,
};
use sluice_repo::{RepoError, Repository};
use sluice_store::{FileType, LocalBackend, ObjectStoreBackend, StorageBackend};

/// Encrypted, deduplicating backup & disaster-recovery tool.
#[derive(Parser)]
#[command(name = "sluice", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Initialize a new encrypted repository.
    Init {
        /// Repository path or object-store URL (e.g. s3://bucket/prefix).
        repo: String,
    },
    /// Back up a directory into the repository.
    Backup {
        /// Repository path or object-store URL.
        repo: String,
        /// Directory to back up.
        source: PathBuf,
        /// Glob of entry names to exclude (repeatable), e.g. --exclude '*.log'.
        #[arg(long = "exclude", value_name = "GLOB")]
        excludes: Vec<String>,
        /// Tag to attach to the snapshot (repeatable).
        #[arg(long = "tag", value_name = "TAG")]
        tags: Vec<String>,
        /// Report what would be backed up without writing anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Restore a snapshot into a target directory.
    Restore {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Directory to restore into.
        target: PathBuf,
        /// Restore only this path within the snapshot.
        #[arg(long)]
        path: Option<String>,
    },
    /// List the snapshots in a repository.
    Snapshots {
        /// Repository path or object-store URL.
        repo: String,
        /// Only show snapshots with this tag.
        #[arg(long)]
        tag: Option<String>,
    },
    /// Verify the integrity of all snapshots.
    Verify {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Check structural integrity without reading file data (fast).
    Check {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Forget snapshots; reclaim their data later with `prune`.
    Forget {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id to forget (a unique hex prefix is accepted).
        snapshot: Option<String>,
        /// Keep the N most recent snapshots (combinable with the other --keep rules).
        #[arg(long, value_name = "N")]
        keep_last: Option<usize>,
        /// Keep the most recent snapshot of each of the last N days.
        #[arg(long, value_name = "N")]
        keep_daily: Option<usize>,
        /// Keep the most recent snapshot of each of the last N (Monday-aligned) weeks.
        #[arg(long, value_name = "N")]
        keep_weekly: Option<usize>,
        /// Keep the most recent snapshot of each of the last N calendar months.
        #[arg(long, value_name = "N")]
        keep_monthly: Option<usize>,
        /// Keep the most recent snapshot of each of the last N calendar years.
        #[arg(long, value_name = "N")]
        keep_yearly: Option<usize>,
        /// Instead, forget every snapshot with this tag.
        #[arg(long, value_name = "TAG")]
        tag: Option<String>,
        /// Show which snapshots would be forgotten without removing them.
        #[arg(long)]
        dry_run: bool,
        /// After forgetting, run prune to reclaim the freed storage.
        #[arg(long)]
        prune: bool,
    },
    /// Reclaim storage no longer referenced by any snapshot.
    Prune {
        /// Repository path or object-store URL.
        repo: String,
        /// Show what would be reclaimed without deleting anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// List the contents of a snapshot without restoring.
    Ls {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
    },
    /// Show the changes between two snapshots.
    Diff {
        /// Repository path or object-store URL.
        repo: String,
        /// The older snapshot id (a unique hex prefix is accepted).
        from: String,
        /// The newer snapshot id (a unique hex prefix is accepted).
        to: String,
    },
    /// Write a single file from a snapshot to stdout.
    Dump {
        /// Repository path or object-store URL.
        repo: String,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Path of the file within the snapshot.
        path: String,
    },
    /// Show repository metadata.
    Info {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Show repository storage statistics.
    Stats {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Remove advisory locks left behind by an interrupted operation.
    Unlock {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Rebuild index segments by rescanning packs (repairs a damaged index).
    RebuildIndex {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Manage the passphrases (keys) that unlock the repository.
    Key {
        #[command(subcommand)]
        action: KeyCmd,
    },
}

/// Sub-commands of `key`.
#[derive(Subcommand)]
enum KeyCmd {
    /// List the repository's keys.
    List {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Add a passphrase (read from SLUICE_NEW_PASSWORD or prompted).
    Add {
        /// Repository path or object-store URL.
        repo: String,
    },
    /// Remove a key by id (refused if it is the last key).
    Remove {
        /// Repository path or object-store URL.
        repo: String,
        /// The key id to remove (as shown by `key list`).
        id: String,
    },
    /// Change the current passphrase, rotating out its key.
    Passwd {
        /// Repository path or object-store URL.
        repo: String,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("error: {error}");
        std::process::exit(exit_code(error.as_ref()));
    }
}

/// Map an error to a stable, documented exit code (`DESIGN.md` §7): 10 repo not
/// found, 11 wrong passphrase, 12 lock held, 13 corruption detected, else 1.
fn exit_code(error: &(dyn Error + 'static)) -> i32 {
    fn repo_code(e: &RepoError) -> i32 {
        match e {
            RepoError::NotFound => 10,
            RepoError::Key(_) => 11,
            RepoError::Locked => 12,
            RepoError::Blob | RepoError::BlobNotFound(_) => 13,
            _ => 1,
        }
    }
    // A repository error may be the error itself, wrapped in an EngineError, or
    // further down the source chain.
    let mut current: Option<&(dyn Error + 'static)> = Some(error);
    while let Some(err) = current {
        if let Some(e) = err.downcast_ref::<RepoError>() {
            return repo_code(e);
        }
        if let Some(EngineError::Repo(e)) = err.downcast_ref::<EngineError>() {
            return repo_code(e);
        }
        current = err.source();
    }
    1
}

#[tokio::main]
async fn run() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let confirm = matches!(cli.command, Command::Init { .. });
    let passphrase = read_passphrase(confirm)?;
    let pw = passphrase.as_bytes();

    match cli.command {
        Command::Init { repo } => {
            let repository =
                Repository::init(backend(&repo, true).await?, pw, kdf_params()).await?;
            println!("initialized repository {} at {repo}", repository.id());
        }
        Command::Backup {
            repo,
            source,
            excludes,
            tags,
            dry_run,
        } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            if dry_run {
                let s = backup_dry_run(&mut repository, &source, &excludes).await?;
                println!(
                    "dry run: {} new, {} changed, {} unmodified, {} dirs, {} bytes (nothing written)",
                    s.files_new, s.files_changed, s.files_unmodified, s.dirs, s.bytes_processed
                );
            } else {
                let snapshot = backup_excluding(&mut repository, &source, &excludes, &tags).await?;
                println!("{snapshot}");
                let s = repository.load_snapshot(&snapshot).await?.summary;
                eprintln!(
                    "  {} new, {} changed, {} unmodified, {} dirs, {} bytes",
                    s.files_new, s.files_changed, s.files_unmodified, s.dirs, s.bytes_processed
                );
            }
        }
        Command::Restore {
            repo,
            snapshot,
            target,
            path,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            restore_subpath(&repository, &id, path.as_deref(), &target).await?;
            println!("restored {id} into {}", target.display());
        }
        Command::Snapshots { repo, tag } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            for id in repository.list_snapshots().await? {
                let snap = repository.load_snapshot(&id).await?;
                if let Some(tag) = &tag {
                    if !snap.tags.iter().any(|t| t == tag) {
                        continue;
                    }
                }
                let files = snap.summary.files_new
                    + snap.summary.files_changed
                    + snap.summary.files_unmodified;
                let paths: Vec<String> = snap
                    .paths
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                let hex = id.to_string();
                let tags = if snap.tags.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", snap.tags.join(","))
                };
                println!(
                    "{}  {}  {files} files  {}{tags}",
                    &hex[..16],
                    format_utc(snap.time_ns),
                    paths.join(", ")
                );
            }
        }
        Command::Verify { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let report = verify(&repository).await?;
            println!(
                "ok: {} snapshots, {} trees, {} blobs verified",
                report.snapshots, report.trees, report.blobs
            );
        }
        Command::Check { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let report = check(&repository).await?;
            if report.missing.is_empty() {
                println!(
                    "ok: {} snapshots, {} trees, {} blobs referenced",
                    report.snapshots, report.trees, report.blobs
                );
            } else {
                eprintln!(
                    "FAILED: {} of {} referenced blobs missing",
                    report.missing.len(),
                    report.blobs
                );
                for id in &report.missing {
                    eprintln!("  missing {id}");
                }
                return Err("structural integrity check failed".into());
            }
        }
        Command::Forget {
            repo,
            snapshot,
            keep_last,
            keep_daily,
            keep_weekly,
            keep_monthly,
            keep_yearly,
            tag,
            dry_run,
            prune: do_prune,
        } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let policy = RetentionPolicy {
                last: keep_last.unwrap_or(0),
                daily: keep_daily.unwrap_or(0),
                weekly: keep_weekly.unwrap_or(0),
                monthly: keep_monthly.unwrap_or(0),
                yearly: keep_yearly.unwrap_or(0),
            };
            let verb = if dry_run { "would forget" } else { "forgot" };
            let forgotten: Vec<Id> = match (snapshot, tag, policy.is_empty()) {
                (Some(snapshot), None, true) => {
                    let id = resolve_snapshot(&repository, &snapshot).await?;
                    if !dry_run {
                        forget(&repository, &id).await?;
                    }
                    println!("{verb} {id}");
                    vec![id]
                }
                (None, Some(tag), true) => {
                    let forgotten = forget_tagged(&repository, &tag, dry_run).await?;
                    println!("{verb} {} snapshot(s)", forgotten.len());
                    forgotten
                }
                (None, None, false) => {
                    let forgotten = forget_with_policy(&repository, policy, dry_run).await?;
                    println!("{verb} {} snapshot(s)", forgotten.len());
                    forgotten
                }
                _ => {
                    return Err(
                        "specify exactly one of: <snapshot>, --tag T, or one or more \
                         --keep-last/-daily/-weekly/-monthly/-yearly rules"
                            .into(),
                    );
                }
            };
            if do_prune {
                // Under --dry-run the snapshots are still present, so treat the
                // would-be-forgotten ones as excluded to preview the reclamation.
                let report = if dry_run {
                    let excluded: HashSet<Id> = forgotten.into_iter().collect();
                    prune_excluding(&mut repository, true, &excluded).await?
                } else {
                    prune(&mut repository, false).await?
                };
                let pverb = if dry_run {
                    "would reclaim"
                } else {
                    "reclaimed"
                };
                println!(
                    "{pverb} {} bytes ({} packs deleted, {} repacked)",
                    report.reclaimed_bytes, report.deleted, report.repacked
                );
            }
        }
        Command::Prune { repo, dry_run } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let report = prune(&mut repository, dry_run).await?;
            let verb = if dry_run { "would prune" } else { "pruned" };
            println!(
                "{verb} {} packs, {} repacked ({} bytes reclaimed)",
                report.deleted, report.repacked, report.reclaimed_bytes
            );
        }
        Command::Ls { repo, snapshot } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            for entry in list_files(&repository, &id).await? {
                let tag = match entry.kind {
                    EntryKind::Dir => "d",
                    EntryKind::Symlink => "l",
                    _ => "-",
                };
                println!("{tag} {:>12} {}", entry.size, entry.path);
            }
        }
        Command::Diff { repo, from, to } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let a = resolve_snapshot(&repository, &from).await?;
            let b = resolve_snapshot(&repository, &to).await?;
            for change in diff(&repository, &a, &b).await? {
                let sign = match change.change {
                    DiffKind::Added => '+',
                    DiffKind::Removed => '-',
                    DiffKind::Modified => 'M',
                };
                println!("{sign} {}", change.path);
            }
        }
        Command::Dump {
            repo,
            snapshot,
            path,
        } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            let data = dump(&repository, &id, &path).await?;
            use std::io::Write;
            std::io::stdout().write_all(&data)?;
        }
        Command::Info { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let config = repository.config();
            let snapshots = repository.list_snapshots().await?.len();
            println!("repository:  {}", repository.id());
            println!("created:     {}", format_utc(config.created_ns));
            println!("cipher:      {:?}", config.cipher);
            println!(
                "chunker:     min {} / avg {} / max {} bytes",
                config.chunker.min, config.chunker.avg, config.chunker.max
            );
            println!("pack target: {} bytes", config.pack_target);
            println!("snapshots:   {snapshots}");
        }
        Command::Stats { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let pack_ids = repository.backend().list(FileType::Pack).await?;
            let mut stored = 0u64;
            for pid in &pack_ids {
                stored += repository.backend().size(FileType::Pack, pid).await?;
            }
            let snapshots = repository.list_snapshots().await?;
            let mut logical = 0u64;
            for id in &snapshots {
                logical += repository.load_snapshot(id).await?.summary.bytes_processed;
            }
            let saved = if logical > 0 && stored < logical {
                (logical - stored) * 100 / logical
            } else {
                0
            };
            println!("snapshots:     {}", snapshots.len());
            println!("packs:         {}", pack_ids.len());
            println!("logical bytes: {logical}");
            println!("stored bytes:  {stored}");
            println!("saved:         {saved}% (dedup + compression)");
        }
        Command::Unlock { repo } => {
            let repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let locks = repository.list_locks().await?;
            for (id, _) in &locks {
                repository.release_lock(id).await?;
            }
            println!("removed {} lock(s)", locks.len());
        }
        Command::RebuildIndex { repo } => {
            let mut repository = Repository::open(backend(&repo, false).await?, pw).await?;
            let n = rebuild_index(&mut repository).await?;
            println!("rebuilt index for {n} pack(s)");
        }
        Command::Key { action } => match action {
            KeyCmd::List { repo } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let keys = repository.list_keys().await?;
                println!("{} key(s):", keys.len());
                for id in &keys {
                    println!("  {id}");
                }
            }
            KeyCmd::Add { repo } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .add_key(new_pass.as_bytes(), kdf_params())
                    .await?;
                println!("added key {id}");
            }
            KeyCmd::Remove { repo, id } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let key_id: Id = id.parse().map_err(|_| "invalid key id")?;
                repository.remove_key(&key_id).await?;
                println!("removed key {key_id}");
            }
            KeyCmd::Passwd { repo } => {
                let repository = Repository::open(backend(&repo, false).await?, pw).await?;
                let new_pass = read_new_passphrase()?;
                let id = repository
                    .change_passphrase(new_pass.as_bytes(), kdf_params())
                    .await?;
                println!("changed passphrase; new key {id}");
            }
        },
    }
    Ok(())
}

/// Open (or, when `create`, create) the storage backend for `repo` — a local
/// path or an object-store URL such as `s3://bucket/prefix`.
async fn backend(repo: &str, create: bool) -> Result<Arc<dyn StorageBackend>, Box<dyn Error>> {
    if repo.contains("://") {
        let url = url::Url::parse(repo)?;
        let (store, prefix) = object_store::parse_url(&url)?;
        Ok(Arc::new(ObjectStoreBackend::with_prefix(
            Arc::from(store),
            prefix,
        )))
    } else if create {
        Ok(Arc::new(LocalBackend::create(repo).await?))
    } else {
        Ok(Arc::new(LocalBackend::open(repo)))
    }
}

/// Resolve a full id or a unique hex prefix to a snapshot id.
async fn resolve_snapshot<B: StorageBackend>(
    repo: &Repository<B>,
    needle: &str,
) -> Result<Id, Box<dyn Error>> {
    if let Ok(id) = needle.parse::<Id>() {
        return Ok(id);
    }
    let matches: Vec<Id> = repo
        .list_snapshots()
        .await?
        .into_iter()
        .filter(|id| id.to_string().starts_with(needle))
        .collect();
    match matches.as_slice() {
        [id] => Ok(*id),
        [] => Err(format!("no snapshot matches '{needle}'").into()),
        _ => Err(format!("ambiguous snapshot prefix '{needle}'").into()),
    }
}

/// Argon2id parameters for `init`, tunable via the environment for power users
/// and tests (`SLUICE_KDF_MEMORY_KIB`, `SLUICE_KDF_PASSES`); defaults otherwise.
fn kdf_params() -> KdfParams {
    let mut params = KdfParams::DEFAULT;
    if let Some(memory) = std::env::var("SLUICE_KDF_MEMORY_KIB")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        params.m_cost_kib = memory;
    }
    if let Some(passes) = std::env::var("SLUICE_KDF_PASSES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        params.t_cost = passes;
    }
    params
}

/// Read the passphrase from `SLUICE_PASSWORD`, or prompt with no echo when a
/// terminal is attached. With `confirm` set (for `init`), it is entered twice.
fn read_passphrase(confirm: bool) -> Result<String, Box<dyn Error>> {
    use std::io::IsTerminal;
    if let Ok(passphrase) = std::env::var("SLUICE_PASSWORD") {
        return Ok(passphrase);
    }
    if !std::io::stdin().is_terminal() {
        return Err("no passphrase: set SLUICE_PASSWORD or run in a terminal".into());
    }
    let passphrase = rpassword::prompt_password("Passphrase: ")?;
    if confirm && passphrase != rpassword::prompt_password("Confirm passphrase: ")? {
        return Err("passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Read the *new* passphrase for `key add` from `SLUICE_NEW_PASSWORD` or, on a
/// terminal, a confirmed prompt.
fn read_new_passphrase() -> Result<String, Box<dyn Error>> {
    use std::io::IsTerminal;
    if let Ok(passphrase) = std::env::var("SLUICE_NEW_PASSWORD") {
        return Ok(passphrase);
    }
    if !std::io::stdin().is_terminal() {
        return Err("no new passphrase: set SLUICE_NEW_PASSWORD or run in a terminal".into());
    }
    let passphrase = rpassword::prompt_password("New passphrase: ")?;
    if passphrase != rpassword::prompt_password("Confirm new passphrase: ")? {
        return Err("passphrases do not match".into());
    }
    Ok(passphrase)
}

/// Format epoch-nanoseconds as `YYYY-MM-DD HH:MM:SS UTC` (no dependencies).
fn format_utc(ns: i64) -> String {
    let secs = ns.div_euclid(1_000_000_000);
    let days = secs.div_euclid(86_400);
    let tod = secs.rem_euclid(86_400);
    let (hour, minute, second) = (tod / 3600, (tod % 3600) / 60, tod % 60);

    // civil_from_days (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

#[cfg(test)]
mod tests {
    use super::format_utc;

    #[test]
    fn formats_epoch_in_utc() {
        assert_eq!(format_utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(
            format_utc(1_700_000_000 * 1_000_000_000),
            "2023-11-14 22:13:20 UTC"
        );
    }
}
