//! `sluice` — command-line interface for the encrypted, deduplicating backup
//! and disaster-recovery tool (see `DESIGN.md` §7).
//!
//! The passphrase comes from the `SLUICE_PASSWORD` environment variable, or an
//! interactive no-echo prompt when a terminal is attached.

use std::error::Error;
use std::path::PathBuf;

use clap::{Parser, Subcommand};
use sluice_core::{EntryKind, Id};
use sluice_crypto::KdfParams;
use sluice_engine::{backup, forget, forget_keep_last, list_files, prune, restore, verify};
use sluice_repo::Repository;
use sluice_store::{LocalBackend, StorageBackend};

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
        /// Path of the repository to create.
        repo: PathBuf,
    },
    /// Back up a directory into the repository.
    Backup {
        /// Path of the repository.
        repo: PathBuf,
        /// Directory to back up.
        source: PathBuf,
    },
    /// Restore a snapshot into a target directory.
    Restore {
        /// Path of the repository.
        repo: PathBuf,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
        /// Directory to restore into.
        target: PathBuf,
    },
    /// List the snapshots in a repository.
    Snapshots {
        /// Path of the repository.
        repo: PathBuf,
    },
    /// Verify the integrity of all snapshots.
    Verify {
        /// Path of the repository.
        repo: PathBuf,
    },
    /// Forget snapshots; reclaim their data later with `prune`.
    Forget {
        /// Path of the repository.
        repo: PathBuf,
        /// Snapshot id to forget (a unique hex prefix is accepted).
        snapshot: Option<String>,
        /// Instead, keep the N most recent snapshots and forget the rest.
        #[arg(long, value_name = "N")]
        keep_last: Option<usize>,
    },
    /// Reclaim storage no longer referenced by any snapshot.
    Prune {
        /// Path of the repository.
        repo: PathBuf,
    },
    /// List the contents of a snapshot without restoring.
    Ls {
        /// Path of the repository.
        repo: PathBuf,
        /// Snapshot id (a unique hex prefix is accepted).
        snapshot: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();
    let confirm = matches!(cli.command, Command::Init { .. });
    let passphrase = read_passphrase(confirm)?;
    let pw = passphrase.as_bytes();

    match cli.command {
        Command::Init { repo } => {
            let backend = LocalBackend::create(&repo).await?;
            let repository = Repository::init(backend, pw, kdf_params()).await?;
            println!(
                "initialized repository {} at {}",
                repository.id(),
                repo.display()
            );
        }
        Command::Backup { repo, source } => {
            let mut repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let snapshot = backup(&mut repository, &source).await?;
            println!("{snapshot}");
        }
        Command::Restore {
            repo,
            snapshot,
            target,
        } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let id = resolve_snapshot(&repository, &snapshot).await?;
            restore(&repository, &id, &target).await?;
            println!("restored {id} into {}", target.display());
        }
        Command::Snapshots { repo } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            for id in repository.list_snapshots().await? {
                let snap = repository.load_snapshot(&id).await?;
                let files = snap.summary.files_new
                    + snap.summary.files_changed
                    + snap.summary.files_unmodified;
                let paths: Vec<String> = snap
                    .paths
                    .iter()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                let hex = id.to_string();
                println!(
                    "{}  {}  {files} files  {}",
                    &hex[..16],
                    format_utc(snap.time_ns),
                    paths.join(", ")
                );
            }
        }
        Command::Verify { repo } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let report = verify(&repository).await?;
            println!(
                "ok: {} snapshots, {} trees, {} blobs verified",
                report.snapshots, report.trees, report.blobs
            );
        }
        Command::Forget {
            repo,
            snapshot,
            keep_last,
        } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            match (snapshot, keep_last) {
                (Some(snapshot), None) => {
                    let id = resolve_snapshot(&repository, &snapshot).await?;
                    forget(&repository, &id).await?;
                    println!("forgot {id}");
                }
                (None, Some(keep)) => {
                    let forgotten = forget_keep_last(&repository, keep).await?;
                    println!("forgot {} snapshot(s)", forgotten.len());
                }
                _ => return Err("specify either a snapshot id or --keep-last N".into()),
            }
        }
        Command::Prune { repo } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
            let removed = prune(&repository).await?;
            println!("pruned {removed} packs");
        }
        Command::Ls { repo, snapshot } => {
            let repository = Repository::open(LocalBackend::open(&repo), pw).await?;
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
    }
    Ok(())
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
