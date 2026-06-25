//! End-to-end integration tests driving the built `sluice` binary.

use assert_cmd::Command;
use predicates::prelude::*;

/// A `sluice` command pre-seeded with a passphrase.
fn sluice() -> Command {
    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env("SLUICE_PASSWORD", "integration-pw")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1");
    cmd
}

#[test]
fn init_backup_snapshots_verify_restore_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("nested")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha content").unwrap();
    std::fs::write(src.join("nested/b.bin"), vec![3u8; 4096]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();

    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snapshot = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    assert_eq!(snapshot.len(), 64, "expected a 64-hex snapshot id");

    sluice()
        .arg("snapshots")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains(&snapshot[..12]));

    sluice()
        .arg("verify")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("blobs verified"));

    // Restore by a unique hex prefix.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snapshot[..12])
        .arg(&out)
        .assert()
        .success();

    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha content");
    assert_eq!(
        std::fs::read(out.join("nested/b.bin")).unwrap(),
        vec![3u8; 4096]
    );
}

#[test]
fn backup_emits_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"one").unwrap();
    std::fs::write(src.join("b.txt"), b"two").unwrap();
    sluice().arg("init").arg(&repo).assert().success();

    let out = sluice()
        .args(["backup"])
        .arg(&repo)
        .arg(&src)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(v["files_new"], 2);
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["bytes"], 6);
    assert_eq!(v["snapshot"].as_str().unwrap().len(), 64);

    // A dry-run reports a null snapshot, and the unchanged files as unmodified.
    let out = sluice()
        .args(["backup"])
        .arg(&repo)
        .arg(&src)
        .args(["--json", "--dry-run"])
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert!(v["snapshot"].is_null());
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["files_unmodified"], 2);
}

#[test]
fn verify_and_check_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha unique").unwrap();
    std::fs::write(src.join("b.txt"), b"bravo unique").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // Full verify: ok, two distinct blobs, nothing sampled.
    let out = sluice()
        .arg("verify")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["snapshots"], 1);
    assert_eq!(v["blobs"], 2);
    assert_eq!(v["total_blobs"], 2);
    assert_eq!(v["sampled"], false);

    // A 50% sample reads one of the two blobs and reports it as sampled.
    let out = sluice()
        .args(["verify", "--sample", "50", "--json"])
        .arg(&repo)
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(v["blobs"], 1, "ceil(2 * 50/100) == 1");
    assert_eq!(v["total_blobs"], 2);
    assert_eq!(v["sampled"], true);

    // Check: ok with no missing blobs.
    let out = sluice()
        .arg("check")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(v["ok"], true);
    assert_eq!(v["snapshots"], 1);
    assert!(v["missing"].as_array().unwrap().is_empty());
}

#[test]
fn check_reports_missing_blobs_and_exits_13() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    // ~20 MiB of incompressible data so the content spills past the 16 MiB pack
    // target into a second pack: the first (full) pack holds only content, while
    // the tree and snapshot land in the smaller final pack.
    let mut data = vec![0u8; 20 * 1024 * 1024];
    let mut x: u32 = 0x1234_5678; // a deterministic LCG fill that defeats zstd
    for b in data.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    std::fs::write(src.join("big.bin"), &data).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // Drop the largest pack (the content-only one) and its index segment, leaving
    // the tree intact, so its referenced content blobs become missing.
    let mut packs: Vec<_> = std::fs::read_dir(repo.join("data"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    assert!(packs.len() >= 2, "20 MiB should span at least two packs");
    packs.sort_by_key(|p| std::fs::metadata(p).unwrap().len());
    let biggest = packs.last().unwrap();
    let id = biggest.file_name().unwrap().to_owned();
    std::fs::remove_file(biggest).unwrap();
    let _ = std::fs::remove_file(repo.join("index").join(&id));

    // Non-JSON check exits 13 (corruption, DESIGN.md §7).
    sluice()
        .arg("check")
        .arg(&repo)
        .assert()
        .code(13)
        .stderr(predicate::str::contains("missing"));

    // JSON check also exits 13 and reports ok:false with a non-empty missing list.
    let out = sluice()
        .arg("check")
        .arg(&repo)
        .arg("--json")
        .assert()
        .code(13);
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    assert_eq!(v["ok"], false);
    assert!(!v["missing"].as_array().unwrap().is_empty());
}

#[test]
fn key_list_marks_the_active_key() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();

    // Add a second passphrase (read from SLUICE_NEW_PASSWORD).
    sluice()
        .env("SLUICE_NEW_PASSWORD", "second-pass")
        .arg("key")
        .arg("add")
        .arg(&repo)
        .assert()
        .success();

    // JSON list: two keys, exactly one flagged active.
    let out = sluice()
        .arg("key")
        .arg("list")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 2, "init key plus the added one");
    let active: Vec<_> = arr.iter().filter(|k| k["active"] == true).collect();
    assert_eq!(active.len(), 1, "exactly one key is active");

    // The human listing marks it.
    sluice()
        .arg("key")
        .arg("list")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("(active)"));
}

#[test]
fn completions_generate_without_a_passphrase() {
    // No SLUICE_PASSWORD set: completion generation must not prompt or require it.
    let out = Command::cargo_bin("sluice")
        .unwrap()
        .args(["completions", "bash"])
        .assert()
        .success();
    let script = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    assert!(
        script.contains("sluice"),
        "the bash completion script names the binary"
    );

    // Another supported shell also works.
    Command::cargo_bin("sluice")
        .unwrap()
        .args(["completions", "zsh"])
        .assert()
        .success();

    // An unknown shell is rejected by the argument parser.
    Command::cargo_bin("sluice")
        .unwrap()
        .args(["completions", "nonsense-shell"])
        .assert()
        .failure();
}

#[test]
fn man_pages_are_written_without_a_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    // No SLUICE_PASSWORD set: man-page generation must not require it.
    Command::cargo_bin("sluice")
        .unwrap()
        .arg("man")
        .arg(dir.path())
        .assert()
        .success();

    let top = std::fs::read_to_string(dir.path().join("sluice.1")).unwrap();
    assert!(top.contains(".TH"), "sluice.1 is a troff man page");
    assert!(top.to_lowercase().contains("sluice"));
    // A page is written per subcommand.
    assert!(dir.path().join("sluice-backup.1").exists());
    assert!(dir.path().join("sluice-restore.1").exists());
}

#[test]
fn snapshots_filter_by_host_and_path() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    std::fs::write(a.join("x"), b"x").unwrap();
    std::fs::write(b.join("y"), b"y").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    // Two snapshots: different host names, different source paths.
    sluice()
        .env("HOSTNAME", "host-one")
        .args(["backup"])
        .arg(&repo)
        .arg(&a)
        .assert()
        .success();
    sluice()
        .env("HOSTNAME", "host-two")
        .args(["backup"])
        .arg(&repo)
        .arg(&b)
        .assert()
        .success();

    let json = |cmd: assert_cmd::assert::Assert| -> serde_json::Value {
        serde_json::from_slice(&cmd.get_output().stdout).unwrap()
    };

    // --host keeps only the matching snapshot.
    let v = json(
        sluice()
            .args(["snapshots"])
            .arg(&repo)
            .args(["--host", "host-one", "--json"])
            .assert()
            .success(),
    );
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["hostname"], "host-one");

    // --path keeps only the snapshot that backed up that source path.
    let v = json(
        sluice()
            .args(["snapshots"])
            .arg(&repo)
            .arg("--path")
            .arg(&b)
            .arg("--json")
            .assert()
            .success(),
    );
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["hostname"], "host-two");

    // A non-matching host yields an empty list.
    let v = json(
        sluice()
            .args(["snapshots"])
            .arg(&repo)
            .args(["--host", "nobody", "--json"])
            .assert()
            .success(),
    );
    assert!(v.as_array().unwrap().is_empty());
}

#[test]
fn full_lifecycle_backup_copy_forget_prune_restore() {
    let json = |a: assert_cmd::assert::Assert| -> serde_json::Value {
        serde_json::from_slice(&a.get_output().stdout).unwrap()
    };
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let repo2 = dir.path().join("repo2");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::write(src.join("docs/a.txt"), b"version one").unwrap();
    std::fs::write(src.join("keep.bin"), vec![5u8; 4096]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice().arg("init").arg(&repo2).assert().success();

    // First snapshot, then change/add files and take a second.
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    std::fs::write(src.join("docs/a.txt"), b"version two is longer").unwrap();
    std::fs::write(src.join("new.txt"), b"added later").unwrap();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    let snaps = json(
        sluice()
            .args(["snapshots"])
            .arg(&repo)
            .arg("--json")
            .assert()
            .success(),
    );
    let arr = snaps.as_array().unwrap();
    assert_eq!(arr.len(), 2, "two snapshots (chronological)");
    let snap1 = arr[0]["id"].as_str().unwrap().to_string();
    let snap2 = arr[1]["id"].as_str().unwrap().to_string();

    // Replicate everything to a second repository (re-encrypted under its keys).
    sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&repo2)
        .assert()
        .success();

    // Forget the old snapshot in the source and reclaim its space.
    sluice()
        .arg("forget")
        .arg(&repo)
        .arg(&snap1[..12])
        .assert()
        .success();
    sluice().arg("prune").arg(&repo).assert().success();
    sluice().arg("verify").arg(&repo).assert().success();

    // The surviving snapshot still restores byte-identical from the pruned repo.
    let out = dir.path().join("out");
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap2[..12])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(out.join("docs/a.txt")).unwrap(),
        b"version two is longer"
    );
    assert_eq!(std::fs::read(out.join("new.txt")).unwrap(), b"added later");
    assert_eq!(
        std::fs::read(out.join("keep.bin")).unwrap(),
        vec![5u8; 4096]
    );

    // The copy kept BOTH snapshots; its oldest still restores the original v1
    // state — recovering a version that was pruned from the source.
    let snaps2 = json(
        sluice()
            .args(["snapshots"])
            .arg(&repo2)
            .arg("--json")
            .assert()
            .success(),
    );
    let arr2 = snaps2.as_array().unwrap();
    assert_eq!(arr2.len(), 2, "the copy retains both snapshots");
    let old_in_copy = arr2[0]["id"].as_str().unwrap();
    let out1 = dir.path().join("out1");
    sluice()
        .arg("restore")
        .arg(&repo2)
        .arg(&old_in_copy[..12])
        .arg(&out1)
        .assert()
        .success();
    assert_eq!(
        std::fs::read(out1.join("docs/a.txt")).unwrap(),
        b"version one"
    );
    assert!(!out1.join("new.txt").exists());
    sluice().arg("verify").arg(&repo2).assert().success();
}

#[test]
fn wrong_password_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();

    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env("SLUICE_PASSWORD", "the-wrong-password");
    // Exit code 11 = wrong passphrase (DESIGN.md §7).
    cmd.arg("snapshots").arg(&repo).assert().code(11);
}

#[test]
fn opening_a_missing_repo_exits_10() {
    let dir = tempfile::tempdir().unwrap();
    // No init: the location holds no repository -> exit code 10 (not found).
    sluice()
        .arg("snapshots")
        .arg(dir.path().join("nope"))
        .assert()
        .code(10);
}

#[test]
fn prune_exits_12_when_a_lock_is_held() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();

    // Inject an advisory lock: a CBOR LockInfo { exclusive: false, hostname:
    // "x", time_ns: 0 } at a valid 64-hex object id.
    let lock = [
        &[0xa3u8, 0x69][..],
        b"exclusive",
        &[0xf4, 0x68],
        b"hostname",
        &[0x61],
        b"x",
        &[0x67],
        b"time_ns",
        &[0x00],
    ]
    .concat();
    std::fs::write(repo.join("locks").join("aa".repeat(32)), lock).unwrap();

    // Exit code 12 = lock held (DESIGN.md §7).
    sluice().arg("prune").arg(&repo).assert().code(12);
}

#[test]
fn init_refuses_to_overwrite_an_existing_repo() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"precious").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let snap = String::from_utf8(
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    // Re-initializing the same location is refused with a clear message, never
    // clobbering the existing config and keys.
    sluice()
        .arg("init")
        .arg(&repo)
        .assert()
        .failure()
        .stderr(predicate::str::contains("already exists"))
        .stderr(predicate::str::contains("refusing to overwrite"));

    // The original snapshot is untouched and still restores.
    let out = dir.path().join("out");
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("f")).unwrap(), b"precious");
}

#[test]
fn nonexistent_full_snapshot_id_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // A syntactically valid but absent 64-hex id gets the same clear "no snapshot
    // matches" as a bad prefix, not a cryptic downstream error.
    let absent = "0".repeat(64);
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&absent)
        .arg(dir.path().join("out"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("no snapshot matches"));
}

#[test]
fn ambiguous_snapshot_prefix_lists_candidates() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let mut ids = Vec::new();
    for v in ["one", "two"] {
        std::fs::write(src.join("f"), v).unwrap();
        let a = sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success();
        ids.push(
            String::from_utf8(a.get_output().stdout.clone())
                .unwrap()
                .trim()
                .to_string(),
        );
    }

    // The empty prefix matches every snapshot; the error names the count and the
    // candidate ids so the user can pick a longer, unique prefix.
    let assert = sluice()
        .arg("restore")
        .arg(&repo)
        .arg("")
        .arg(dir.path().join("out"))
        .assert()
        .failure();
    let stderr = String::from_utf8(assert.get_output().stderr.clone()).unwrap();
    assert!(stderr.contains("ambiguous snapshot prefix"));
    assert!(stderr.contains("matches 2 snapshots"));
    assert!(
        ids.iter().any(|id| stderr.contains(&id[..16])),
        "the error should list candidate ids: {stderr}"
    );
}

#[test]
fn missing_password_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env_remove("SLUICE_PASSWORD");
    cmd.arg("init")
        .arg(dir.path().join("repo"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("SLUICE_PASSWORD"));
}

#[test]
fn password_file_is_read_and_newline_stripped() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hi").unwrap();
    // The passphrase lives in a file, with a trailing newline that must be ignored.
    let pwfile = dir.path().join("pw");
    std::fs::write(&pwfile, "secret-from-file\n").unwrap();

    // A command authenticated only by SLUICE_PASSWORD_FILE (no SLUICE_PASSWORD).
    let by_file = || {
        let mut cmd = Command::cargo_bin("sluice").unwrap();
        cmd.env_remove("SLUICE_PASSWORD")
            .env("SLUICE_KDF_MEMORY_KIB", "16")
            .env("SLUICE_KDF_PASSES", "1")
            .env("SLUICE_PASSWORD_FILE", &pwfile);
        cmd
    };
    by_file().arg("init").arg(&repo).assert().success();
    by_file()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // The repository opens with the *newline-stripped* passphrase passed directly,
    // proving the file was read and trimmed correctly.
    let mut direct = Command::cargo_bin("sluice").unwrap();
    direct
        .env_remove("SLUICE_PASSWORD_FILE")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1")
        .env("SLUICE_PASSWORD", "secret-from-file");
    direct.arg("snapshots").arg(&repo).assert().success();

    // A wrong passphrase is still rejected (exit 11).
    let mut wrong = Command::cargo_bin("sluice").unwrap();
    wrong
        .env_remove("SLUICE_PASSWORD_FILE")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1")
        .env("SLUICE_PASSWORD", "not-it");
    wrong.arg("snapshots").arg(&repo).assert().code(11);
}

#[test]
fn password_command_supplies_the_passphrase() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hi").unwrap();

    // A command authenticated only by SLUICE_PASSWORD_COMMAND (its stdout is the
    // passphrase) — the secret-manager integration path.
    let by_command = || {
        let mut cmd = Command::cargo_bin("sluice").unwrap();
        cmd.env_remove("SLUICE_PASSWORD")
            .env_remove("SLUICE_PASSWORD_FILE")
            .env("SLUICE_KDF_MEMORY_KIB", "16")
            .env("SLUICE_KDF_PASSES", "1")
            .env("SLUICE_PASSWORD_COMMAND", "printf cmd-secret");
        cmd
    };
    by_command().arg("init").arg(&repo).assert().success();
    by_command()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // The repository opens with the command's stdout passed directly.
    let mut direct = Command::cargo_bin("sluice").unwrap();
    direct
        .env_remove("SLUICE_PASSWORD_FILE")
        .env_remove("SLUICE_PASSWORD_COMMAND")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1")
        .env("SLUICE_PASSWORD", "cmd-secret");
    direct.arg("snapshots").arg(&repo).assert().success();

    // A command that fails is surfaced as an error, not a silent empty passphrase.
    let mut failing = Command::cargo_bin("sluice").unwrap();
    failing
        .env_remove("SLUICE_PASSWORD")
        .env_remove("SLUICE_PASSWORD_FILE")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1")
        .env("SLUICE_PASSWORD_COMMAND", "exit 7");
    failing
        .arg("snapshots")
        .arg(&repo)
        .assert()
        .failure()
        .stderr(predicate::str::contains("password command"));
}

#[test]
fn info_shows_repository_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("info")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("cipher:"))
        .stdout(predicate::str::contains("snapshots:   0"));
}

#[test]
fn info_json_reports_fields() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hi").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    let out = sluice()
        .arg("info")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    assert_eq!(v["repository"].as_str().unwrap().len(), 64);
    assert_eq!(v["snapshots"], 1);
    assert_eq!(v["keys"], 1);
    assert!(v["packs"].as_u64().unwrap() >= 1);
    assert!(v["chunker"]["avg"].is_number());
}

#[test]
fn backup_of_missing_source_reports_clearly() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(dir.path().join("nope"))
        .assert()
        .failure()
        .stderr(predicate::str::contains("not a file or directory"));
}

#[test]
fn stats_reports_counts() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hello").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    sluice()
        .arg("stats")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("snapshots:     1"))
        .stdout(predicate::str::contains("packs:"));
}

#[test]
fn snapshots_are_chronological_and_last_limits() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    sluice().arg("init").arg(&repo).assert().success();

    let mut ids = Vec::new();
    for v in ["v1", "v2", "v3"] {
        std::fs::write(src.join("f"), v).unwrap();
        let a = sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success();
        ids.push(
            String::from_utf8(a.get_output().stdout.clone())
                .unwrap()
                .trim()
                .to_string(),
        );
    }

    // --json lists them oldest-first (creation order here).
    let out = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    let got: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["id"].as_str().unwrap())
        .collect();
    assert_eq!(got, vec![&ids[0][..], &ids[1][..], &ids[2][..]]);

    // --last 1 keeps only the most recent.
    let out = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--last")
        .arg("1")
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap()).unwrap();
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"], ids[2]);
}

#[test]
fn snapshots_and_stats_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hello json").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .arg("--tag")
        .arg("daily")
        .assert()
        .success();

    let out = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["id"].as_str().unwrap().len(), 64);
    assert_eq!(arr[0]["tags"][0], "daily");
    assert_eq!(arr[0]["files"], 1);

    let out = sluice()
        .arg("stats")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let stdout = String::from_utf8(out.get_output().stdout.clone()).unwrap();
    let v: serde_json::Value = serde_json::from_str(&stdout).expect("valid JSON");
    assert_eq!(v["snapshots"], 1);
    assert!(v["packs"].as_u64().unwrap() >= 1);
}

#[test]
fn stats_for_a_single_snapshot_counts_entries_and_dedups() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    // a.bin and sub/b.bin are byte-identical (and compressible) so they dedup to
    // one stored blob; c.txt is distinct.
    let dup = vec![7u8; 4000];
    std::fs::write(src.join("a.bin"), &dup).unwrap();
    std::fs::write(src.join("sub/b.bin"), &dup).unwrap();
    std::fs::write(src.join("c.txt"), vec![9u8; 1000]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snapshot = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    let out = sluice()
        .arg("stats")
        .arg(&repo)
        .arg(&snapshot[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("valid JSON");
    assert_eq!(v["snapshot"], snapshot);
    assert_eq!(v["files"], 3);
    assert_eq!(v["dirs"], 1);
    assert_eq!(v["restore_bytes"], 4000 + 4000 + 1000);
    assert_eq!(v["blobs"], 2, "sub/b.bin reuses a.bin's blob");
    let raw = v["raw_bytes"].as_u64().unwrap();
    assert!(raw > 0 && raw < 9000, "raw {raw} below restore size");
}

#[test]
fn backup_reads_sources_from_files_from() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    // Two separate source directories plus a third given on the command line.
    let d1 = dir.path().join("d1");
    let d2 = dir.path().join("d2");
    let d3 = dir.path().join("d3");
    std::fs::create_dir_all(&d1).unwrap();
    std::fs::create_dir_all(&d2).unwrap();
    std::fs::create_dir_all(&d3).unwrap();
    std::fs::write(d1.join("a.txt"), b"aaa").unwrap();
    std::fs::write(d2.join("b.txt"), b"bbb").unwrap();
    std::fs::write(d3.join("c.txt"), b"ccc").unwrap();
    let list = dir.path().join("list.txt");
    std::fs::write(
        &list,
        format!("# sources\n{}\n\n{}\n", d1.display(), d2.display()),
    )
    .unwrap();

    sluice().arg("init").arg(&repo).assert().success();

    // d1 and d2 come from the file; d3 from the command line — all three land in
    // one snapshot.
    let out = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&d3)
        .arg("--files-from")
        .arg(&list)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_slice(&out.get_output().stdout).expect("valid JSON");
    assert_eq!(v["files_new"], 3, "a.txt + b.txt + c.txt");

    // A --files-from file that resolves to nothing (only comments/blanks) is an
    // error, not a backup of the whole filesystem.
    let empty = dir.path().join("empty.txt");
    std::fs::write(&empty, "# nothing here\n\n").unwrap();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg("--files-from")
        .arg(&empty)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no backup sources"));
}

#[test]
fn restore_delete_mirrors_the_target() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("sub/b.txt"), b"bravo").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Restore, then litter the target with extras the snapshot does not contain.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();
    std::fs::write(out.join("stray.txt"), b"junk").unwrap();
    std::fs::create_dir(out.join("staledir")).unwrap();
    std::fs::write(out.join("staledir/x"), b"junk").unwrap();

    // --delete cannot be combined with a path/glob filter.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .args(["--delete", "--include", "**/*.txt"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("--delete cannot be combined"));

    // A dry run previews deletions without removing anything.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .args(["--delete", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would delete 2 extra"));
    assert!(out.join("stray.txt").exists(), "dry run kept the extra");

    // The real mirror removes exactly the extras and keeps the snapshot content.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .arg("--delete")
        .assert()
        .success()
        .stdout(predicate::str::contains("deleted 2 extra"));
    assert!(!out.join("stray.txt").exists());
    assert!(!out.join("staledir").exists());
    assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(out.join("sub/b.txt")).unwrap(), b"bravo");
}

#[test]
fn restore_emits_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("b.txt"), b"bravo").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // A JSON dry run reports the would-restore counts without writing.
    let o = sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .args(["--json", "--dry-run"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["dry_run"], true);
    assert_eq!(v["snapshot"], snap);
    assert_eq!(v["files"], 2);
    assert_eq!(v["bytes"], 10);
    assert!(!out.exists(), "dry run wrote nothing");

    // A real JSON restore reports zero warnings and (with --delete) a deleted
    // count for the extra it removed.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();
    std::fs::write(out.join("stray.txt"), b"junk").unwrap();
    let o = sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .args(["--delete", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["warnings"], 0);
    assert_eq!(v["deleted"], 1);
    assert!(!out.join("stray.txt").exists());
}

#[test]
fn copy_preserves_metadata() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let dest = dir.path().join("dest");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"data").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice().arg("init").arg(&dest).assert().success();
    // Back up with non-default host, tag and time.
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args([
            "--host",
            "fileserver",
            "--tag",
            "important",
            "--time",
            "1577836800",
        ])
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&dest)
        .arg(&snap[..12])
        .assert()
        .success();

    // The destination snapshot keeps the host, tag and time but has a new id.
    let o = sluice()
        .arg("snapshots")
        .arg(&dest)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["hostname"], "fileserver");
    assert_eq!(arr[0]["tags"], serde_json::json!(["important"]));
    assert_eq!(arr[0]["time_ns"], 1_577_836_800_000_000_000i64);
    assert_ne!(arr[0]["id"].as_str().unwrap(), snap, "copy re-encrypts");
}

#[test]
fn copy_emits_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let repo2 = dir.path().join("repo2");
    let repo3 = dir.path().join("repo3");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"data").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice().arg("init").arg(&repo2).assert().success();
    sluice().arg("init").arg(&repo3).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Copying one snapshot reports a new destination id, which differs from the
    // source id because copy re-encrypts under the destination's keys.
    let o = sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&repo2)
        .arg(&snap[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["copied"], 1);
    let new_id = v["snapshots"][0].as_str().unwrap();
    assert_eq!(new_id.len(), 64);
    assert_ne!(new_id, snap, "copy re-encrypts, so the id changes");

    // Copying the whole repository reports the count.
    let o = sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&repo3)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["copied"], 1);
    assert_eq!(v["snapshots"].as_array().unwrap().len(), 1);
}

#[test]
fn copy_compression_override() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let dest = dir.path().join("dest");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    let data = vec![b'Z'; 80_000];
    std::fs::write(src.join("f.bin"), &data).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice().arg("init").arg(&dest).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Recompress into the destination at level 19; the copy still restores.
    let o = sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&dest)
        .arg(&snap[..12])
        .args(["--compression", "19", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let new_id = v["snapshots"][0].as_str().unwrap().to_string();
    sluice()
        .arg("restore")
        .arg(&dest)
        .arg(&new_id[..12])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("f.bin")).unwrap(), data);

    // Out-of-range levels are rejected.
    sluice()
        .arg("copy")
        .arg(&repo)
        .arg(&dest)
        .arg(&snap[..12])
        .args(["--compression", "0"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in 1..=22"));
}

#[test]
fn init_tag_unlock_rebuild_index_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"hi").unwrap();

    // init --json reports the new repo id and location.
    let o = sluice()
        .arg("init")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["repo_id"].as_str().unwrap().len(), 64);
    assert_eq!(v["location"], repo.to_string_lossy().as_ref());

    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // tag --json reports the retagged snapshot id and the resulting tag set.
    let o = sluice()
        .arg("tag")
        .arg(&repo)
        .arg(&snap[..12])
        .args(["--add", "keep", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["changed"], true);
    assert_eq!(v["snapshot"].as_str().unwrap().len(), 64);
    assert_eq!(v["tags"], serde_json::json!(["keep"]));

    // rebuild-index --json reports the pack count.
    let o = sluice()
        .arg("rebuild-index")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert!(v["packs"].as_u64().unwrap() >= 1);

    // unlock --json reports how many locks were removed (none here).
    let o = sluice()
        .arg("unlock")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["removed"], 0);
}

#[test]
fn key_add_remove_passwd_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    sluice().arg("init").arg(&repo).assert().success();

    // key add --json reports the new key id.
    let o = sluice()
        .env("SLUICE_NEW_PASSWORD", "second")
        .arg("key")
        .arg("add")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let added = v["key_id"].as_str().unwrap().to_string();
    assert_eq!(added.len(), 64);

    // Now there are two keys.
    let o = sluice()
        .arg("key")
        .arg("list")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 2);

    // key remove --json reports the removed id and the remaining count.
    let o = sluice()
        .arg("key")
        .arg("remove")
        .arg(&repo)
        .arg(&added)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["removed"], added);
    assert_eq!(v["keys"], 1);

    // key passwd --json rotates the primary key (do this last: it invalidates the
    // helper's integration-pw). The new id differs from the removed one.
    let o = sluice()
        .env("SLUICE_NEW_PASSWORD", "rotated")
        .arg("key")
        .arg("passwd")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let rotated = v["key_id"].as_str().unwrap();
    assert_eq!(rotated.len(), 64);
    assert_ne!(rotated, added);

    // The rotated passphrase now opens the repository.
    let mut cmd = Command::cargo_bin("sluice").unwrap();
    cmd.env("SLUICE_PASSWORD", "rotated")
        .env("SLUICE_KDF_MEMORY_KIB", "16")
        .env("SLUICE_KDF_PASSES", "1");
    cmd.arg("snapshots").arg(&repo).assert().success();
}

#[test]
fn backup_skip_if_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"v1").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .arg("--skip-if-unchanged")
        .assert()
        .success();

    // A second, unchanged backup is skipped (no new snapshot), reported as JSON.
    let o = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--skip-if-unchanged", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert!(v["snapshot"].is_null());
    assert_eq!(v["skipped"], true);
    assert_eq!(v["dry_run"], false);

    // Still only one snapshot.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 1);

    // A real change is captured.
    std::fs::write(src.join("f"), b"v2 is different").unwrap();
    let o = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--skip-if-unchanged", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert!(v["snapshot"].as_str().is_some());
    assert_eq!(v["skipped"], false);

    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 2);
}

#[test]
fn backup_force_rereads_unchanged_files() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join("b.txt"), b"bravo").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // A normal re-backup reuses both unchanged files.
    let o = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["files_unmodified"], 2);
    assert_eq!(v["files_changed"], 0);

    // --force re-reads them regardless of the size+mtime heuristic.
    let o = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--force", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["files_unmodified"], 0, "--force bypasses reuse");
    assert_eq!(v["files_changed"], 2);
}

#[test]
fn forget_keep_hourly() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Snapshots at this hour and 1, 2 and 30 hours ago (exact-hour offsets keep
    // each in a distinct hour bucket).
    for hours in [0i64, 1, 2, 30] {
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .args(["--time", &(now - hours * 3600).to_string(), "--force"])
            .assert()
            .success();
    }

    // --keep-hourly 3 keeps the three recent hours, forgets the 30-hour-old one.
    let o = sluice()
        .arg("forget")
        .arg(&repo)
        .args(["--keep-hourly", "3", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["count"], 1);
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[test]
fn forget_dry_run_lists_affected_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Three snapshots dated today, yesterday and two days ago (newest first).
    let mut ids = Vec::new();
    for days in [0i64, 1, 2] {
        let a = sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .args(["--time", &(now - days * 86400).to_string(), "--force"])
            .assert()
            .success();
        ids.push(
            String::from_utf8(a.get_output().stdout.clone())
                .unwrap()
                .trim()
                .to_string(),
        );
    }

    // keep-last 1 keeps the newest (ids[0]); a dry run lists the other two with
    // their dates, and removes nothing.
    sluice()
        .arg("forget")
        .arg(&repo)
        .args(["--keep-last", "1", "--dry-run"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would forget 2 snapshot(s)"))
        .stdout(predicate::str::contains(&ids[1][..16]))
        .stdout(predicate::str::contains(&ids[2][..16]))
        .stdout(predicate::str::contains("UTC"))
        .stdout(predicate::str::contains(&ids[0][..16]).not());

    // The dry run did not actually forget anything.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[test]
fn forget_keep_within_daily() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"x").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    // Snapshots dated today, 1, 2 and 10 days ago (exact-day offsets put each in a
    // distinct UTC day regardless of the current time of day).
    for days in [0i64, 1, 2, 10] {
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .args(["--time", &(now - days * 86400).to_string(), "--force"])
            .assert()
            .success();
    }

    // A 3-day daily window keeps the three recent days and forgets the 10-day-old.
    let o = sluice()
        .arg("forget")
        .arg(&repo)
        .args(["--keep-within-daily", "3d", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["count"], 1, "only the 10-day-old snapshot is forgotten");
    // Three snapshots remain.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v.as_array().unwrap().len(), 3);
}

#[test]
fn backup_time_override_dates_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"hi").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    // 1577836800 = 2020-01-01 00:00:00 UTC.
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--time", "1577836800"])
        .assert()
        .success();

    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v[0]["time_ns"], 1_577_836_800_000_000_000i64);

    // The human listing renders that date.
    sluice()
        .arg("snapshots")
        .arg(&repo)
        .assert()
        .success()
        .stdout(predicate::str::contains("2020-01-01 00:00:00 UTC"));
}

#[test]
fn check_targets_one_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let s1 = dir.path().join("s1");
    let s2 = dir.path().join("s2");
    std::fs::create_dir_all(&s1).unwrap();
    std::fs::create_dir_all(&s2).unwrap();
    std::fs::write(s1.join("a.bin"), vec![1u8; 5000]).unwrap();
    std::fs::write(s2.join("b.bin"), vec![2u8; 5000]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&s1)
        .assert()
        .success();
    let snap1 = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&s2)
        .assert()
        .success();

    // Whole-repo check sees both snapshots.
    let o = sluice()
        .arg("check")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["snapshots"], 2);

    // Targeting snap1 checks only it.
    let o = sluice()
        .arg("check")
        .arg(&repo)
        .arg(&snap1[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["snapshots"], 1);
    assert_eq!(v["ok"], true);
}

#[test]
fn verify_targets_one_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let s1 = dir.path().join("s1");
    let s2 = dir.path().join("s2");
    std::fs::create_dir_all(&s1).unwrap();
    std::fs::create_dir_all(&s2).unwrap();
    std::fs::write(s1.join("a.bin"), vec![1u8; 5000]).unwrap();
    std::fs::write(s2.join("b.bin"), vec![2u8; 5000]).unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&s1)
        .assert()
        .success();
    let snap1 = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&s2)
        .assert()
        .success();

    // Whole-repo verify sees both snapshots.
    let o = sluice()
        .arg("verify")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["snapshots"], 2);
    assert_eq!(v["total_blobs"], 2);

    // Targeting snap1 verifies only it.
    let o = sluice()
        .arg("verify")
        .arg(&repo)
        .arg(&snap1[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    assert_eq!(v["snapshots"], 1);
    assert_eq!(v["total_blobs"], 1);
}

#[test]
fn snapshots_compact_drops_paths_and_size() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("srcdir");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"hi").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--tag", "daily"])
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Compact: id, date and tag present; file count, size and source path gone.
    sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--compact")
        .assert()
        .success()
        .stdout(predicate::str::contains(&snap[..16]))
        .stdout(predicate::str::contains("[daily]"))
        .stdout(predicate::str::contains("files").not())
        .stdout(predicate::str::contains("srcdir").not());
}

#[test]
fn snapshots_group_by_host() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"hi").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    for host in ["alpha", "alpha", "beta"] {
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .args(["--host", host, "--force"])
            .assert()
            .success();
    }

    // Grouped JSON: one entry per host (sorted by label), each with its snapshots.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .args(["--group-by", "host", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let groups = v.as_array().unwrap();
    assert_eq!(groups.len(), 2);
    assert_eq!(groups[0]["group"], "alpha");
    assert_eq!(groups[0]["snapshots"].as_array().unwrap().len(), 2);
    assert_eq!(groups[1]["group"], "beta");
    assert_eq!(groups[1]["snapshots"].as_array().unwrap().len(), 1);

    // The human listing prints a header per host.
    sluice()
        .arg("snapshots")
        .arg(&repo)
        .args(["--group-by", "host"])
        .assert()
        .success()
        .stdout(predicate::str::contains("host alpha"))
        .stdout(predicate::str::contains("host beta"));
}

#[test]
fn backup_host_override_attributes_the_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f.txt"), b"hi").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--host", "fileserver01"])
        .assert()
        .success();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--host", "laptop", "--force"])
        .assert()
        .success();

    // --json reports the recorded hostname.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let hosts: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s["hostname"].as_str().unwrap())
        .collect();
    assert!(hosts.contains(&"fileserver01"));
    assert!(hosts.contains(&"laptop"));

    // --host filters the listing to a single host.
    let o = sluice()
        .arg("snapshots")
        .arg(&repo)
        .args(["--host", "fileserver01", "--json"])
        .assert()
        .success();
    let v: serde_json::Value = serde_json::from_slice(&o.get_output().stdout).expect("valid JSON");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["hostname"], "fileserver01");
}

#[test]
fn backup_compression_override() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    let data = vec![b'A'; 100_000];
    std::fs::write(src.join("f.bin"), &data).unwrap();

    // Repo default is level 3; this run overrides to 19.
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--compression", "19"])
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("f.bin")).unwrap(), data);

    // Out-of-range levels are rejected by the argument parser.
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .args(["--compression", "99"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("not in 1..=22"));
}

#[test]
fn restore_include_exclude_from_files() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::create_dir_all(src.join("logs")).unwrap();
    std::fs::write(src.join("docs/a.pdf"), b"pdf").unwrap();
    std::fs::write(src.join("docs/b.txt"), b"txt").unwrap();
    std::fs::write(src.join("logs/c.log"), b"log").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // --include-from: only the matching files are written.
    let inc = dir.path().join("inc.txt");
    std::fs::write(&inc, "# only pdfs\n**/*.pdf\n").unwrap();
    let out1 = dir.path().join("out1");
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out1)
        .arg("--include-from")
        .arg(&inc)
        .assert()
        .success();
    assert!(out1.join("docs/a.pdf").exists());
    assert!(!out1.join("docs/b.txt").exists());
    assert!(!out1.join("logs/c.log").exists());

    // --exclude-from: matching files are skipped, the rest restored.
    let exc = dir.path().join("exc.txt");
    std::fs::write(&exc, "**/*.log\n").unwrap();
    let out2 = dir.path().join("out2");
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out2)
        .arg("--exclude-from")
        .arg(&exc)
        .assert()
        .success();
    assert!(out2.join("docs/a.pdf").exists());
    assert!(out2.join("docs/b.txt").exists());
    assert!(!out2.join("logs/c.log").exists());
}

#[test]
fn backup_exclude_from_file() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("node_modules")).unwrap();
    std::fs::write(src.join("keep.txt"), b"k").unwrap();
    std::fs::write(src.join("skip.log"), b"l").unwrap();
    std::fs::write(src.join("node_modules/x"), b"n").unwrap();
    let exfile = dir.path().join("excludes.txt");
    std::fs::write(&exfile, "# a comment\n*.log\n\nnode_modules\n").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .arg("--exclude-from")
        .arg(&exfile)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    let out = sluice()
        .arg("ls")
        .arg(&repo)
        .arg(&snap[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    let paths: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"keep.txt"));
    assert!(!paths.iter().any(|p| p.contains("skip.log")));
    assert!(!paths.iter().any(|p| p.contains("node_modules")));
}

#[test]
fn restore_multiple_paths() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::create_dir_all(src.join("other")).unwrap();
    std::fs::write(src.join("docs/memo"), b"m").unwrap();
    std::fs::write(src.join("config.txt"), b"c").unwrap();
    std::fs::write(src.join("other/z"), b"z").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // Restore two specific paths; the third (other/) is left out.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .arg("--path")
        .arg("docs")
        .arg("--path")
        .arg("config.txt")
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("docs/memo")).unwrap(), b"m");
    assert_eq!(std::fs::read(out.join("config.txt")).unwrap(), b"c");
    assert!(
        !out.join("other").exists(),
        "unrequested paths must not be restored"
    );
}

#[test]
fn restore_dry_run_verbose_lists_filtered_files() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("docs")).unwrap();
    std::fs::create_dir_all(src.join("logs")).unwrap();
    std::fs::write(src.join("docs/a.pdf"), b"a").unwrap();
    std::fs::write(src.join("docs/b.txt"), b"b").unwrap();
    std::fs::write(src.join("logs/c.log"), b"c").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // A verbose dry run lists exactly the files the filter selects (on stderr),
    // and the summary (on stdout) — writing nothing.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .args(["--dry-run", "-v", "--include", "**/*.pdf"])
        .assert()
        .success()
        .stdout(predicate::str::contains("would restore 1 files"))
        .stderr(predicate::str::contains("docs/a.pdf"))
        .stderr(predicate::str::contains("b.txt").not())
        .stderr(predicate::str::contains("c.log").not());
    assert!(!out.exists(), "a dry run writes nothing");
}

#[test]
fn restore_skip_newer_protects_local_edits() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"snapshot version").unwrap();

    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();

    // Edit the restored file; rewriting it now makes its mtime newer than the
    // snapshot's (taken earlier).
    std::fs::write(out.join("f"), b"local newer edit").unwrap();
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .arg("--skip-newer")
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("f")).unwrap(), b"local newer edit");

    // Without the flag, the snapshot version overwrites it.
    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .assert()
        .success();
    assert_eq!(std::fs::read(out.join("f")).unwrap(), b"snapshot version");
}

#[test]
fn restore_dry_run_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    let out = dir.path().join("out");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("top.txt"), b"t").unwrap();
    std::fs::write(src.join("sub/a"), b"aa").unwrap();
    std::fs::write(src.join("sub/b"), b"bbb").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    sluice()
        .arg("restore")
        .arg(&repo)
        .arg(&snap[..12])
        .arg(&out)
        .arg("--dry-run")
        .assert()
        .success()
        .stdout(predicate::str::contains("would restore 3 files"))
        .stdout(predicate::str::contains("nothing written"));
    assert!(!out.exists(), "a dry run must not create the target");
}

#[test]
fn ls_lists_a_subpath() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub/deep")).unwrap();
    std::fs::write(src.join("top.txt"), b"t").unwrap();
    std::fs::write(src.join("sub/a"), b"a").unwrap();
    std::fs::write(src.join("sub/deep/b"), b"b").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    let out = sluice()
        .arg("ls")
        .arg(&repo)
        .arg(&snap[..12])
        .arg("sub")
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    let paths: Vec<&str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"sub"));
    assert!(paths.contains(&"sub/a"));
    assert!(paths.contains(&"sub/deep/b"));
    assert!(
        !paths.contains(&"top.txt"),
        "subpath ls must exclude siblings"
    );
}

#[test]
fn diff_human_output_ends_with_a_summary() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    sluice().arg("init").arg(&repo).assert().success();

    std::fs::write(src.join("a"), b"1").unwrap();
    std::fs::write(src.join("b"), b"2").unwrap();
    let s1 = String::from_utf8(
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    std::fs::write(src.join("a"), b"changed").unwrap(); // modified
    std::fs::remove_file(src.join("b")).unwrap(); // removed
    std::fs::write(src.join("c"), b"3").unwrap(); // added
    let s2 = String::from_utf8(
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    // The human diff lists each change and ends with a one/some/none summary.
    sluice()
        .arg("diff")
        .arg(&repo)
        .arg(&s1[..12])
        .arg(&s2[..12])
        .assert()
        .success()
        .stdout(predicate::str::contains("1 added, 1 removed, 1 modified"));
}

#[test]
fn diff_emits_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    sluice().arg("init").arg(&repo).assert().success();

    std::fs::write(src.join("a"), b"1").unwrap();
    std::fs::write(src.join("b"), b"2").unwrap();
    let s1 = String::from_utf8(
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    std::fs::write(src.join("a"), b"11111").unwrap(); // size change -> modified
    std::fs::remove_file(src.join("b")).unwrap(); // removed
    std::fs::write(src.join("c"), b"3").unwrap(); // added
    let s2 = String::from_utf8(
        sluice()
            .arg("backup")
            .arg(&repo)
            .arg(&src)
            .assert()
            .success()
            .get_output()
            .stdout
            .clone(),
    )
    .unwrap()
    .trim()
    .to_string();

    let out = sluice()
        .arg("diff")
        .arg(&repo)
        .arg(&s1[..12])
        .arg(&s2[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    let changes: std::collections::HashMap<&str, &str> = v
        .as_array()
        .unwrap()
        .iter()
        .map(|e| (e["path"].as_str().unwrap(), e["change"].as_str().unwrap()))
        .collect();
    assert_eq!(changes.get("a"), Some(&"modified"));
    assert_eq!(changes.get("b"), Some(&"removed"));
    assert_eq!(changes.get("c"), Some(&"added"));
}

#[test]
fn cat_emits_config_snapshot_and_tree_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), b"data").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .arg("--tag")
        .arg("daily")
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    let parse = |a: assert_cmd::assert::Assert| -> serde_json::Value {
        serde_json::from_str(&String::from_utf8(a.get_output().stdout.clone()).unwrap())
            .expect("valid JSON")
    };

    // cat config
    let v = parse(
        sluice()
            .arg("cat")
            .arg("config")
            .arg(&repo)
            .assert()
            .success(),
    );
    assert_eq!(v["repo_id"].as_str().unwrap().len(), 64);
    assert_eq!(v["cipher"], "XChaCha20Poly1305");
    assert!(v["chunker"]["min"].is_number());

    // cat snapshot
    let v = parse(
        sluice()
            .arg("cat")
            .arg("snapshot")
            .arg(&repo)
            .arg(&snap[..12])
            .assert()
            .success(),
    );
    assert_eq!(v["tags"][0], "daily");
    let tree_id = v["tree"].as_str().unwrap().to_string();
    assert_eq!(tree_id.len(), 64);

    // cat tree (the id from the snapshot above)
    let v = parse(
        sluice()
            .arg("cat")
            .arg("tree")
            .arg(&repo)
            .arg(&tree_id)
            .assert()
            .success(),
    );
    let nodes = v["nodes"].as_array().unwrap();
    assert!(
        nodes
            .iter()
            .any(|n| n["name"] == "f" && n["kind"] == "file")
    );
}

#[test]
fn forget_and_prune_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(&src).unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    std::fs::write(src.join("f"), vec![1u8; 4000]).unwrap();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    std::fs::write(src.join("f"), vec![2u8; 4000]).unwrap();
    sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();

    // Forget the older snapshot and prune, as JSON.
    let out = sluice()
        .arg("forget")
        .arg(&repo)
        .arg("--keep-last")
        .arg("1")
        .arg("--prune")
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    assert_eq!(v["dry_run"], false);
    assert_eq!(v["count"], 1);
    assert_eq!(v["forgotten"].as_array().unwrap().len(), 1);
    assert!(v["pruned"]["reclaimed_bytes"].as_u64().unwrap() > 0);

    // Prune again as JSON: nothing left to reclaim.
    let out = sluice()
        .arg("prune")
        .arg(&repo)
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    assert_eq!(v["dry_run"], false);
    assert!(v["reclaimed_bytes"].is_number());
}

#[test]
fn ls_and_find_emit_json() {
    let dir = tempfile::tempdir().unwrap();
    let repo = dir.path().join("repo");
    let src = dir.path().join("src");
    std::fs::create_dir_all(src.join("sub")).unwrap();
    std::fs::write(src.join("top.txt"), b"t").unwrap();
    std::fs::write(src.join("sub/needle.log"), b"n").unwrap();
    sluice().arg("init").arg(&repo).assert().success();
    let assert = sluice()
        .arg("backup")
        .arg(&repo)
        .arg(&src)
        .assert()
        .success();
    let snap = String::from_utf8(assert.get_output().stdout.clone())
        .unwrap()
        .trim()
        .to_string();

    // ls --json: the directory entry is "dir", and both files are listed.
    let out = sluice()
        .arg("ls")
        .arg(&repo)
        .arg(&snap[..12])
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    let entries = v.as_array().unwrap();
    let paths: Vec<&str> = entries
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"top.txt"));
    assert!(paths.contains(&"sub/needle.log"));
    let subdir = entries.iter().find(|e| e["path"] == "sub").unwrap();
    assert_eq!(subdir["kind"], "dir");

    // find --json: one log file, kind "file", with a full-length snapshot id.
    let out = sluice()
        .arg("find")
        .arg(&repo)
        .arg("**/*.log")
        .arg("--json")
        .assert()
        .success();
    let v: serde_json::Value =
        serde_json::from_str(&String::from_utf8(out.get_output().stdout.clone()).unwrap())
            .expect("valid JSON");
    let arr = v.as_array().unwrap();
    assert_eq!(arr.len(), 1);
    assert_eq!(arr[0]["path"], "sub/needle.log");
    assert_eq!(arr[0]["kind"], "file");
    assert_eq!(arr[0]["snapshot"].as_str().unwrap().len(), 64);
}
