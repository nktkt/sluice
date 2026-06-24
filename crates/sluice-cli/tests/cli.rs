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
        .stderr(predicate::str::contains("not a directory"));
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
