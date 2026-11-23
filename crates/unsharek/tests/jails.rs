//! unsharek inside an outer jail: bubblewrap's namespaces decide what exists (the store, a work
//! directory, nothing else of the host's files), unsharek's filter which host calls the program
//! can make. Each case runs busybox under `bwrap --unshare-all -- unsharek …` (as
//! examples/bwrap/run.sh does) and checks, from the host, what it did: a live `rw` mount with
//! Landlock and without it (`--no-landlock`: then bwrap alone confines its paths), and a `map`
//! mount. Each checks that writes inside the mount reach the host, that a path outside it isn't
//! there, and that the program's exit status is unsharek's. Bounded: 10 s each.
//!
//! The cases run at once and share one image cache, each unsharek pid 2 in its own pid namespace:
//! the image builder's temporary files were named by the pid, and the second sandbox's build
//! failed with EEXIST (store.rs's `tmp_id`).
//!
//! Docker is `cargo xtask test-docker` (examples/docker): it needs a daemon.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

mod common;

fn busybox() -> PathBuf {
    PathBuf::from(std::env::var("UNSHAREK_TEST_BUSYBOX").expect("UNSHAREK_TEST_BUSYBOX: run in the devshell (cargo xtask test)"))
}

/// The devshell's bubblewrap (`UNSHAREK_TEST_BWRAP`), else the one on PATH.
fn bwrap() -> String {
    std::env::var("UNSHAREK_TEST_BWRAP").unwrap_or_else(|_| "bwrap".into())
}

/// The store path `p` is in.
fn store_path(p: &Path) -> &Path {
    p.ancestors().find(|a| a.parent() == Some(Path::new("/nix/store"))).expect("a store path")
}

/// `unsharek FLAGS -- busybox sh -c SCRIPT` inside bwrap, `work` its /work (read-write in bwrap's
/// view), the image cache bound in (unsharek builds busybox's mapped image there). Its exit code and
/// output.
fn in_bwrap(work: &Path, flags: &[&str], script: &str) -> (Option<i32>, String) {
    let cache = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache");
    std::fs::create_dir_all(&cache).unwrap();
    let bb = busybox();
    let mut cmd = Command::new(bwrap());
    cmd.args(["--unshare-all", "--die-with-parent", "--new-session", "--ro-bind", "/nix/store", "/nix/store"])
        .arg("--ro-bind")
        .arg(env!("CARGO_BIN_EXE_unsharek"))
        .arg("/unsharek")
        .arg("--bind")
        .arg(work)
        .arg("/work")
        .arg("--bind")
        .arg(&cache)
        .arg(&cache)
        .args(["--setenv", "UNSHAREK_IMAGE_CACHE", cache.to_str().unwrap()])
        // Fork mode: the script's applets are processes of the shell's.
        .args(["--dev", "/dev", "--proc", "/proc", "--tmpfs", "/tmp", "--", "/unsharek", "--mode", "fork", "--mount"])
        // busybox is static: its store path alone, mapped (`closure` would ask nix-store, which
        // bwrap's view has no database for).
        .arg(format!("{}:map", store_path(&bb).display()))
        .args(flags)
        .arg("--")
        .arg(&bb)
        .args(["sh", "-c", script])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, _, out, err) = common::spawn_bounded(cmd, None, Duration::from_secs(10)).expect("bwrap ran");
    (status.code(), out + &err)
}

/// The script: busybox's applets by its path (the guest has no PATH). Writes inside /work, reads
/// the host's /etc/hostname (not in the sandbox: bwrap has no /etc, and unsharek shows none),
/// then exits 7.
fn script(bb: &Path) -> String {
    let b = bb.display();
    format!(
        "{b} echo from-the-guest > /work/out && {b} cat /work/in && {b} mkdir /work/d && {b} mv /work/out /work/d/out && \
         {b} cat /etc/hostname 2>/dev/null; echo outside=$?; exit 7"
    )
}

fn check_run(how: &str, flags: &[&str]) {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("in"), "from-the-host\n").unwrap();
    let (code, out) = in_bwrap(work.path(), flags, &script(&busybox()));
    assert_eq!(code, Some(7), "{how}: the program's status is unsharek's\n{out}");
    assert!(out.contains("from-the-host"), "{how}: read inside the mount\n{out}");
    assert!(out.contains("outside=1"), "{how}: a path outside the mounts isn't there\n{out}");
    let got = std::fs::read_to_string(work.path().join("d/out"));
    assert_eq!(got.as_deref().ok(), Some("from-the-guest\n"), "{how}: the write reached the host\n{out}");
}

/// A live read-write mount under bwrap, Landlock's ruleset over it (Landlock stacks under bwrap's
/// namespaces).
#[test]
fn bwrap_rw_with_landlock() {
    check_run("rw", &["--mount", "/work:rw"]);
}

/// The same with `--no-landlock`: bwrap's view alone confines the mount's paths. unsharek says so.
#[test]
fn bwrap_rw_no_landlock() {
    let work = tempfile::tempdir().unwrap();
    let (_, out) = in_bwrap(work.path(), &["--no-landlock", "--mount", "/work:rw"], "exit 0");
    assert!(out.contains("--no-landlock: the ro and rw mounts' paths are confined only by where unsharek runs"), "{out}");
    check_run("rw --no-landlock", &["--no-landlock", "--mount", "/work:rw"]);
}

/// A `map` mount under bwrap: read-only, mapped in place, no host call added; a write is refused.
#[test]
fn bwrap_map() {
    let work = tempfile::tempdir().unwrap();
    std::fs::write(work.path().join("in"), "mapped\n").unwrap();
    let b = busybox();
    let bb = b.display();
    let s = format!("{bb} cat /work/in; {bb} echo x > /work/new 2>/dev/null; echo write=$?; {bb} cat /etc/hostname 2>/dev/null; echo outside=$?; exit 3");
    let (code, out) = in_bwrap(work.path(), &["--mount", "/work:map"], &s);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("mapped"), "{out}");
    assert!(out.contains("write=1") && out.contains("outside=1"), "{out}");
    assert!(!work.path().join("new").exists(), "{out}");
}
