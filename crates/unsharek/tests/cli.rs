//! The CLI's view of what the guest is shown: nothing is implicit. A program from the store runs
//! only with its closure mounted (`--mount <store path>:closure`), or `--system`; every mount
//! names its type.

use std::process::Command;

fn bash() -> String {
    std::env::var("UNSHAREK_TEST_BASH").expect("UNSHAREK_TEST_BASH (the devshell's bash)")
}

fn unsharek(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_unsharek")).args(args).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Without its closure mounted, the program's own closure isn't shown: a clear error, before it
/// runs.
#[test]
fn program_needs_its_closure() {
    let b = bash();
    let (st, out, err) = unsharek(&["--", &b, "-c", "echo RAN"]);
    assert_eq!(st, Some(125), "{out}{err}");
    assert!(err.contains("the program isn't in the sandbox: add --mount <its store path>:closure"), "{err}");
    assert!(!out.contains("RAN"));
    let (st, out, err) = unsharek(&["--mount", &format!("{b}:closure"), "--", &b, "-c", "echo RAN"]);
    assert_eq!(st, Some(0), "{out}{err}");
    assert!(out.contains("RAN"), "{out}{err}");
}

/// A mount's type is required, and is one of the four; a closure takes no mount point.
#[test]
fn mount_type_is_required() {
    let b = bash();
    for (arg, want) in [
        ("/tmp", "TYPE"),
        ("/tmp:/x:bogus", "bogus: not a mount type"),
        (&*format!("{b}:/elsewhere:closure"), "no mount point"),
        ("/tmp:relative:ro", "must be absolute"),
    ] {
        let (st, _, err) = unsharek(&["--mount", arg, "--", &b, "-c", "true"]);
        assert_eq!(st, Some(2), "{arg}: {err}");
        assert!(err.contains(want), "{arg}: {err}");
    }
}

/// The old flags are gone (one `--mount`, one `--env`).
#[test]
fn old_flags_are_gone() {
    let b = bash();
    for flag in ["--closure", "--ro", "--rw", "--setenv", "--keep-env", "--publish", "--immutable"] {
        let (st, _, err) = unsharek(&[flag, "/tmp", "--", &b, "-c", "true"]);
        assert_eq!(st, Some(2), "{flag}: {err}");
    }
}

/// `--no-landlock` with a live mount says what it gives up, on stderr, and runs.
#[test]
fn no_landlock_warns() {
    let b = bash();
    let d = tempfile::tempdir().unwrap();
    let ro = format!("{}:ro", d.path().display());
    let (st, out, err) = unsharek(&["--no-landlock", "--mount", &ro, "--mount", &format!("{b}:closure"), "--", &b, "-c", "echo RAN"]);
    assert_eq!(st, Some(0), "{out}{err}");
    assert!(err.contains("--no-landlock: the ro and rw mounts' paths are confined only by where unsharek runs"), "{err}");
    let (_, _, err) = unsharek(&["--mount", &ro, "--mount", &format!("{b}:closure"), "--", &b, "-c", "true"]);
    assert!(!err.contains("--no-landlock"), "{err}");
}
