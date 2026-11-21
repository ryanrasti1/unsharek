//! The CLI's view of what the guest is shown: nothing is implicit. A program from the store runs
//! only with its closure given (`--closure`), or `--system`; `--ro` is for host directories, and
//! refuses a store path (its place is `--closure`).

use std::process::Command;

fn bash() -> String {
    std::env::var("UNSHAREK_TEST_BASH").expect("UNSHAREK_TEST_BASH (the devshell's bash)")
}

fn unsharek(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_unsharek")).args(args).output().unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned(), String::from_utf8_lossy(&out.stderr).into_owned())
}

/// Without --closure, the program's own closure isn't shown: a clear error, before it runs.
#[test]
fn program_needs_its_closure() {
    let b = bash();
    let (st, out, err) = unsharek(&["--", &b, "-c", "echo RAN"]);
    assert_eq!(st, Some(125), "{out}{err}");
    assert!(err.contains("the program isn't in the sandbox: add --closure"), "{err}");
    assert!(!out.contains("RAN"));
    let (st, out, err) = unsharek(&["--closure", &b, "--", &b, "-c", "echo RAN"]);
    assert_eq!(st, Some(0), "{out}{err}");
    assert!(out.contains("RAN"), "{out}{err}");
}

/// `--ro` of a store path is refused: --closure shows store paths.
#[test]
fn ro_refuses_a_store_path() {
    let b = bash();
    let store = std::path::Path::new(&b).ancestors().find(|a| a.parent() == Some(std::path::Path::new("/nix/store"))).unwrap();
    let (st, _, err) = unsharek(&["--ro", store.to_str().unwrap(), "--", &b, "-c", "true"]);
    assert_eq!(st, Some(125), "{err}");
    assert!(err.contains("a store path: use --closure"), "{err}");
}
