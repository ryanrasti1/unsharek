//! Each example run once, small (`EXOBOX_EXAMPLE_QUICK`), under a timeout, its key output
//! checked: so `./test` keeps them from rotting. An example whose nixpkgs program isn't in the
//! environment says "skipped:", which passes.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Runs example `bin` to its end (killed after 10 s: a failure), returning its stdout and stderr
/// together, and whether it exited 0.
fn run(bin: &str, args: &[&str]) -> (bool, String) {
    let exe = std::env::var_os(format!("CARGO_BIN_EXE_{bin}")).expect("cargo sets CARGO_BIN_EXE_<name>");
    let mut child = Command::new(exe)
        .args(args)
        .env("EXOBOX_EXAMPLE_QUICK", "1")
        .env("EXOBOX_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let drain = |mut r: Box<dyn Read + Send>| {
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = r.read_to_string(&mut s);
            s
        })
    };
    let (out, err) = (drain(Box::new(child.stdout.take().unwrap())), drain(Box::new(child.stderr.take().unwrap())));
    let start = Instant::now();
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if start.elapsed() > Duration::from_secs(10) {
            let _ = child.kill();
            let _ = child.wait();
            panic!("{bin} timed out\n{}\n{}", out.join().unwrap(), err.join().unwrap());
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    (status.success(), out.join().unwrap() + &err.join().unwrap())
}

fn expect(bin: &str, args: &[&str], wanted: &[&str]) -> String {
    let (ok, out) = run(bin, args);
    if out.starts_with("skipped:") {
        return out;
    }
    assert!(ok, "{bin} failed:\n{out}");
    for w in wanted {
        assert!(out.contains(w), "{bin}: wanted {w:?} in:\n{out}");
    }
    out
}

#[test]
fn nix_program() {
    expect("nix-program", &[], &["\n42\n", "--- exit 0", "peak PSS"]);
}

#[test]
fn setup() {
    expect(
        "setup",
        &[],
        &["app: hello from an erofs image", "config: greeting=hi", "(writable: False)", "exists here: False"],
    );
}

#[test]
fn channel() {
    expect("channel", &[], &["host sent  99, sandbox answered 9801", "sandbox: exit 0"]);
}

#[test]
fn net_policy() {
    expect(
        "net-policy",
        &[],
        &[
            "-> 'hello from the host!'",
            "allows port",
            "Connection refused",
            "resolve elsewhere.test -> refused (no such name)",
            "sandbox: exit 0",
        ],
    );
}

#[test]
fn threads() {
    let out = expect("threads", &[], &["native: compute", "coroutine: compute", "threaded: compute"]);
    assert!(!out.contains("killed") && !out.contains("exit "), "a run failed:\n{out}");
}

#[test]
fn escape() {
    let out = expect("escape", &[], &["killed by SIGSYS", "getppid(), trapped"]);
    if out.starts_with("skipped:") {
        return;
    }
    // Each attempt's forbidden call kills its sandbox: none survives, and each was killed.
    assert!(!out.contains("survived"), "an attempt survived:\n{out}");
    assert_eq!(out.matches("killed by SIGSYS").count(), 3, "every attempt killed:\n{out}");
}
