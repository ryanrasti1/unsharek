//! The project's tasks, `cargo xtask <task> [args]` (the alias is .cargo/config.toml's), run
//! from the workspace's root inside the devshell (direnv's `.envrc`, or `nix develop -c`):
//!
//! - `test [nextest args]`: every test, incremental, seconds warm: the unit tests, the in-guest
//!   tests (a sandbox per test) and the host-side suite, natively and in each mode; then
//!   seccomp-fn's workspace, unless args picked tests. E.g. `-E 'test(/::fork$/)'` (one mode of
//!   the suite), `-E 'binary(guest_fork)'`, `-E 'test(/^escape/)'`, `--no-fail-fast`.
//! - `perf [nextest args]`: the performance budgets (crates/unsharek/tests/perf.rs), release.
//! - `prove [kani args]`: Kani's proofs, each `policy!` harness (seccomp-fn's examples,
//!   unsharek-tcb's filter, a harness per mode); minutes.
//! - `vs-native [args]`: each mode against native on build workloads (bench/quick.py).
//!
//! Any step's failure is the task's: its exit status is nonzero.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let task = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    let steps: Vec<Command> = match task.as_str() {
        "test" => {
            let mut s = vec![cargo(&["nextest", "run", "--workspace", "--no-tests=warn"], &rest)];
            // seccomp-fn, its own workspace (its fast checks, and run_bpf against the kernel)
            if rest.is_empty() {
                s.push(cargo(&["nextest", "run", "--manifest-path", "seccomp-fn/Cargo.toml", "--workspace", "--no-tests=warn"], &[]));
            }
            s
        }
        // The budgets are release numbers, measured one at a time (nextest's perf profile).
        "perf" => vec![cargo(&["nextest", "run", "--workspace", "--no-tests=warn", "--profile", "perf", "--release"], &rest)],
        // -j: the harnesses in parallel (one per mode and shape; each a minute or two alone)
        "prove" => vec![
            cargo(&["kani", "--manifest-path", "seccomp-fn/Cargo.toml", "-p", "seccomp-fn", "--tests", "-j", "--output-format=terse"], &rest),
            cargo(&["kani", "-p", "unsharek-tcb", "-j", "--output-format=terse"], &rest),
        ],
        "vs-native" => {
            let mut c = Command::new(root().join("bench/quick"));
            c.args(&rest);
            vec![c]
        }
        _ => {
            eprintln!("usage: cargo xtask test|perf|prove|vs-native [args] (xtask/src/main.rs)");
            return ExitCode::from(2);
        }
    };
    for mut step in steps {
        step.current_dir(root());
        match step.status() {
            Ok(s) if s.success() => {}
            Ok(s) => return ExitCode::from(s.code().map_or(1, |c| c.clamp(1, 255) as u8)),
            Err(e) => {
                eprintln!("xtask: {:?}: {e}", step.get_program());
                return ExitCode::from(1);
            }
        }
    }
    ExitCode::SUCCESS
}

fn cargo(args: &[&str], rest: &[String]) -> Command {
    let mut c = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
    c.args(args).args(rest);
    c
}

/// The workspace's root: this crate's parent.
fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).parent().unwrap().to_owned()
}
