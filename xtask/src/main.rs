//! The project's tasks, `cargo xtask <task> [args]` (the alias is .cargo/config.toml's), run
//! from the workspace's root inside the devshell (direnv's `.envrc`, or `nix develop -c`):
//!
//! - `test [nextest args]`: every test, incremental, seconds warm: the unit tests, the in-guest
//!   tests (a sandbox per test) and the host-side suite, natively and in each mode (seccomp-fn-verify's
//!   among them: a member). E.g. `-E 'test(/::fork$/)'` (one mode of
//!   the suite), `-E 'binary(guest_fork)'`, `-E 'test(/^escape/)'`, `--no-fail-fast`.
//! - `perf [nextest args]`: the performance budgets (crates/unsharek/tests/perf.rs), release.
//! - `test-docker`: unsharek in a Docker image (examples/docker/test.sh): under Docker's default
//!   seccomp profile, a map, ro and ro --no-landlock mount and --net host; skipped without a
//!   daemon.
//! - `prove [kani args]`: Kani's proofs: seccomp-fn-verify's (its compiler, proven once for every
//!   tree, and the tree's lemmas) and unsharek-tcb's `tree_is_policy` (a harness per mode and
//!   plugin choice); minutes.
//! - `vs-native [args]`: each mode against native on build workloads (bench/quick.py).
//! - `calls`: seccomp-fn-verify's typed syscall table (seccomp-fn-verify/src/calls.rs) from mainline
//!   Linux's sources (calls.rs, nix/linux-syscalls.nix).
//! - `stats [args]`: the headline numbers (memory, startup, a syscall, CPU) into bench/STATS.md
//!   (bench/stats.py); minutes, on a quiet machine.
//!
//! Any step's failure is the task's: its exit status is nonzero.

use std::path::PathBuf;
use std::process::{Command, ExitCode};

mod calls;

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let task = args.next().unwrap_or_default();
    let rest: Vec<String> = args.collect();
    if task == "calls" {
        return match calls::run(&root()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("xtask calls: {e}");
                ExitCode::from(1)
            }
        };
    }
    let steps: Vec<Command> = match task.as_str() {
        "test" => {
            // (seccomp-fn, the macro, is its own workspace and repository: its tests are its own;
            // here it is a path dependency, exercised by unsharek-tcb's.)
            vec![cargo(&["nextest", "run", "--workspace", "--no-tests=warn"], &rest)]
        }
        // The budgets are release numbers, measured one at a time (nextest's perf profile).
        "perf" => vec![cargo(&["nextest", "run", "--workspace", "--no-tests=warn", "--profile", "perf", "--release"], &rest)],
        // -j: the harnesses in parallel (one per mode and shape; each a minute or two alone)
        "prove" => vec![
            cargo(&["kani", "-p", "seccomp-fn-verify", "-j", "2", "--output-format=terse", "--no-assertion-reach-checks"], &rest),
            cargo(&["kani", "-p", "unsharek-tcb", "-j", "2", "--output-format=terse"], &rest),
        ],
        "test-docker" => vec![Command::new(root().join("examples/docker/test.sh"))],
        "vs-native" | "stats" => {
            let mut c = Command::new(root().join(if task == "stats" { "bench/stats" } else { "bench/quick" }));
            c.args(&rest);
            vec![c]
        }
        _ => {
            eprintln!("usage: cargo xtask test|test-docker|perf|prove|calls|vs-native|stats [args] (xtask/src/main.rs)");
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
