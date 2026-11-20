//! What the examples share: plain host-process plumbing. Nothing here hides unsharek's API.
//!
//! A sandbox takes its process over (`run` never returns, and the process ends with the
//! program's status), so an example that wants to watch or talk to a sandbox forks it off as a
//! template's child (`Guest::spawn`: `channel`, `net-policy`) and stays the parent. One that
//! wants sandboxes of different configurations (one guest per process: `escape`, `threads`), or
//! a cold one measured from outside (`nix-program`), re-runs itself as a child in a "role"
//! ([`role`], [`self_command`]).

pub mod mux;

use std::ffi::OsString;
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;


const ROLE: &str = "UNSHAREK_EXAMPLE_ROLE";

/// This process's role, when an example re-ran itself as a child.
pub fn role() -> Option<String> {
    std::env::var(ROLE).ok()
}

/// This example again, as a child in `role`.
pub fn self_command(role: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().expect("current_exe"));
    c.env(ROLE, role);
    c
}

/// Gives the child `fd` as its fd `at` (dup2 between fork and exec, so the parent's copy keeps
/// its close-on-exec and only the child has it).
pub fn give_fd(cmd: &mut Command, fd: &impl AsRawFd, at: RawFd) {
    let fd = fd.as_raw_fd();
    // SAFETY: dup2 and fcntl are async-signal-safe. (If `fd` is `at` already, dup2 does nothing
    // and close-on-exec stays: cleared instead.)
    unsafe {
        cmd.pre_exec(move || {
            let r = if fd == at { libc::fcntl(at, libc::F_SETFD, 0) } else { libc::dup2(fd, at) };
            if r < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
        });
    }
}

/// A nixpkgs program named by a devshell variable (`UNSHAREK_TEST_PYTHON`, ...), or a clean skip.
pub fn nix_program(var: &str) -> PathBuf {
    match std::env::var_os(var) {
        Some(p) => p.into(),
        None => {
            println!("skipped: ${var} is unset (run inside the devshell: direnv, or `nix develop`)");
            std::process::exit(0)
        }
    }
}

/// Small workloads, for the smoke tests (`tests/smoke.rs` sets it).
pub fn quick() -> bool {
    std::env::var_os("UNSHAREK_EXAMPLE_QUICK").is_some()
}

/// After a sandbox's start failed: before the program started, so the error is ours to report.
/// (After lockdown, stderr and exit still work, through the guest.)
pub fn fail(e: unsharek::Error) -> ! {
    eprintln!("unsharek: {e}");
    std::process::exit(125)
}

/// Strings as argv/env.
pub fn os(v: &[&str]) -> Vec<OsString> {
    v.iter().map(OsString::from).collect()
}

/// A process's proportional set size (its share of the pages it maps), in KB.
pub fn pss_kb(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).ok()?;
    s.lines().find_map(|l| l.strip_prefix("Pss:")?.trim().strip_suffix("kB")?.trim().parse().ok())
}

/// How a child ended, as a shell would say it.
pub fn describe(status: std::process::ExitStatus) -> String {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(c), _) => format!("exit {c}"),
        (_, Some(libc::SIGSYS)) => "killed by SIGSYS (the host filter)".into(),
        (_, Some(s)) => format!("killed by signal {s}"),
        _ => format!("{status}"),
    }
}
