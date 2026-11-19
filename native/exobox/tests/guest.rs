//! The library's layers below the CLI, each in a process of its own (a guest takes its process
//! over): this binary re-runs itself as the child, which boots the layer and runs a fixture.
//!
//! - Layer 1, `Guest` with only the routing filter: a program runs and its syscalls are the
//!   guest's (hello: files, TCP, threads, memory), and the gate is not filtered (escape_kill's
//!   `openat` through it reaches the host and succeeds).
//! - Layer 3, `Sandbox`: the same gate call is refused once the mode's filter is stacked on the
//!   routing one (deny=errno: EPERM, the program survives to say so).
//! - `Sandbox::pass_fd`: a host socket as guest fd 1000 (fd_echo answers on it); and a thread
//!   blocked reading it doesn't keep its process from ending (group_exit), in each mode.

use std::ffi::OsString;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use exobox_fixtures as fx;
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

const CHILD: &str = "EXOBOX_GUEST_TEST_CHILD";
/// The child's mode (`coroutine`, the default, or `threaded`) and the fixture's arguments
/// (space-separated).
const CHILD_MODE: &str = "EXOBOX_GUEST_TEST_MODE";
const CHILD_ARGS: &str = "EXOBOX_GUEST_TEST_ARGS";

/// The hooks: only the closure's images mounted, before the exec.
fn setup(mounts: Vec<(exobox::Image, PathBuf)>) -> exobox::Hooks {
    exobox::Hooks { pre_exec: exobox::PreExec::new(move || exobox::setup::mount_closure(&mounts)), ..Default::default() }
}

/// The child: boot `layer`, mount the fixtures' closure, run fixture `name`.
fn child(layer: &str, name: &str) -> ! {
    let program = fx::bin(name);
    let config = exobox::Config {
        argv: vec![program.clone().into()],
        allow_paths: vec![fx::bin_dir()],
        image_cache: std::env::var_os("EXOBOX_GUEST_TEST_CACHE").map(PathBuf::from),
        ..Default::default()
    };
    let store = exobox::store(&config).unwrap();
    let mode = std::env::var(CHILD_MODE).unwrap_or_else(|_| "coroutine".into());
    let mut argv: Vec<OsString> = vec![program.into()];
    argv.extend(std::env::var(CHILD_ARGS).unwrap_or_default().split_whitespace().map(OsString::from));
    let env: Vec<OsString> = vec![format!("EXOBOX_TEST_MODE={mode}").into()];
    let e = match layer {
        "guest" => {
            let mut g = exobox::Guest::boot(exobox::GuestConfig::default()).unwrap();
            let mounts: Vec<_> = store.mounts.iter().map(|m| (g.map_image(&m.image).unwrap(), m.guest.clone())).collect();
            g.run(setup(mounts), &argv, &env).unwrap_err()
        }
        _ => {
            let m = if mode == "threaded" { exobox::Mode::Threaded } else { exobox::Mode::Coroutine };
            let mut sb = exobox::Sandbox::boot(m, exobox::GuestConfig::default()).unwrap();
            sb.deny(exobox::Deny::Errno);
            if layer == "passfd" {
                // The parent's socketpair end, inherited at fd 3 (`run_passfd`), as guest fd 1000.
                // SAFETY: fd 3 is this process's, from the parent, and nothing else owns it.
                sb.pass_fd(unsafe { std::os::fd::OwnedFd::from_raw_fd(3) }, 1000);
            }
            let mounts: Vec<_> = store.mounts.iter().map(|m| (sb.map_image(&m.image).unwrap(), m.guest.clone())).collect();
            sb.run(setup(mounts), &argv, &env).unwrap_err()
        }
    };
    eprintln!("exobox: {e}");
    std::process::exit(125)
}

fn run(layer: &str, name: &str) -> Result<(i32, String, String), Failed> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.env(CHILD, format!("{layer}:{name}"))
        .env("EXOBOX_GUEST_TEST_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, _, out, err) = common::spawn_bounded(cmd, None, Duration::from_secs(10))?;
    Ok((status.code().unwrap_or(-1), out, err))
}

/// The `passfd` layer: a socketpair, one end the child's fd 3; `send` sent before it starts (none:
/// the socket stays open and silent while it runs), the answer read after it ends. The child runs
/// `fixture args` in `mode`.
fn run_passfd(
    mode: &str,
    fixture: &str,
    args: &str,
    send: Option<&[u8]>,
) -> Result<(std::process::ExitStatus, String, String, String), Failed> {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::os::unix::process::CommandExt;
    let (mut ours, theirs) = UnixStream::pair()?;
    if let Some(b) = send {
        ours.write_all(b)?;
    }
    let theirs_fd = theirs.as_raw_fd();
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.env(CHILD, format!("passfd:{fixture}"))
        .env(CHILD_MODE, mode)
        .env(CHILD_ARGS, args)
        .env("EXOBOX_GUEST_TEST_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    // SAFETY: dup2 between fork and exec, async-signal-safe.
    unsafe {
        cmd.pre_exec(move || if libc::dup2(theirs_fd, 3) < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) });
    }
    let (status, _, out, err) = common::spawn_bounded(cmd, None, Duration::from_secs(10))?;
    drop(theirs);
    ours.set_nonblocking(true)?;
    let mut answer = vec![0; 64];
    let n = ours.read(&mut answer).unwrap_or(0);
    Ok((status, out, err, String::from_utf8_lossy(&answer[..n]).into_owned()))
}

fn main() {
    if let Ok(what) = std::env::var(CHILD) {
        let (layer, name) = what.split_once(':').unwrap();
        child(layer, name);
    }
    let args = Arguments::from_args();
    let mut trials = vec![
        Trial::test("sandbox_pass_fd", || {
            let (st, out, err, answer) = run_passfd("coroutine", "fd_echo", "", Some(b"ping"))?;
            if st.code() != Some(0) || !out.contains("FD_ECHO_OK") || answer != "got:ping" {
                return Err(format!("{st:?}, answer {answer:?}\n{out}\n{err}").into());
            }
            Ok(())
        }),
        Trial::test("guest_runs_hello", || {
            let (code, out, err) = run("guest", "hello")?;
            if code != 0 || !out.contains("HELLO_OK") {
                return Err(format!("exit {code}\n{out}\n{err}").into());
            }
            Ok(())
        }),
        Trial::test("guest_gate_is_unfiltered", || {
            // Routing only: openat("/") through the gate is the host's, and succeeds.
            let (code, out, err) = run("guest", "escape_kill")?;
            let fd = out.trim().strip_prefix("ESCAPE_KILL_SURVIVED ").and_then(|v| v.parse::<i64>().ok());
            if code != 1 || !fd.is_some_and(|fd| fd >= 0) {
                return Err(format!("wanted the gate's openat to succeed: exit {code}\n{out}\n{err}").into());
            }
            Ok(())
        }),
        Trial::test("sandbox_gate_is_filtered", || {
            // The mode's filter stacked: the same call is EPERM (deny=errno).
            let (code, out, err) = run("sandbox", "escape_kill")?;
            if code != 1 || out.trim() != "ESCAPE_KILL_SURVIVED -1" {
                return Err(format!("wanted EPERM from the gate: exit {code}\n{out}\n{err}").into());
            }
            Ok(())
        }),
    ];
    // A thread blocked reading the passed fd (open, silent) while main exits with 3, or dies of
    // SIGTERM: the process ends so, within the timeout (capnix's app hung on its fd 1000).
    for mode in ["coroutine", "threaded"] {
        for (how, want) in [("exit", (Some(3), None)), ("signal", (None, Some(15)))] {
            trials.push(Trial::test(format!("pass_fd_reader_{how}::{mode}"), move || {
                use std::os::unix::process::ExitStatusExt;
                let (st, out, err, _) = run_passfd(mode, "group_exit", &format!("fd1000,futex {how}"), None)?;
                if (st.code(), st.signal()) != want || !out.contains("GROUP_EXIT_READY") || out.contains("reader of fd") {
                    return Err(format!("{st:?}, wanted {want:?}\n{out}\n{err}").into());
                }
                Ok(())
            }));
        }
    }
    libtest_mimic::run(&args, trials).exit();
}
