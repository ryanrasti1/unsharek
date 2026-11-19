//! The library below the CLI, each case in a process of its own (a guest takes its process over):
//! this binary re-runs itself as the child, which builds a guest or sandbox and runs a fixture.
//!
//! - Layer 1, `Guest` with only the routing filter: a program runs and its syscalls are the
//!   guest's (hello: files, TCP, threads, memory), and the gate is not filtered (escape_kill's
//!   `openat` through it reaches the host and succeeds).
//! - Layer 3, `Sandbox`: the same gate call is refused once the mode's filter is stacked on the
//!   routing one (deny=errno: EPERM, the program survives to say so).
//! - `Sandbox::pass_fd`: a host socket as guest fd 1000 (fd_echo answers on it); and a thread
//!   blocked reading it doesn't keep its process from ending (group_exit), in each mode.
//! - `Sandbox::intercept`: what a guard routes (getpid, files, ids, the hostname) and what the
//!   host code between guards still does as the host's (passthrough: files, a thread, a signal
//!   handler, the signal mask, a fork, a refused exec), several guards in a row.
//! - `Builder::restrict`: a restriction makes a call the mode allows fail (write to fd 2, from
//!   the gate: killed, or EPERM), and leaves the mode's own probes as they were (escape_gate).
//! - `Cache::images` and `setup::mount_closure` with store paths that are a file and a symlink
//!   (`store_entries`): each shown at its store path as it is.
//! - Templates (`Sandbox::spawn`): children of one setup, each running its own fixture and its
//!   own setup, with random bytes of their own.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use exobox::{Deny, Mode, Sandbox, SockFilter};
use exobox_fixtures as fx;
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

const CHILD: &str = "EXOBOX_GUEST_TEST_CHILD";
/// The child's mode (`coroutine`, the default, or `threaded`) and the fixture's arguments
/// (space-separated).
const CHILD_MODE: &str = "EXOBOX_GUEST_TEST_MODE";
const CHILD_ARGS: &str = "EXOBOX_GUEST_TEST_ARGS";

fn mode() -> (Mode, String) {
    let m = std::env::var(CHILD_MODE).unwrap_or_else(|_| "coroutine".into());
    let mode = match m.as_str() {
        "threaded" => Mode::Threaded,
        "fork" => Mode::Fork,
        _ => Mode::Coroutine,
    };
    (mode, m)
}

fn argv(name: &str) -> Vec<OsString> {
    let mut argv: Vec<OsString> = vec![fx::bin(name).into()];
    argv.extend(std::env::var(CHILD_ARGS).unwrap_or_default().split_whitespace().map(OsString::from));
    argv
}

fn env() -> Vec<OsString> {
    vec![format!("EXOBOX_TEST_MODE={}", mode().1).into(), format!("EXOBOX_TEST_TARGET={}", std::os::unix::process::parent_id()).into()]
}

fn check(what: &str, ok: bool) {
    println!("{what}: {}", if ok { "ok" } else { "FAIL" });
}

/// `write` to fd 2 from anywhere: killed (or EPERM, with `errno`), everything else allowed. A
/// restriction as a caller writes one: classic BPF over seccomp_data (nr at 0, args[0] at 16).
fn no_stderr(errno: bool) -> Vec<SockFilter> {
    let i = |code, jt, jf, k| SockFilter { code, jt, jf, k };
    let deny = if errno { 0x0005_0000 | 1 } else { 0x8000_0000 };
    vec![
        i(0x20, 0, 0, 0),                                // nr
        i(0x15, 0, 3, libc::SYS_write as u32),           // write? else allow
        i(0x20, 0, 0, 16),                               // args[0], low half
        i(0x15, 0, 1, 2),                                // fd 2? else allow
        i(0x06, 0, 0, deny),
        i(0x06, 0, 0, 0x7fff_0000),
    ]
}

/// The child: `layer` set up, then fixture `name` run.
fn child(layer: &str, name: &str) -> ! {
    let (m, _) = mode();
    let program = fx::bin(name);
    let allow = [fx::bin_dir()];
    let e = match layer {
        "guest" => {
            let mut g = exobox::Guest::boot(exobox::GuestConfig::default()).unwrap();
            let mounts = g.map_closure(&program, &allow).unwrap();
            {
                let _g = g.intercept().unwrap();
                exobox::setup::mount_closure(&mounts).unwrap();
            }
            g.run(&argv(name), &env()).unwrap_err()
        }
        "intercept" => intercept(m, name),
        "entries" => entries(m),
        "template" => template(m),
        "run_fn" => run_fn(m, name),
        _ => {
            let mut b = Sandbox::builder().mode(m).deny(Deny::Errno);
            match layer {
                "restrict_kill" => b = Sandbox::builder().mode(m).restrict(no_stderr(false)),
                "restrict_errno" => b = b.restrict(no_stderr(true)),
                _ => {}
            }
            let mut sb = b.build().unwrap();
            if layer == "passfd" {
                // The parent's socketpair end, inherited at fd 3 (`run_passfd`), as guest fd 1000.
                // SAFETY: fd 3 is this process's, from the parent, and nothing else owns it.
                sb.pass_fd(unsafe { std::os::fd::OwnedFd::from_raw_fd(3) }, 1000).unwrap();
            }
            let mounts = sb.map_closure(&program, &allow).unwrap();
            {
                let _g = sb.intercept().unwrap();
                exobox::setup::mount_closure(&mounts).unwrap();
            }
            sb.run(&argv(name), &env()).unwrap_err()
        }
    };
    eprintln!("exobox: {e}");
    std::process::exit(125)
}

/// Guards and the host code around them, then `name` (creds) run as uid 1000 on host `box`.
fn intercept(m: Mode, name: &str) -> exobox::Error {
    let host_file = std::env::var("EXOBOX_GUEST_TEST_FILE").unwrap();
    let mut sb = Sandbox::builder().mode(m).build().unwrap();
    let mounts = sb.map_closure(&fx::bin(name), &[fx::bin_dir()]).unwrap();
    let pid = std::process::id();
    // SAFETY: getpid.
    let getpid = || unsafe { libc::getpid() } as u32;
    check("before: getpid is the host's", getpid() == pid);
    {
        let _g = sb.intercept().unwrap();
        check("guard 1: getpid is init's", getpid() == 1);
        check("guard 1: the host's file isn't there", !std::path::Path::new(&host_file).exists());
        exobox::setup::mount_closure(&mounts).unwrap();
        std::fs::write("/exobox-guard-test", "made in guard 1").unwrap();
    }
    check("after 1: getpid is the host's", getpid() == pid);
    check("after 1: a host file reads", std::fs::read_to_string(&host_file).is_ok_and(|s| s == "host data"));
    check("after 1: the guest's file isn't the host's", !std::path::Path::new("/exobox-guard-test").exists());
    // A thread made now inherits the routing filter: its calls pass through too.
    let t = std::thread::spawn(move || std::fs::read_to_string(&host_file).ok()).join().unwrap();
    check("after 1: a thread reads a host file", t.as_deref() == Some("host data"));
    // A host signal handler runs, and returns (its rt_sigreturn trapped and made again).
    static GOT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    extern "C" fn on_usr1(_: i32) {
        GOT.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    // SAFETY: a handler that only stores to an atomic; raise to ourselves.
    unsafe {
        libc::signal(libc::SIGUSR1, on_usr1 as *const () as libc::sighandler_t);
        libc::raise(libc::SIGUSR1);
    }
    check("after 1: a host signal handler ran and returned", GOT.load(std::sync::atomic::Ordering::SeqCst));
    // The mask: blocked, read back, unblocked (the frame's mask, which the trap's return restores).
    // SAFETY: sigprocmask on local sets.
    let masked = unsafe {
        let (mut set, mut old) = (std::mem::zeroed::<libc::sigset_t>(), std::mem::zeroed::<libc::sigset_t>());
        libc::sigemptyset(&mut set);
        libc::sigaddset(&mut set, libc::SIGUSR2);
        libc::sigprocmask(libc::SIG_BLOCK, &set, std::ptr::null_mut());
        libc::sigprocmask(libc::SIG_UNBLOCK, &set, &mut old);
        libc::sigismember(&old, libc::SIGUSR2) == 1
    };
    check("after 1: sigprocmask keeps the mask", masked);
    // A host fork: the child returns from it as the parent does.
    // SAFETY: fork; the child only exits.
    let c = unsafe { libc::fork() };
    if c == 0 {
        // SAFETY: the child ends at once.
        unsafe { libc::_exit(7) };
    }
    let st = exobox::wait(c as u32).ok().and_then(|s| s.code());
    check("after 1: a host fork's child ran", st == Some(7));
    // A host program can't start any more: the filters would follow it into the exec.
    let spawned = Command::new("/bin/sh").arg("-c").arg("true").status();
    check("after 1: exec is refused", spawned.is_err());
    {
        let _g = sb.intercept().unwrap();
        check("guard 2: guard 1's file is still there", std::fs::read_to_string("/exobox-guard-test").is_ok_and(|s| s == "made in guard 1"));
        // SAFETY: the guest's init dropping to uid/gid 1000, naming its host, setting its clock
        // (to the host's time: the vDSO's, which a guard's clock_gettime is).
        unsafe {
            check("guard 2: sethostname", libc::sethostname(c"box".as_ptr(), 3) == 0);
            let mut ts = std::mem::zeroed::<libc::timespec>();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            check("guard 2: clock_settime", libc::clock_settime(libc::CLOCK_REALTIME, &ts) == 0);
            let tv = libc::timeval { tv_sec: ts.tv_sec, tv_usec: ts.tv_nsec / 1000 };
            check("guard 2: settimeofday", libc::settimeofday(&tv, std::ptr::null()) == 0);
            check("guard 2: setresgid", libc::setresgid(1000, 1000, 1000) == 0);
            check("guard 2: setresuid", libc::setresuid(1000, 1000, 1000) == 0);
        }
    }
    {
        let _g = sb.intercept().unwrap();
        // uid 1000 uses /dev's nodes (they were 0644, root's: capnix's build user couldn't write
        // /dev/null).
        check("guard 3: uid 1000 writes /dev/null", std::fs::write("/dev/null", "x").is_ok());
        for dev in ["/dev/zero", "/dev/urandom"] {
            let mut b = [0u8; 16];
            let read = std::fs::File::open(dev).and_then(|mut f| f.read_exact(&mut b));
            check(&format!("guard 3: uid 1000 reads {dev}"), read.is_ok());
        }
        // A guard's clock_settime is the guest kernel's, which asks for CAP_SYS_TIME: uid 1000
        // has none. (The program's gets sysmap's EPERM whoever it is: sysaudit.)
        // SAFETY: a timespec of the host's time.
        unsafe {
            let mut ts = std::mem::zeroed::<libc::timespec>();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            check("guard 3: uid 1000 can't set the clock", libc::clock_settime(libc::CLOCK_REALTIME, &ts) != 0);
        }
    }
    check("after 2: getpid is the host's", getpid() == pid);
    sb.run(&argv(name), &env()).unwrap_err()
}

/// Store-like paths (`ENTRIES`, in a temporary directory: the suite can't count on a store path
/// that is a file being on the host) given as store paths, as capnix gives a build's inputs from
/// its real store directory: their images from the cache, each shown at `/nix/store/<name>`; then
/// `paths` run on them.
const ENTRIES: [&str; 3] =
    ["0000000000000000000000000000000f-entry-file", "0000000000000000000000000000000l-entry-link", "0000000000000000000000000000000d-entry-dir"];

fn entries(m: Mode) -> exobox::Error {
    let dir = PathBuf::from(std::env::var("EXOBOX_GUEST_TEST_FILE").unwrap());
    let closure = exobox::store::Closure { store: ENTRIES.iter().map(|n| dir.join(n)).collect(), host: Default::default() };
    let mut store = exobox::store::Cache::open_default().unwrap().images(&closure).unwrap();
    for m in &mut store.mounts {
        m.guest = std::path::Path::new("/nix/store").join(m.guest.file_name().unwrap());
    }
    let mut sb = Sandbox::builder().mode(m).build().unwrap();
    let mut mounts = sb.map_store(&store).unwrap();
    mounts.extend(sb.map_closure(&fx::bin("paths"), &[fx::bin_dir()]).unwrap());
    {
        let _g = sb.intercept().unwrap();
        exobox::setup::mount_closure(&mounts).unwrap();
    }
    let mut argv = argv("paths");
    argv.extend(ENTRIES.iter().map(|n| format!("/nix/store/{n}").into()));
    sb.run(&argv, &env()).unwrap_err()
}

/// A template: one setup, then four children in turn, each with setup of its own and its own
/// fixture. Prints each one's status; their output is theirs (stdout, in turn).
/// `Sandbox::run_fn`: a closure run as the program, after lockdown. `ok`: its calls are the
/// guest's (init's pid, the guest's files, no host path), a host fd from before lockdown is
/// closed, and its return value is the status (42). `gate`: a host call from the gate is the
/// security filter's (EPERM with deny=errno, which `ok` doesn't set: the kill is checked by
/// `run_fn_gate_kills`).
fn run_fn(m: Mode, what: &str) -> exobox::Error {
    let deny = if what == "errno" { Deny::Errno } else { Deny::Kill };
    let sb = Sandbox::builder().mode(m).deny(deny).build().unwrap();
    // A host fd opened now, before lockdown: the closure finds it closed.
    let before = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
    let before_fd = before.as_raw_fd();
    std::mem::forget(before);
    let host_path = env!("CARGO_MANIFEST_DIR");
    let what = what.to_owned();
    let Err(e) = sb.run_fn(move || {
        // SAFETY: getpid; fcntl on a number.
        check("run_fn: getpid is init's", unsafe { libc::getpid() } == 1);
        check("run_fn: the guest's files", std::fs::write("/tmp/run_fn", "x").is_ok() && std::fs::read("/tmp/run_fn").is_ok_and(|b| b == b"x"));
        check("run_fn: no host path", !std::path::Path::new(host_path).exists());
        check("run_fn: memory", vec![7u8; 1 << 20].iter().map(|&b| b as usize).sum::<usize>() == 7 << 20);
        let gate = find_gate();
        // The host fd from before: closed at lockdown. ppoll is on the list (any fd: it moves no
        // data), and says POLLNVAL for an fd that isn't open; stdin, which is, isn't.
        let poll = |fd: i32| {
            let mut p = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
            let ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
            let r = gate_call4(gate, libc::SYS_ppoll, [&mut p as *mut _ as usize, 1, &ts as *const _ as usize, 0]);
            (r, p.revents)
        };
        check("run_fn: a host fd from before lockdown is closed", poll(before_fd) == (1, libc::POLLNVAL));
        check("run_fn: stdin is open", poll(0).1 & libc::POLLNVAL == 0);
        if what == "errno" {
            // Not on the list: EPERM.
            check("run_fn: the gate's getppid is refused", gate_call(gate, libc::SYS_getppid, 0, 0) == -(libc::EPERM as isize));
            return 42;
        }
        if what == "kill" {
            gate_call(gate, libc::SYS_getppid, 0, 0);
            println!("run_fn: survived the gate");
        }
        42
    });
    e
}

/// The gate's `syscall` instruction, found in the binary's code: `mov r9, [rsp + 8]; syscall;
/// ret` (exobox-rt's `trap::gate`), as a compromised program would find it.
fn find_gate() -> usize {
    unsafe extern "C" {
        static __executable_start: u8;
        static etext: u8;
    }
    const TAIL: [u8; 8] = [0x4c, 0x8b, 0x4c, 0x24, 0x08, 0x0f, 0x05, 0xc3];
    let (lo, hi) = (&raw const __executable_start as usize, &raw const etext as usize);
    // SAFETY: the binary's own code, readable.
    let text = unsafe { std::slice::from_raw_parts(lo as *const u8, hi - lo) };
    lo + text.windows(8).position(|w| w == TAIL).expect("the gate") + 5
}

fn gate_call(gate: usize, nr: i64, a0: usize, a1: usize) -> isize {
    gate_call4(gate, nr, [a0, a1, 0, 0])
}

fn gate_call4(gate: usize, nr: i64, a: [usize; 4]) -> isize {
    let r: isize;
    // SAFETY: the gate's `syscall; ret`: whatever it does is the filter's to allow.
    unsafe {
        std::arch::asm!("call {g}", g = in(reg) gate, inlateout("rax") nr as isize => r, in("rdi") a[0], in("rsi") a[1],
            in("rdx") a[2], in("r10") a[3], in("r8") 0, in("r9") 0, lateout("rcx") _, lateout("r11") _);
    }
    r
}

fn template(m: Mode) -> exobox::Error {
    let mut sb = Sandbox::builder().mode(m).build().unwrap();
    let mounts = sb.map_closure(&fx::bin("hello"), &[fx::bin_dir()]).unwrap();
    {
        let _g = sb.intercept().unwrap();
        exobox::setup::mount_closure(&mounts).unwrap();
        std::fs::create_dir_all("/etc").unwrap();
        std::fs::write("/etc/template", "shared").unwrap();
    }
    // The last dies of SIGABRT: a child's death by a signal is its own (its pid, not the
    // template's, is the one the runtime and the filter's `kill` name).
    let runs: [(&str, &[&str]); 5] =
        [("creds", &[]), ("creds", &[]), ("hello", &[]), ("exit_status", &["exit42"]), ("exit_status", &["abort"])];
    for (n, (fixture, args)) in runs.iter().enumerate() {
        let child = sb
            .spawn(move |mut sb| {
                {
                    let _g = sb.intercept()?;
                    let host = format!("child-{n}");
                    // SAFETY: a NUL-free name, its length.
                    unsafe { libc::sethostname(host.as_ptr().cast(), host.len()) };
                    assert_eq!(std::fs::read_to_string("/etc/template")?, "shared");
                }
                let mut argv: Vec<OsString> = vec![fx::bin(fixture).into()];
                argv.extend(args.iter().map(OsString::from));
                sb.run(&argv, &env())
            })
            .unwrap();
        let st = child.wait().unwrap();
        use std::os::unix::process::ExitStatusExt;
        println!("CHILD {n} {fixture} status {:?} signal {:?}", st.code(), st.signal());
    }
    std::process::exit(0)
}

fn run(layer: &str, name: &str, mode: &str, extra: &[(&str, &str)]) -> Result<(std::process::ExitStatus, String, String), Failed> {
    let mut cmd = Command::new(std::env::current_exe()?);
    cmd.env(CHILD, format!("{layer}:{name}"))
        .env(CHILD_MODE, mode)
        .env("EXOBOX_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
        .envs(extra.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let (status, _, out, err) = common::spawn_bounded(cmd, None, Duration::from_secs(10))?;
    Ok((status, out, err))
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
    use std::io::Write;
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
        .env("EXOBOX_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
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

fn fail(st: std::process::ExitStatus, out: &str, err: &str, why: &str) -> Result<(), Failed> {
    Err(format!("{why}: {st:?}\n--- stdout:\n{out}\n--- stderr:\n{err}").into())
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
            let (st, out, err) = run("guest", "hello", "coroutine", &[])?;
            if st.code() != Some(0) || !out.contains("HELLO_OK") {
                return fail(st, &out, &err, "wanted HELLO_OK");
            }
            Ok(())
        }),
        Trial::test("guest_gate_is_unfiltered", || {
            // Routing only: openat("/") through the gate is the host's, and succeeds.
            let (st, out, err) = run("guest", "escape_kill", "coroutine", &[])?;
            let fd = out.trim().strip_prefix("ESCAPE_KILL_SURVIVED ").and_then(|v| v.parse::<i64>().ok());
            if st.code() != Some(1) || !fd.is_some_and(|fd| fd >= 0) {
                return fail(st, &out, &err, "wanted the gate's openat to succeed");
            }
            Ok(())
        }),
        Trial::test("sandbox_gate_is_filtered", || {
            // The mode's filter stacked: the same call is EPERM (deny=errno).
            let (st, out, err) = run("sandbox", "escape_kill", "coroutine", &[])?;
            if st.code() != Some(1) || out.trim() != "ESCAPE_KILL_SURVIVED -1" {
                return fail(st, &out, &err, "wanted EPERM from the gate");
            }
            Ok(())
        }),
    ];
    for mode in ["coroutine", "threaded", "fork"] {
        trials.push(Trial::test(format!("run_fn::{mode}"), move || {
            let (st, out, err) = run("run_fn", "ok", mode, &[])?;
            if st.code() != Some(42) || out.contains("FAIL") || out.matches(": ok").count() != 6 {
                return fail(st, &out, &err, "wanted the closure's checks and status 42");
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("run_fn_gate_errno::{mode}"), move || {
            let (st, out, err) = run("run_fn", "errno", mode, &[])?;
            if st.code() != Some(42) || out.contains("FAIL") || out.matches(": ok").count() != 7 {
                return fail(st, &out, &err, "wanted the gate's calls refused (EPERM)");
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("run_fn_gate_kills::{mode}"), move || {
            use std::os::unix::process::ExitStatusExt;
            let (st, out, err) = run("run_fn", "kill", mode, &[])?;
            if st.signal() != Some(libc::SIGSYS) || out.contains("survived") {
                return fail(st, &out, &err, "wanted the sandbox killed by SIGSYS at the gate's getppid");
            }
            Ok(())
        }));
    }
    for mode in ["coroutine", "threaded"] {
        // A thread blocked reading the passed fd (open, silent) while main exits with 3, or dies
        // of SIGTERM: the process ends so, within the timeout (capnix's app hung on its fd 1000).
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
        trials.push(Trial::test(format!("intercept::{mode}"), move || {
            let dir = tempfile::tempdir()?;
            let file = dir.path().join("host-file");
            std::fs::write(&file, "host data")?;
            let (st, out, err) = run("intercept", "creds", mode, &[("EXOBOX_GUEST_TEST_FILE", file.to_str().unwrap())])?;
            if st.code() != Some(0) || out.contains("FAIL") || !out.contains("CREDS_OK") {
                return fail(st, &out, &err, "a check failed");
            }
            // The program's ids, and its auxiliary vector's, are init's at exec: 1000.
            if !out.contains("CREDS 1000 1000 1000 1000 1000 1000 1000 1000\n") || !out.contains("HOST box\n") {
                return fail(st, &out, &err, "wanted the program as uid/gid 1000 on host box");
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("store_entries::{mode}"), move || {
            // A closure with store paths that are a file and a symlink (to the file), and a
            // directory: each shown at its store path as it is.
            let dir = tempfile::tempdir()?;
            let [file, link, sub] = ENTRIES.map(|n| dir.path().join(n));
            std::fs::write(&file, "a single-file store path\n")?;
            std::fs::set_permissions(&file, std::os::unix::fs::PermissionsExt::from_mode(0o444))?;
            std::os::unix::fs::symlink(ENTRIES[0], &link)?;
            std::fs::create_dir(&sub)?;
            std::fs::write(sub.join("x"), "")?;
            let (st, out, err) = run("entries", "paths", mode, &[("EXOBOX_GUEST_TEST_FILE", dir.path().to_str().unwrap())])?;
            let want = [
                format!("PATH /nix/store/{} file a single-file store path_ 444 ro\n", ENTRIES[0]),
                format!("PATH /nix/store/{} link {} a single-file store path_\n", ENTRIES[1], ENTRIES[0]),
                format!("PATH /nix/store/{} dir\n", ENTRIES[2]),
            ];
            if st.code() != Some(0) || !out.contains("PATHS_OK") || want.iter().any(|w| !out.contains(w.as_str())) {
                return fail(st, &out, &err, &format!("wanted {want:?}"));
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("restrict_kills::{mode}"), move || {
            // write(2) from the gate is the mode's; the restriction kills it.
            use std::os::unix::process::ExitStatusExt;
            let (st, out, err) =
                run("restrict_kill", "exit_status", mode, &[(CHILD_ARGS, "stderr")])?;
            if st.signal() != Some(libc::SIGSYS) || err.contains("to stderr") {
                return fail(st, &out, &err, "wanted the write to stderr killed");
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("restrict_errno::{mode}"), move || {
            // The same, as EPERM: the program goes on (its stderr line lost), and the mode's own
            // probes (escape_gate, deny=errno) are as without the restriction.
            let (st, out, err) = run("restrict_errno", "exit_status", mode, &[(CHILD_ARGS, "stderr")])?;
            if st.code() != Some(3) || err.contains("to stderr") {
                return fail(st, &out, &err, "wanted exit 3 with stderr refused");
            }
            let (st, out, err) = run("restrict_errno", "escape_gate", mode, &[])?;
            if st.code() != Some(0) || !out.contains("ESCAPE_GATE_OK") {
                return fail(st, &out, &err, "wanted escape_gate's probes to pass under the restriction");
            }
            Ok(())
        }));
        trials.push(Trial::test(format!("template::{mode}"), move || {
            let (st, out, err) = run("template", "-", mode, &[])?;
            let statuses: Vec<&str> = out.lines().filter(|l| l.starts_with("CHILD ")).collect();
            let want = [
                "CHILD 0 creds status Some(0) signal None",
                "CHILD 1 creds status Some(0) signal None",
                "CHILD 2 hello status Some(0) signal None",
                "CHILD 3 exit_status status Some(42) signal None",
                "CHILD 4 exit_status status None signal Some(6)",
            ];
            if st.code() != Some(0) || statuses != want || !out.contains("HELLO_OK") {
                return fail(st, &out, &err, "wanted five children, their statuses theirs");
            }
            let random: Vec<&str> = out.lines().filter(|l| l.starts_with("RANDOM ")).collect();
            if random.len() != 2 || random[0] == random[1] {
                return fail(st, &out, &err, "wanted two children's random bytes to differ");
            }
            if !out.contains("HOST child-0\n") || !out.contains("HOST child-1\n") {
                return fail(st, &out, &err, "wanted each child's own setup (its hostname)");
            }
            Ok(())
        }));
    }
    libtest_mimic::run(&args, trials).exit();
}
