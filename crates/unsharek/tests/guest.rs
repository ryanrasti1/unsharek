//! The library below the CLI, each case in a process of its own (a guest takes its process over):
//! this binary re-runs itself as the child, which builds a guest or sandbox and runs a fixture.
//!
//! - `Guest`, set up in a `run` closure, locked down, exec'd: a program runs and its syscalls are
//!   the guest's (hello: files, TCP, threads, memory); the loader refuses before lockdown (a
//!   `run` closure's exec is EPERM); and the gate is filtered (escape_kill's `openat` through it
//!   kills the sandbox: SIGSYS).
//! - `Guest::pass_fd`: a host socket as guest fd 1000 (fd_echo answers on it); and a thread
//!   blocked reading it doesn't keep its process from ending (group_exit), in each mode.
//! - `Guest::run` before lockdown: what a closure routes (getpid, files, ids, the hostname) and
//!   that the host code between closures is an ordinary process's (files, a thread, a signal
//!   handler, the signal mask, a fork, an exec), several closures in a row.
//! - `Cache::images` and `setup::mount_closure` with store paths that are a file and a symlink
//!   (`store_entries`): each shown at its store path as it is.
//! - Templates (`Guest::spawn`): children of one setup, each running its own fixture and its own
//!   setup, with random bytes of their own.

use std::ffi::OsString;
use std::io::Read;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::Duration;

use unsharek::{Guest, GuestConfig, Mode};
use unsharek_fixtures as fx;
use libtest_mimic::{Arguments, Failed, Trial};

mod common;

const CHILD: &str = "UNSHAREK_GUEST_TEST_CHILD";
/// The child's mode (`coroutine`, the default, or `threaded`) and the fixture's arguments
/// (space-separated).
const CHILD_MODE: &str = "UNSHAREK_GUEST_TEST_MODE";
const CHILD_ARGS: &str = "UNSHAREK_GUEST_TEST_ARGS";

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
    vec![format!("UNSHAREK_TEST_MODE={}", mode().1).into(), format!("UNSHAREK_TEST_TARGET={}", std::os::unix::process::parent_id()).into()]
}

fn check(what: &str, ok: bool) {
    println!("{what}: {}", if ok { "ok" } else { "FAIL" });
}

/// A guest for mode `m`.
fn boot(m: Mode) -> Guest {
    Guest::boot(GuestConfig { mode: m, ..Default::default() }).unwrap()
}

/// Lockdown with the program's stdio granted, then `argv` exec'd: after lockdown `run`'s closure
/// is the program, so this returns only its failure.
fn exec(g: &mut Guest, argv: &[OsString], env: &[OsString]) -> unsharek::Error {
    if let Err(e) = g.configure_sandbox(unsharek::SandboxConfig::new().grant([0, 1, 2])).and_then(|c| unsharek::lockdown(c).map_err(Into::into)) {
        return e.into();
    }
    match g.run(|| unsharek::execve(argv, env)) {
        Ok(e) | Err(e) => e,
    }
}

/// The child: `layer` set up, then fixture `name` run.
fn child(layer: &str, name: &str) -> ! {
    let (m, _) = mode();
    let allow = [fx::bin_dir()];
    let e = match layer {
        "guest" => {
            let mut g = boot(Mode::Coroutine);
            g.mount_closure(&allow).unwrap();
            let (argv, env) = (argv(name), env());
            exec(&mut g, &argv, &env)
        }
        "exec_before" => {
            // The loader refuses before lockdown, in a setup closure as anywhere.
            let mut g = boot(m);
            g.mount_closure(&allow).unwrap();
            let e = g.run(|| unsharek::execve(&argv(name), &env())).unwrap();
            let refused = matches!(&e, unsharek::Error::Exec { errno, .. } if errno.raw_os_error() == Some(libc::EPERM));
            println!("EXEC_BEFORE_LOCKDOWN {}", if refused { "refused" } else { "ran" });
            std::process::exit(0)
        }
        "setup" => setup_closures(m, name),
        "entries" => entries(m),
        "template" => template(m),
        "hostdir_live" => hostdir_live(m),
        "run_fn" => run_fn(m, name),
        "landlock" => landlock(m, name),
        "run_after_failed" => {
            // A lockdown that fails (a grant of an fd that isn't open) leaves the guest half
            // prepared: a run after it is an error, never a setup closure or the program.
            let mut g = boot(m);
            let c = g.configure_sandbox(unsharek::SandboxConfig::new().grant([0, 1, 2, 900])).unwrap();
            // (Not open, it stays at 900, past the kept fds' 0..n: a gap.)
            let refused = matches!(unsharek::lockdown(c), Err(unsharek::tcb::Error::Gap { .. } | unsharek::tcb::Error::NotOpen(900)));
            let after = matches!(g.run(|| 0), Err(unsharek::Error::NotLockedDown));
            println!("RUN_AFTER_FAILED {refused} {after}");
            std::process::exit(0)
        }
        _ => {
            let mut g = boot(m);
            if layer == "passfd" {
                // The parent's socketpair end, inherited at fd 3 (`run_passfd`), as guest fd 1000.
                // SAFETY: fd 3 is this process's, from the parent, and nothing else owns it.
                g.pass_fd(unsafe { std::os::fd::OwnedFd::from_raw_fd(3) }, 1000).unwrap();
            }
            g.mount_closure(&allow).unwrap();
            // The program's argv and env before lockdown: after it, `getppid` (env's target) is
            // the guest's.
            let (argv, env) = (argv(name), env());
            exec(&mut g, &argv, &env)
        }
    };
    eprintln!("unsharek: {e}");
    std::process::exit(125)
}

/// A host directory served live (through `hostfs`, unsharek-fs's in-process passthrough): a change the host makes
/// between two setup closures is what the guest reads in the second (the store's images are
/// snapshots; this is the host's file, as of now).
fn hostdir_live(m: Mode) -> unsharek::Error {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("f"), "before").unwrap();
    let mut g = boot(m);
    let real = std::fs::canonicalize(dir.path()).unwrap();
    unsharek::hostfs::add("live", &real, false, m == Mode::Fork).unwrap();
    let at = dir.path().to_owned();
    let read = |g: &mut Guest| g.run(|| std::fs::read_to_string(at.join("f")).unwrap()).unwrap();
    let a = dir.path().to_owned();
    g.run(|| unsharek::hostfs::mount("live", &a).unwrap()).unwrap();
    check("the guest reads the host's file", read(&mut g) == "before");
    std::fs::write(dir.path().join("f"), "after, longer").unwrap();
    check("then the host's change", read(&mut g) == "after, longer");
    // A file past one readahead (128 KiB): its reply is 33 descriptors and more, which the device
    // cut at 32, a short read the guest took for EOF (a 1.4 MB file read as 124 KiB).
    let big: Vec<u8> = (0..1_500_000u32).map(|i| (i * 7 + i / 4096) as u8).collect();
    std::fs::write(dir.path().join("big"), &big).unwrap();
    let got = g.run(|| std::fs::read(at.join("big")).unwrap()).unwrap();
    check("a file past a readahead, whole", got == big);
    // Names are cached for a second (the server's entry timeout), of the guest's time: the wait is
    // the guest's (its clock runs while it does).
    std::fs::remove_file(dir.path().join("f")).unwrap();
    let gone = g.run(|| {
        std::thread::sleep(std::time::Duration::from_millis(1100));
        !at.join("f").exists()
    });
    check("and its removal, a second later", gone.unwrap());
    println!("HOSTDIR_LIVE_OK");
    std::process::exit(0)
}

/// Setup closures and the host code around them, then `name` (creds) run as uid 1000 on host
/// `box`.
fn setup_closures(m: Mode, name: &str) -> unsharek::Error {
    let host_file = std::env::var("UNSHAREK_GUEST_TEST_FILE").unwrap();
    let mut g = boot(m);
    g.mount_closure(&[fx::bin_dir()]).unwrap();
    let pid = std::process::id();
    // SAFETY: getpid.
    let getpid = || unsafe { libc::getpid() } as u32;
    check("before: getpid is the host's", getpid() == pid);
    let hf = host_file.clone();
    g.run(|| {
        check("setup 1: getpid is init's", getpid() == 1);
        check("setup 1: the host's file isn't there", !std::path::Path::new(&hf).exists());
        std::fs::write("/unsharek-guard-test", "made in setup 1").unwrap();
    })
    .unwrap();
    check("after 1: getpid is the host's", getpid() == pid);
    check("after 1: a host file reads", std::fs::read_to_string(&host_file).is_ok_and(|s| s == "host data"));
    check("after 1: the guest's file isn't the host's", !std::path::Path::new("/unsharek-guard-test").exists());
    // Between closures the process is an ordinary one: a thread (joined before lockdown, which
    // wants one thread), a signal handler, the mask, a fork, an exec.
    let hf = host_file.clone();
    let t = std::thread::spawn(move || std::fs::read_to_string(&hf).ok()).join().unwrap();
    check("after 1: a thread reads a host file", t.as_deref() == Some("host data"));
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
    // SAFETY: fork; the child only exits.
    let c = unsafe { libc::fork() };
    if c == 0 {
        // SAFETY: the child ends at once.
        unsafe { libc::_exit(7) };
    }
    let st = unsharek::wait(c as u32).ok().and_then(|s| s.code());
    check("after 1: a host fork's child ran", st == Some(7));
    // Syscall user dispatch is the thread's and exec clears it: a host program runs as ever.
    let spawned = Command::new("/bin/sh").arg("-c").arg("exit 5").status();
    check("after 1: a host program runs", spawned.is_ok_and(|s| s.code() == Some(5)));
    g.run(|| {
        check("setup 2: setup 1's file is still there", std::fs::read_to_string("/unsharek-guard-test").is_ok_and(|s| s == "made in setup 1"));
        // SAFETY: the guest's init dropping to uid/gid 1000, naming its host, setting its clock
        // (to the host's time: the vDSO's, which a setup's clock_gettime is).
        unsafe {
            check("setup 2: sethostname", libc::sethostname(c"box".as_ptr(), 3) == 0);
            let mut ts = std::mem::zeroed::<libc::timespec>();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            check("setup 2: clock_settime", libc::clock_settime(libc::CLOCK_REALTIME, &ts) == 0);
            let tv = libc::timeval { tv_sec: ts.tv_sec, tv_usec: ts.tv_nsec / 1000 };
            check("setup 2: settimeofday", libc::settimeofday(&tv, std::ptr::null()) == 0);
            check("setup 2: setresgid", libc::setresgid(1000, 1000, 1000) == 0);
            check("setup 2: setresuid", libc::setresuid(1000, 1000, 1000) == 0);
        }
    })
    .unwrap();
    g.run(|| {
        // uid 1000 uses /dev's nodes (they were 0644, root's: capnix's build user couldn't write
        // /dev/null).
        check("setup 3: uid 1000 writes /dev/null", std::fs::write("/dev/null", "x").is_ok());
        for dev in ["/dev/zero", "/dev/urandom"] {
            let mut b = [0u8; 16];
            let read = std::fs::File::open(dev).and_then(|mut f| f.read_exact(&mut b));
            check(&format!("setup 3: uid 1000 reads {dev}"), read.is_ok());
        }
        // A setup's clock_settime is the guest kernel's, which asks for CAP_SYS_TIME: uid 1000
        // has none. (The program's gets sysmap's EPERM whoever it is: sysaudit.)
        // SAFETY: a timespec of the host's time.
        unsafe {
            let mut ts = std::mem::zeroed::<libc::timespec>();
            libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
            check("setup 3: uid 1000 can't set the clock", libc::clock_settime(libc::CLOCK_REALTIME, &ts) != 0);
        }
    })
    .unwrap();
    check("after 2: getpid is the host's", getpid() == pid);
    let (argv, env) = (argv(name), env());
    exec(&mut g, &argv, &env)
}

/// Store-like paths (`ENTRIES`, in a temporary directory: the suite can't count on a store path
/// that is a file being on the host) given as store paths, as capnix gives a build's inputs from
/// its real store directory: their images from the cache, each shown at `/nix/store/<name>`; then
/// `paths` run on them.
const ENTRIES: [&str; 3] =
    ["0000000000000000000000000000000f-entry-file", "0000000000000000000000000000000l-entry-link", "0000000000000000000000000000000d-entry-dir"];

fn entries(m: Mode) -> unsharek::Error {
    let dir = PathBuf::from(std::env::var("UNSHAREK_GUEST_TEST_FILE").unwrap());
    let closure = unsharek::store::Closure { store: ENTRIES.iter().map(|n| dir.join(n)).collect(), host: Default::default() };
    let mut store = unsharek::store::Cache::open_default().unwrap().images(&closure).unwrap();
    for m in &mut store.mounts {
        m.guest = std::path::Path::new("/nix/store").join(m.guest.file_name().unwrap());
    }
    let mut g = boot(m);
    let mounts = g.map_store(&store).unwrap();
    g.mount_closure(&[fx::bin_dir()]).unwrap();
    g.run(|| unsharek::setup::mount_closure(&mounts)).unwrap().unwrap();
    let mut argv = argv("paths");
    argv.extend(ENTRIES.iter().map(|n| format!("/nix/store/{n}").into()));
    let env = env();
    exec(&mut g, &argv, &env)
}

/// A template: one setup, then four children in turn, each with setup of its own and its own
/// fixture. Prints each one's status; their output is theirs (stdout, in turn).
/// `Guest::run` after lockdown: a closure run as the program. `ok`: its calls are the
/// guest's (init's pid, the guest's files, no host path), a host fd from before lockdown is
/// closed, and its return value is the status (42). `kill`: a host call from the gate the filter
/// refuses kills the sandbox (`run_fn_gate_kills`).
fn run_fn(m: Mode, what: &str) -> unsharek::Error {
    let mut g = boot(m);
    // A host fd opened now, before lockdown: the closure finds it closed.
    // At 900, past the kept fds' 0..n: a number below n may be a kept fd's after their move.
    let before = std::fs::File::open(env!("CARGO_MANIFEST_DIR")).unwrap();
    // SAFETY: dup2 of this process's fd onto a free number.
    let before_fd = unsafe { libc::dup2(before.as_raw_fd(), 900) };
    drop(before);
    let host_path = env!("CARGO_MANIFEST_DIR");
    let what = what.to_owned();
    if let Err(e) = g.configure_sandbox(unsharek::SandboxConfig::new().grant([0, 1, 2])).and_then(|c| unsharek::lockdown(c).map_err(Into::into)) {
        return e.into();
    }
    let r = g.run(move || {
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
        if what == "kill" {
            gate_call(gate, libc::SYS_getppid, 0, 0);
            println!("run_fn: survived the gate");
        }
        42
    });
    match r {
        Ok(_) => unreachable!("the program's run returns only on failure"),
        Err(e) => e,
    }
}

/// The gate's `syscall` instruction, found in the binary's code: `mov r9, [rsp + 8]; syscall;
/// ret` (unsharek-rt's `trap::gate`), as a compromised program would find it.
/// The fs plugin's `openat` from the gate after lockdown (what a compromised runtime could make),
/// its root a temporary directory: a file inside opens; one outside is Landlock's EACCES, or,
/// with `no_landlock` (`what`), opens too (the opt-out confines nothing).
fn landlock(m: Mode, what: &str) -> unsharek::Error {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("inside"), "x").unwrap();
    let root = std::fs::canonicalize(dir.path()).unwrap();
    let inside = std::ffi::CString::new(root.join("inside").into_os_string().into_encoded_bytes()).unwrap();
    let outside = std::ffi::CString::new(concat!(env!("CARGO_MANIFEST_DIR"), "/Cargo.toml")).unwrap();
    let files = unsharek::plugin::Files::new().root(&root, unsharek::plugin::Fs::ReadOnly).no_landlock(what == "no_landlock");
    let mut g = boot(m);
    if let Err(e) = g.configure_sandbox(unsharek::SandboxConfig::new().grant([0, 1, 2])).and_then(|c| unsharek::lockdown_with(c, &[&files]).map_err(Into::into)) {
        return e.into();
    }
    let r = g.run(move || {
        let gate = find_gate();
        let open = |p: &std::ffi::CStr| {
            gate_call4(gate, libc::SYS_openat, [i32::MAX as usize, p.as_ptr() as usize, (libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC) as usize, 0])
        };
        check("landlock: a file under the root opens", open(&inside) >= 0);
        let o = open(&outside);
        if what == "no_landlock" {
            check("landlock: opted out, a file outside opens too", o >= 0);
        } else {
            check("landlock: a file outside is EACCES", o == -(libc::EACCES as isize));
        }
        0
    });
    match r {
        Ok(_) => unreachable!("the program's run returns only on failure"),
        Err(e) => e,
    }
}

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

fn template(m: Mode) -> unsharek::Error {
    let mut g = boot(m);
    g.mount_closure(&[fx::bin_dir()]).unwrap();
    g.run(|| {
        std::fs::create_dir_all("/etc").unwrap();
        std::fs::write("/etc/template", "shared").unwrap();
    })
    .unwrap();
    // The last dies of SIGABRT: a child's death by a signal is its own (its pid, not the
    // template's, is the one the runtime and the filter's `kill` name).
    let runs: [(&str, &[&str]); 5] =
        [("creds", &[]), ("creds", &[]), ("hello", &[]), ("exit_status", &["exit42"]), ("exit_status", &["abort"])];
    for (n, (fixture, args)) in runs.iter().enumerate() {
        let child = g
            .spawn(move |mut g| {
                g.run(|| -> std::io::Result<()> {
                    let host = format!("child-{n}");
                    // SAFETY: a NUL-free name, its length.
                    unsafe { libc::sethostname(host.as_ptr().cast(), host.len()) };
                    assert_eq!(std::fs::read_to_string("/etc/template")?, "shared");
                    Ok(())
                })??;
                let mut argv: Vec<OsString> = vec![fx::bin(fixture).into()];
                argv.extend(args.iter().map(OsString::from));
                let env = env();
                Ok(exec(&mut g, &argv, &env)).and_then(Err)
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
        .env("UNSHAREK_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
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
        .env("UNSHAREK_IMAGE_CACHE", PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("image-cache"))
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
        Trial::test("exec_refused_before_lockdown", || {
            // The loader is the program's start, and starts nothing unfiltered: a setup closure's
            // exec is EPERM.
            let (st, out, err) = run("exec_before", "hello", "coroutine", &[])?;
            if st.code() != Some(0) || out.trim() != "EXEC_BEFORE_LOCKDOWN refused" {
                return fail(st, &out, &err, "wanted the exec refused");
            }
            Ok(())
        }),
        Trial::test("run_after_failed_lockdown", || {
            let (st, out, err) = run("run_after_failed", "hello", "coroutine", &[])?;
            if st.code() != Some(0) || out.trim() != "RUN_AFTER_FAILED true true" {
                return fail(st, &out, &err, "wanted the lockdown refused, then the run");
            }
            Ok(())
        }),
        Trial::test("sandbox_gate_is_filtered", || {
            // The filter: openat("/") through the gate kills the sandbox.
            use std::os::unix::process::ExitStatusExt;
            let (st, out, err) = run("sandbox", "escape_kill", "coroutine", &[])?;
            if st.signal() != Some(libc::SIGSYS) || out.contains("SURVIVED") {
                return fail(st, &out, &err, "wanted SIGSYS from the gate's openat");
            }
            Ok(())
        }),
    ];
    for mode in ["coroutine", "threaded", "fork"] {
        trials.push(Trial::test(format!("hostdir_live::{mode}"), move || {
            let (st, out, err) = run("hostdir_live", "hello", mode, &[])?;
            if st.code() != Some(0) || !out.contains("HOSTDIR_LIVE_OK") || out.contains("FAIL") {
                return fail(st, &out, &err, "wanted the host's changes seen");
            }
            Ok(())
        }));
        for how in ["landlock", "no_landlock"] {
            trials.push(Trial::test(format!("fs_plugin_{how}::{mode}"), move || {
                let (st, out, err) = run("landlock", how, mode, &[])?;
                if st.code() != Some(0) || out.contains("FAIL") || out.matches(": ok").count() != 2 {
                    return fail(st, &out, &err, "wanted the root's file open and the outside one as Landlock says");
                }
                Ok(())
            }));
        }
        trials.push(Trial::test(format!("run_fn::{mode}"), move || {
            let (st, out, err) = run("run_fn", "ok", mode, &[])?;
            if st.code() != Some(42) || out.contains("FAIL") || out.matches(": ok").count() != 6 {
                return fail(st, &out, &err, "wanted the closure's checks and status 42");
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
        // (SIGTERM: 128 + 15, an exit: unsharek-tcb's filter has no `kill`.)
        for (how, want) in [("exit", (Some(3), None)), ("signal", (Some(128 + 15), None))] {
            trials.push(Trial::test(format!("pass_fd_reader_{how}::{mode}"), move || {
                use std::os::unix::process::ExitStatusExt;
                let (st, out, err, _) = run_passfd(mode, "group_exit", &format!("fd1000,futex {how}"), None)?;
                if (st.code(), st.signal()) != want || !out.contains("GROUP_EXIT_READY") || out.contains("reader of fd") {
                    return Err(format!("{st:?}, wanted {want:?}\n{out}\n{err}").into());
                }
                Ok(())
            }));
        }
        trials.push(Trial::test(format!("setup_closures::{mode}"), move || {
            let dir = tempfile::tempdir()?;
            let file = dir.path().join("host-file");
            std::fs::write(&file, "host data")?;
            let (st, out, err) = run("setup", "creds", mode, &[("UNSHAREK_GUEST_TEST_FILE", file.to_str().unwrap())])?;
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
            let (st, out, err) = run("entries", "paths", mode, &[("UNSHAREK_GUEST_TEST_FILE", dir.path().to_str().unwrap())])?;
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
        trials.push(Trial::test(format!("template::{mode}"), move || {
            let (st, out, err) = run("template", "-", mode, &[])?;
            let statuses: Vec<&str> = out.lines().filter(|l| l.starts_with("CHILD ")).collect();
            let want = [
                "CHILD 0 creds status Some(0) signal None",
                "CHILD 1 creds status Some(0) signal None",
                "CHILD 2 hello status Some(0) signal None",
                "CHILD 3 exit_status status Some(42) signal None",
                "CHILD 4 exit_status status Some(134) signal None",
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
