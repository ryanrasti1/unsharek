//! The regression suite: one table of cases (`cases()`), each run natively (which checks the test
//! itself) and under `exobox run` in every mode it names. A run is a trial named
//! `<case>::<native|coroutine|threaded|fork>`, with a timeout and an optional CPU budget, so
//! `cargo nextest run -E 'test(/::fork$/)'` runs one mode and a hang fails in seconds.

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;
use std::env;

use exobox_fixtures as fx;

mod common;
use common::spawn_bounded;
use libtest_mimic::{Arguments, Failed, Trial};

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Native,
    Coroutine,
    Threaded,
    Fork,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Native => "native",
            Mode::Coroutine => "coroutine",
            Mode::Threaded => "threaded",
            Mode::Fork => "fork",
        }
    }
}

const ALL: &[Mode] = &[Mode::Coroutine, Mode::Threaded, Mode::Fork];
const FORK: &[Mode] = &[Mode::Fork];
const SIGSYS: i32 = 31;

enum Prog {
    Fixture(&'static str),
    /// A program from nixpkgs, by the devshell variable naming it.
    External(&'static str),
}

enum Arg {
    Lit(&'static str),
    /// The path of a host file with a secret in it, outside every allowed path.
    Secret,
    /// A path that doesn't exist yet, in a directory of this run's own: whether the run created
    /// it on the host is checked afterwards (`Expect::creates`).
    Marker,
    Fixture(&'static str),
    Denied(&'static str),
}

#[derive(Clone, Copy)]
enum Status {
    Code(i32),
    Signal(i32),
    /// Killed by the signal, or exit 128 + it (where the sandbox emulates the default action).
    Fatal(i32),
    Any,
}

#[derive(Clone)]
struct Expect {
    status: Status,
    stdout: Vec<&'static str>,
    stderr: Vec<&'static str>,
    not_stdout: Vec<&'static str>,
    /// Whether the run made `Arg::Marker`'s file on the host (None: not checked).
    creates: Option<bool>,
}

fn ok(marker: &'static str) -> Expect {
    Expect { status: Status::Code(0), stdout: vec![marker], ..status(Status::Code(0)) }
}

fn status(status: Status) -> Expect {
    Expect { status, stdout: vec![], stderr: vec![], not_stdout: vec![], creates: None }
}

struct Case {
    name: &'static str,
    prog: Prog,
    args: Vec<Arg>,
    modes: &'static [Mode],
    /// None: not run natively (it needs the sandbox, or would be unsafe on the host).
    native: Option<Expect>,
    sandbox: Expect,
    flags: Vec<&'static str>,
    env: Vec<(&'static str, &'static str)>,
    stdin: Option<&'static str>,
    timeout: Duration,
    cpu_budget: Option<Duration>,
    /// Checks stdout beyond `Expect` (sysaudit's table).
    check: Option<fn(&str) -> Result<(), String>>,
}

fn case(name: &'static str, prog: Prog, modes: &'static [Mode], sandbox: Expect) -> Case {
    Case {
        name,
        prog,
        args: vec![],
        modes,
        native: Some(sandbox.clone()),
        sandbox,
        flags: vec![],
        env: vec![],
        stdin: None,
        timeout: Duration::from_secs(5),
        cpu_budget: None,
        check: None,
    }
}

/// A fixture that prints `<NAME>_OK` in every mode and natively.
fn fixture(name: &'static str, modes: &'static [Mode]) -> Case {
    let marker = Box::leak(format!("{}_OK", name.to_uppercase()).into_boxed_str());
    case(name, Prog::Fixture(name), modes, ok(marker))
}

impl Case {
    fn args(mut self, args: Vec<Arg>) -> Self {
        self.args = args;
        self
    }
    fn native(mut self, native: Option<Expect>) -> Self {
        self.native = native;
        self
    }
    fn flags(mut self, flags: &[&'static str]) -> Self {
        self.flags = flags.to_vec();
        self
    }
    fn env(mut self, env: &[(&'static str, &'static str)]) -> Self {
        self.env = env.to_vec();
        self
    }
    fn renamed(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }
}

fn cases() -> Vec<Case> {
    let mut c = vec![
        // Basics, in every mode.
        fixture("hello", ALL),
        fixture("shmap", ALL),
        case("sleepy", Prog::Fixture("sleepy"), ALL, ok("SLEEP_OK")),
        fixture("threadpoll", ALL),
        fixture("thread_fds", ALL),
        fixture("futex_wake", ALL),
        fixture("small_stack", ALL),
        fixture("stdio_meminfo", ALL),
        fixture("sigsys", ALL),
        Case { cpu_budget: Some(Duration::from_millis(100)), ..fixture("idle", ALL) },
        // JITs work with no flag: W^X would be hardening of the program, not the sandbox's.
        fixture("rwx", ALL),
        // How a run ends.
        case("exit_code", Prog::Fixture("exit_status"), ALL, status(Status::Code(42)))
            .args(vec![Arg::Lit("exit42")]),
        case("abort", Prog::Fixture("exit_status"), ALL, status(Status::Fatal(6))).args(vec![Arg::Lit("abort")]),
        case("sigterm", Prog::Fixture("exit_status"), ALL, status(Status::Fatal(15))).args(vec![Arg::Lit("term")]),
        Case {
            stdin: Some("through stdin\n"),
            ..case("stdin", Prog::Fixture("exit_status"), ALL, ok("through stdin")).args(vec![Arg::Lit("cat")])
        },
        case("stderr", Prog::Fixture("exit_status"), ALL, Expect { stderr: vec!["to stderr"], ..status(Status::Code(3)) })
            .args(vec![Arg::Lit("stderr")]),
        // The filter.
        fixture("escape", ALL).args(vec![Arg::Secret]).flags(&["--deny=errno"]).native(None),
        fixture("escape_gate", ALL).flags(&["--deny=errno"]).native(None),
        fixture("escape_gate", ALL)
            .renamed("escape_gate_allow")
            .flags(&["--deny=errno", "--allow=getppid"])
            .env(&[("EXOBOX_TEST_ALLOW_NR", "110")])
            .native(None),
        case(
            "escape_kill",
            Prog::Fixture("escape_kill"),
            ALL,
            Expect { not_stdout: vec!["ESCAPE_KILL_SURVIVED"], ..status(Status::Signal(SIGSYS)) },
        )
        .native(None),
        // The loader: nothing the program brings runs before lockdown, and nothing outside the
        // allowed paths maps. Natively each one leaks, which shows the test can see a leak.
        // A hostile PT_INTERP reading a host file, creating one, and calling through the gate
        // (which only fails if the filter is in place before the loader's first instruction).
        case(
            "hostile_interp_read",
            Prog::Fixture("interp_victim"),
            ALL,
            Expect { not_stdout: vec!["LEAKED"], ..status(Status::Any) },
        )
        .args(vec![Arg::Secret, Arg::Lit("read")])
        .native(Some(Expect { stdout: vec!["LEAKED:"], ..status(Status::Code(0)) })),
        case(
            "hostile_interp_write",
            Prog::Fixture("interp_victim"),
            ALL,
            Expect { creates: Some(false), ..status(Status::Any) },
        )
        .args(vec![Arg::Marker, Arg::Lit("write")])
        .native(Some(Expect { stdout: vec!["CREATED"], creates: Some(true), ..status(Status::Code(0)) })),
        case(
            "hostile_interp_gate",
            Prog::Fixture("interp_victim"),
            ALL,
            Expect { not_stdout: vec!["GATE_SURVIVED"], ..status(Status::Signal(SIGSYS)) },
        )
        .args(vec![Arg::Secret, Arg::Lit("gate")])
        .native(Some(ok("NO_GATE"))),
        case(
            "hostile_ctor",
            Prog::Fixture("ctor_victim"),
            ALL,
            Expect { stdout: vec!["CTOR_VICTIM_RAN"], not_stdout: vec!["LEAKED"], ..status(Status::Code(0)) },
        )
        .native(Some(Expect { stdout: vec!["LEAKED:"], ..status(Status::Code(0)) })),
        case("dlopen", Prog::Fixture("dlopen_test"), ALL, ok("DLOPEN_OK"))
            .args(vec![Arg::Fixture("libplug.so"), Arg::Denied("libplug.so")])
            .native(Some(ok("DENIED_LOADED"))),
        // Fork mode.
        fixture("fork", FORK),
        fixture("signals", FORK),
        fixture("forkthreads", FORK),
        fixture("fork_rng", FORK),
        fixture("forkbomb", FORK).flags(&["--max-procs=16"]).env(&[("EXOBOX_TEST_MAX_PROCS", "16")]).native(None),
        Case {
            timeout: Duration::from_secs(15),
            check: Some(sysaudit_check),
            ..case("sysaudit", Prog::Fixture("sysaudit"), FORK, ok("SYSAUDIT_DONE")).native(None)
        },
        // Programs from nixpkgs.
        case("python", Prog::External("EXOBOX_TEST_PYTHON"), ALL, ok("{\"a\": 42}"))
            .args(vec![Arg::Lit("-c"), Arg::Lit("import json; print(json.dumps({'a': 6 * 7}))")]),
        case(
            "bash",
            Prog::External("EXOBOX_TEST_BASH"),
            FORK,
            Expect { stdout: vec!["42", "sub=ok", "st=3", "bg=done"], ..status(Status::Code(0)) },
        )
        .args(vec![
            Arg::Lit("-c"),
            Arg::Lit("echo $((6 * 7)) | { read x; echo $x; }; s=$(echo ok); echo sub=$s; (exit 3); echo st=$?; { sleep 0.05; echo bg=done; } & wait"),
        ]),
    ];
    c.sort_by_key(|c| c.name);
    c
}

/// sysaudit's outcome for every number, against docs/syscalls.md's classes (as capnix's tier A
/// measured them): these two lists, and everything else not skipped served (neither ENOSYS nor
/// EPERM, and no crash or hang).
fn sysaudit_check(out: &str) -> Result<(), String> {
    const EPERM: &[&str] = &[
        "chroot", "mount", "umount2", "pivot_root", "swapon", "swapoff", "sethostname", "setdomainname", "acct",
        "settimeofday", "adjtimex", "clock_settime", "clock_adjtime", "syslog", "vhangup", "quotactl",
        "quotactl_fd", "kexec_load", "kexec_file_load", "init_module", "finit_module", "delete_module", "iopl",
        "ioperm", "unshare", "setns",
    ];
    const ENOSYS: &[&str] = &[
        "shmget", "shmat", "shmctl", "shmdt", "semget", "semop", "semctl", "semtimedop", "msgget", "msgsnd",
        "msgrcv", "msgctl", "mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify",
        "mq_getsetattr", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "io_pgetevents",
        "io_uring_setup", "io_uring_enter", "io_uring_register", "inotify_init", "inotify_init1",
        "inotify_add_watch", "inotify_rm_watch", "fanotify_init", "fanotify_mark", "signalfd", "signalfd4",
        "timerfd_create", "timerfd_settime", "timerfd_gettime", "memfd_create", "name_to_handle_at",
        "open_by_handle_at", "ioprio_set", "ioprio_get", "add_key", "request_key", "keyctl", "bpf",
        "perf_event_open", "userfaultfd", "landlock_create_ruleset", "landlock_add_rule",
        "landlock_restrict_self", "membarrier", "rseq", "get_robust_list", "futex_waitv", "memfd_secret",
        "pkey_mprotect", "pkey_alloc", "pkey_free", "process_vm_readv", "process_vm_writev", "process_madvise",
        "process_mrelease", "pidfd_getfd", "kcmp", "remap_file_pages", "mbind", "set_mempolicy",
        "get_mempolicy", "migrate_pages", "move_pages", "set_mempolicy_home_node", "open_tree", "move_mount",
        "fsopen", "fsconfig", "fsmount", "fspick", "mount_setattr", "getdents", "uselib", "ustat", "sysfs",
        "_sysctl", "create_module", "get_kernel_syms", "query_module", "nfsservctl", "getpmsg", "putpmsg",
        "afs_syscall", "tuxcall", "security", "vserver", "lookup_dcookie", "epoll_ctl_old", "epoll_wait_old",
        "modify_ldt", "set_thread_area", "get_thread_area",
    ];
    // Newer than the syscalls crate's table, by number: cachestat, map_shadow_stack, futex_wake,
    // futex_wait, futex_requeue, statmount, listmount, the lsm_* calls, mseal, the *xattrat calls,
    // open_tree_attr, file_getattr, file_setattr.
    const ENOSYS_NR: &[i64] = &[451, 453, 454, 455, 456, 457, 458, 459, 460, 461, 462, 463, 464, 465, 466, 467, 468, 469];
    let class = |nr: i64| -> &'static str {
        let name = syscalls::Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("");
        if EPERM.contains(&name) {
            "EPERM"
        } else if ENOSYS.contains(&name) || ENOSYS_NR.contains(&nr) {
            "ENOSYS"
        } else {
            "served"
        }
    };
    let mut wrong = vec![];
    for line in out.lines() {
        let Some((nr, result)) = line.split_once(' ') else { continue };
        let Ok(nr) = i64::from_str(nr) else { continue };
        if result == "skip" {
            continue;
        }
        let got = match i64::from_str(result) {
            Ok(-38) => "ENOSYS",
            Ok(-1) => "EPERM",
            Ok(_) => "served",
            Err(_) => result, // signalN, hang, none
        };
        let want = class(nr);
        if got != want {
            wrong.push(format!("{nr} ({}): {result}, wanted {want}", syscalls::Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("?")));
        }
    }
    if wrong.is_empty() { Ok(()) } else { Err(format!("{} numbers off:\n  {}", wrong.len(), wrong.join("\n  "))) }
}

fn main() {
    let args = Arguments::from_args();
    let secret = tempfile::NamedTempFile::new().unwrap();
    secret.as_file().write_all(format!("s3cr3t-{}", std::process::id()).as_bytes()).unwrap();
    let secret = secret.into_temp_path().keep().unwrap();

    let mut trials = vec![];
    for c in cases() {
        let c = std::sync::Arc::new(c);
        let modes = c.native.iter().map(|_| Mode::Native).chain(c.modes.iter().copied());
        for mode in modes {
            let (c, secret) = (c.clone(), secret.clone());
            trials.push(Trial::test(format!("{}::{}", c.name, mode.name()), move || run(&c, mode, &secret)));
        }
    }
    let conclusion = libtest_mimic::run(&args, trials);
    let _ = std::fs::remove_file(&secret);
    conclusion.exit();
}

fn run(c: &Case, mode: Mode, secret: &PathBuf) -> Result<(), Failed> {
    let prog = match c.prog {
        Prog::Fixture(name) => fx::bin(name),
        Prog::External(var) => match env::var_os(var) {
            Some(p) => PathBuf::from(p),
            None => return Err(format!("{var} unset: run in the devshell (./test)").into()),
        },
    };
    let marker_dir = tempfile::tempdir()?;
    let marker = marker_dir.path().join("created-by-the-program");
    let args = c.args.iter().map(|a| match a {
        Arg::Lit(s) => PathBuf::from(s),
        Arg::Secret => secret.clone(),
        Arg::Marker => marker.clone(),
        Arg::Fixture(name) => fx::bin(name),
        Arg::Denied(name) => fx::denied_dir().join(name),
    });
    let mut cmd = if mode == Mode::Native {
        Command::new(&prog)
    } else {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_exobox"));
        cmd.args(["run", "--mode", mode.name(), "--allow-path"]).arg(fx::bin_dir());
        cmd.args(&c.flags).arg("--").arg(&prog);
        cmd
    };
    cmd.args(args)
        .env("EXOBOX_TEST_MODE", mode.name())
        .env("EXOBOX_TEST_SECRET", secret)
        .env("EXOBOX_TEST_TARGET", std::process::id().to_string())
        .envs(c.env.iter().copied())
        .stdin(if c.stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let (status, cpu, stdout, stderr) = spawn_bounded(cmd, c.stdin, c.timeout)?;
    let expect = if mode == Mode::Native { c.native.as_ref().unwrap() } else { &c.sandbox };
    let fail = |why: String| -> Result<(), Failed> {
        Err(format!("{why}\n--- status: {status:?}, cpu {cpu:?}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}").into())
    };
    let status_ok = match expect.status {
        Status::Code(n) => status.code() == Some(n),
        Status::Signal(s) => status.signal() == Some(s),
        Status::Fatal(s) => status.signal() == Some(s) || status.code() == Some(128 + s),
        Status::Any => true,
    };
    if !status_ok {
        return fail(format!("wanted status {:?}", DebugStatus(expect.status)));
    }
    for want in &expect.stdout {
        if !stdout.contains(want) {
            return fail(format!("stdout lacks {want:?}"));
        }
    }
    for want in &expect.stderr {
        if !stderr.contains(want) {
            return fail(format!("stderr lacks {want:?}"));
        }
    }
    for unwanted in &expect.not_stdout {
        if stdout.contains(unwanted) {
            return fail(format!("stdout has {unwanted:?}"));
        }
    }
    if let Some(want) = expect.creates {
        if marker.exists() != want {
            return fail(format!("{} {} on the host", marker.display(), if want { "wasn't created" } else { "was created" }));
        }
    }
    if let (Some(budget), Mode::Coroutine | Mode::Threaded | Mode::Fork) = (c.cpu_budget, mode) {
        if cpu > budget {
            return fail(format!("used {cpu:?} of CPU, over the budget of {budget:?}"));
        }
    }
    if let (Some(check), false) = (c.check, mode == Mode::Native) {
        if let Err(why) = check(&stdout) {
            return fail(why);
        }
    }
    Ok(())
}

struct DebugStatus(Status);

impl std::fmt::Debug for DebugStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0 {
            Status::Code(n) => write!(f, "exit {n}"),
            Status::Signal(s) => write!(f, "signal {s}"),
            Status::Fatal(s) => write!(f, "signal {s} or exit {}", 128 + s),
            Status::Any => write!(f, "any"),
        }
    }
}
