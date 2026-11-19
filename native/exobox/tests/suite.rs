//! The host-side regression suite: one table of cases (`cases()`), each a program run natively
//! (which checks the test itself) and under `exobox run` in every mode it names, and checked from
//! the host: its exit status or signal, its stdio (input given, output read late), its CPU time,
//! files on the host, the CLI's flags, programs from nixpkgs. A run is a trial named
//! `<case>::<native|coroutine|threaded|fork>`, with a timeout and an optional CPU budget, so
//! `cargo nextest run -E 'test(/::fork$/)'` runs one mode and a hang fails in seconds. What a
//! program observes inside the guest is native/guest-tests' (Rust #[test]s, a sandbox each).

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;
use std::env;

use exobox_fixtures as fx;

mod common;
use common::spawn_bounded_with;
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
const THREADED_FORK: &[Mode] = &[Mode::Threaded, Mode::Fork];
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
    /// The path a devshell variable names (a program from nixpkgs, as data).
    Env(&'static str),
}

#[derive(Clone, Copy)]
enum Status {
    Code(i32),
    Signal(i32),
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
    /// Programs from nixpkgs the case runs besides its own (devshell variables naming them): their
    /// store paths are allowed (`--allow-path`), closures and all.
    uses: Vec<&'static str>,
    stdin: Option<&'static str>,
    /// Stdin a pipe held open and silent for the whole run (a reader blocks on it).
    hold_stdin: bool,
    /// How long the suite holds off reading the program's stdout (a slow reader: the pipe fills).
    stdout_delay: Duration,
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
        uses: vec![],
        stdin: None,
        hold_stdin: false,
        stdout_delay: Duration::ZERO,
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
    fn uses(mut self, vars: &[&'static str]) -> Self {
        self.uses = vars.to_vec();
        self
    }
    fn renamed(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }
}

fn group_exit(name: &'static str, waiters: &'static str, how: &'static str, st: Status) -> Case {
    let expect = Expect { stdout: vec!["GROUP_EXIT_READY"], not_stdout: vec!["GROUP_EXIT_SURVIVED"], ..status(st) };
    Case { hold_stdin: true, ..case(name, Prog::Fixture("group_exit"), ALL, expect).args(vec![Arg::Lit(waiters), Arg::Lit(how)]) }
}

fn cases() -> Vec<Case> {
    let mut c = vec![
        // An idle sandbox's host CPU (the guest's own accounting doesn't see the host's spin).
        Case { cpu_budget: Some(Duration::from_millis(100)), ..fixture("idle", ALL) },
        // How a run ends.
        case("exit_code", Prog::Fixture("exit_status"), ALL, status(Status::Code(42)))
            .args(vec![Arg::Lit("exit42")]),
        // A death by a signal is the sandbox's too (the guest's default action, then `kill` of
        // itself), as natively.
        case("abort", Prog::Fixture("exit_status"), ALL, status(Status::Signal(6))).args(vec![Arg::Lit("abort")]),
        case("sigterm", Prog::Fixture("exit_status"), ALL, status(Status::Signal(15))).args(vec![Arg::Lit("term")]),
        Case {
            stdin: Some("through stdin\n"),
            ..case("stdin", Prog::Fixture("exit_status"), ALL, ok("through stdin")).args(vec![Arg::Lit("cat")])
        },
        case("stderr", Prog::Fixture("exit_status"), ALL, Expect { stderr: vec!["to stderr"], ..status(Status::Code(3)) })
            .args(vec![Arg::Lit("stderr")]),
        // The filter.
        fixture("escape", ALL).args(vec![Arg::Secret]).flags(&["--deny=errno"]).native(None),
        fixture("escape_gate", ALL).flags(&["--deny=errno"]).native(None),
        // A restriction (Builder::restrict) on top of the mode's list: tests/guest.rs.
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
        // Init's end is the sandbox's: a child waiting in pause() doesn't outlive it on the host.
        fixture("fork_ends", FORK).args(vec![Arg::Lit("init_exit")]).native(None),
        // A child's death on the host (the filter's kill) is the sandbox's, by the same signal.
        case(
            "fork_ends_child_killed",
            Prog::Fixture("fork_ends"),
            FORK,
            Expect { not_stdout: vec!["FORK_ENDS_SURVIVED"], ..status(Status::Signal(SIGSYS)) },
        )
        .args(vec![Arg::Lit("child_killed")])
        .native(None),
        // Exec's kernel half: close-on-exec fds, handlers reset, the other threads ended. In-guest
        // checks, guest-tests' exec::exec_reset's; here only in the modes where that one is
        // ignored (an exec from libtest's thread panics the runtime there), until it runs there.
        fixture("exec_reset", THREADED_FORK),
        fixture("exec_reset", THREADED_FORK).renamed("exec_reset_threads").args(vec![Arg::Lit("threads")]),
        // A process ends though its other threads wait where the runtime has them, not the kernel:
        // an emulated futex, a host fd (stdin; a passed fd is tests/guest.rs's). By exit, by a
        // signal's default action, and by an itimer's while every thread waits so.
        group_exit("group_exit_futex", "futex", "exit", Status::Code(3)),
        group_exit("group_exit_stdin", "stdin", "exit", Status::Code(3)),
        group_exit("group_exit_signal", "futex,stdin", "signal", Status::Signal(15)),
        group_exit("group_exit_alarm", "futex,stdin", "alarm", Status::Signal(14)),
        // A thread blocked reading a host fd must not keep its process from exiting (capnix).
        Case { hold_stdin: true, ..fixture("hostfd_thread", ALL).args(vec![Arg::Lit("exit")]) },
        Case { hold_stdin: true, ..fixture("hostfd_thread", ALL).renamed("hostfd_thread_sleep").args(vec![Arg::Lit("sleep")]) },
        Case { hold_stdin: true, ..fixture("hostfd_thread", ALL).renamed("hostfd_thread_write").args(vec![Arg::Lit("write")]) },
        // Threads writing to a full stdout pipe (the suite reads it only after 300 ms): a
        // nonblocking write's EAGAIN and poll, and a blocking write that waits without the CPU;
        // in fork mode in a forked process too (init's process watches its fds).
        Case { stdout_delay: Duration::from_millis(300), ..fixture("stdout_full", ALL).args(vec![Arg::Lit("nonblock")]) },
        Case {
            stdout_delay: Duration::from_millis(300),
            ..fixture("stdout_full", ALL).renamed("stdout_full_block").args(vec![Arg::Lit("block")])
        },
        // ... which a signal cuts short, and the process's exit ends (in 0.7 s, the reader not yet
        // reading: the exit doesn't wait for it).
        Case {
            stdout_delay: Duration::from_millis(300),
            ..fixture("stdout_full", ALL).renamed("stdout_full_signal").args(vec![Arg::Lit("signal")])
        },
        Case {
            stdout_delay: Duration::from_millis(1000),
            timeout: Duration::from_millis(700),
            ..case(
                "stdout_full_exit",
                Prog::Fixture("stdout_full"),
                ALL,
                Expect { stderr: vec!["STDOUT_FULL_EXIT"], ..status(Status::Code(0)) },
            )
            .args(vec![Arg::Lit("exit")])
        },
        Case {
            stdout_delay: Duration::from_millis(300),
            ..fixture("stdout_full", FORK).renamed("stdout_full_child").args(vec![Arg::Lit("child"), Arg::Lit("nonblock")])
        },
        // The program that found it: xz's threads writing a nonblocking stdout into a pipe that
        // fills (xz polls for POLLOUT at each EAGAIN). It hung ~4 runs in 6 in threaded and fork
        // mode before the idle wait watched every waited-on host fd. Compresses bash's binary
        // (~1.4 MB in, ~0.5 MB out: several pipefuls); the output starts with xz's magic.
        Case {
            stdout_delay: Duration::from_millis(300),
            ..case("xz_pipe", Prog::External("EXOBOX_TEST_XZ"), ALL, Expect { stdout: vec!["7zXZ"], ..status(Status::Code(0)) })
                .args(vec![Arg::Lit("-T2"), Arg::Lit("-3"), Arg::Lit("--block-size=128KiB"), Arg::Lit("-c"), Arg::Env("EXOBOX_TEST_BASH")])
                .uses(&["EXOBOX_TEST_BASH"])
        },
        Case {
            stdout_delay: Duration::from_millis(300),
            ..fixture("stdout_full", FORK)
                .renamed("stdout_full_child_block")
                .args(vec![Arg::Lit("child"), Arg::Lit("block")])
        },
        // The pipeline that found guest-tests' process::settid's bug: a C++ program on a pipeline's left side, in a
        // bash exec'd in the guest (it failed ~5 runs in 6 in capnix tier A).
        case(
            "pipeline_cpp",
            Prog::External("EXOBOX_TEST_BASH"),
            FORK,
            Expect { stdout: vec!["PIPELINE_OK"], ..status(Status::Code(0)) },
        )
        .args(vec![
            Arg::Lit("-c"),
            Arg::Lit("for i in 1 2 3 4 5; do v=$($EXOBOX_TEST_PATCHELF --version | $EXOBOX_TEST_COREUTILS/bin/cat) || exit 1; [ -n \"$v\" ] || exit 1; $EXOBOX_TEST_COREUTILS/bin/true | $EXOBOX_TEST_PATCHELF --version >/dev/null || exit 1; done; echo PIPELINE_OK"),
        ])
        .uses(&["EXOBOX_TEST_PATCHELF", "EXOBOX_TEST_COREUTILS"]),
        // A compile and link: gcc's driver, collect2 and the ld wrapper (posix_spawn, a bash
        // script) in processes made one from another. The link failed in ld.so ("Inconsistency
        // detected ... elf_machine_rela_relative") when a library's data pages, written by an
        // earlier program in the chain, were mapped in place again (arena: high-water's zone).
        Case {
            timeout: Duration::from_secs(15),
            ..case("gcc", Prog::External("EXOBOX_TEST_BASH"), FORK, ok("GCC_OK"))
                .args(vec![
                    Arg::Lit("-c"),
                    Arg::Lit("export PATH=$EXOBOX_TEST_COREUTILS/bin:$PATH; d=$(mktemp -d -p /tmp) && cd $d && printf 'int main(void) { return 7; }\\n' > m.c && $EXOBOX_TEST_GCC -o m m.c; ./m; [ $? = 7 ] && echo GCC_OK; rm -rf $d"),
                ])
                .uses(&["EXOBOX_TEST_GCC", "EXOBOX_TEST_COREUTILS"])
        },
        // The CPUs a program is told: the host's where its threads run in parallel, one in
        // coroutine mode (rustc sized its codegen from it).
        Case { check: Some(nproc_is_hosts), ..case("nproc", Prog::Fixture("nproc"), THREADED_FORK, ok("NPROC ")) },
        case("nproc_one", Prog::Fixture("nproc"), &[Mode::Coroutine], ok("NPROC 1")).native(None),
        // cargo, rustup-less: Rust's std probes statx with NULLs (statx_probe), which crashed every
        // cargo at startup. Its build in fork mode: cargo, rustc and cc, each a process of its own.
        case("cargo_version", Prog::External("EXOBOX_TEST_CARGO"), ALL, ok("cargo ")).args(vec![Arg::Lit("--version")]),
        Case {
            timeout: Duration::from_secs(20),
            ..case("cargo_build", Prog::External("EXOBOX_TEST_BASH"), FORK, ok("CARGO_BUILD_OK"))
                .args(vec![
                    Arg::Lit("-c"),
                    Arg::Lit("export PATH=$EXOBOX_TEST_COREUTILS/bin:${EXOBOX_TEST_RUSTC%/*}:${EXOBOX_TEST_GCC%/*}:$PATH; d=$(mktemp -d -p /tmp) && cd $d && export CARGO_HOME=$d/home && mkdir src && printf '[package]\\nname = \"t\"\\nversion = \"0.1.0\"\\nedition = \"2021\"\\n' > Cargo.toml && printf 'fn main() { std::process::exit(7) }\\n' > src/main.rs && $EXOBOX_TEST_CARGO build --offline -q && ./target/debug/t; [ $? = 7 ] && echo CARGO_BUILD_OK; rm -rf $d"),
                ])
                .uses(&["EXOBOX_TEST_CARGO", "EXOBOX_TEST_RUSTC", "EXOBOX_TEST_GCC", "EXOBOX_TEST_COREUTILS"])
        },
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
/// The count is this process's own (the sandbox's host threads run where it may).
fn nproc_is_hosts(out: &str) -> Result<(), String> {
    let want = std::thread::available_parallelism().map_err(|e| e.to_string())?.get();
    if out.lines().any(|l| l == format!("NPROC {want}")) { Ok(()) } else { Err(format!("want NPROC {want} in:\n{out}")) }
}

fn sysaudit_check(out: &str) -> Result<(), String> {
    const EPERM: &[&str] = &[
        "swapon", "swapoff", "sethostname", "setdomainname", "acct",
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
    // Served, and with sysaudit's arguments Linux's own answer is an errno these classes name:
    // a signal queued to another pid with si_code >= 0 is EPERM (do_rt_sigqueueinfo checks that
    // first), and a futex op that doesn't exist (the buffer's address as the op) is ENOSYS.
    const SERVED_AS: &[(&str, &str)] = &[("rt_sigqueueinfo", "EPERM"), ("rt_tgsigqueueinfo", "EPERM"), ("futex", "ENOSYS")];
    // Served, and the buffer's address as the mode decides the answer (its file type bits): a
    // device node's is EPERM, an invalid type's EINVAL. Either is served.
    const SERVED_OR: &[(&str, &str)] = &[("mknod", "EPERM"), ("mknodat", "EPERM")];
    let class = |nr: i64| -> &'static str {
        let name = syscalls::Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("");
        if let Some((_, as_)) = SERVED_AS.iter().find(|(n, _)| *n == name) {
            as_
        } else if EPERM.contains(&name) {
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
        let name = syscalls::Sysno::new(nr as usize).map(|s| s.name()).unwrap_or("");
        if got != want && !SERVED_OR.contains(&(name, got)) {
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
        Arg::Env(var) => env::var_os(var).map(PathBuf::from).unwrap_or_default(),
    });
    let mut cmd = if mode == Mode::Native {
        Command::new(&prog)
    } else {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_exobox"));
        cmd.args(["run", "--mode", mode.name(), "--allow-path"]).arg(fx::bin_dir());
        for var in &c.uses {
            let Some(p) = env::var_os(var) else { return Err(format!("{var} unset: run in the devshell (./test)").into()) };
            let p = PathBuf::from(p);
            // Its store path (`/nix/store/<hash>-<name>`), which brings its closure.
            let store = p.ancestors().find(|a| a.parent() == Some(std::path::Path::new("/nix/store"))).unwrap_or(&p);
            cmd.arg("--allow-path").arg(store);
        }
        cmd.args(&c.flags).arg("--").arg(&prog);
        cmd
    };
    cmd.args(args)
        .env("EXOBOX_TEST_MODE", mode.name())
        .env("EXOBOX_TEST_SECRET", secret)
        .env("EXOBOX_TEST_TARGET", std::process::id().to_string())
        .envs(c.env.iter().copied())
        .stdin(if c.stdin.is_some() || c.hold_stdin { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let (status, cpu, stdout, stderr) = spawn_bounded_with(cmd, c.stdin, c.stdout_delay, c.timeout)?;
    let expect = if mode == Mode::Native { c.native.as_ref().unwrap() } else { &c.sandbox };
    let fail = |why: String| -> Result<(), Failed> {
        Err(format!("{why}\n--- status: {status:?}, cpu {cpu:?}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}").into())
    };
    let status_ok = match expect.status {
        Status::Code(n) => status.code() == Some(n),
        Status::Signal(s) => status.signal() == Some(s),
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
            Status::Any => write!(f, "any"),
        }
    }
}
