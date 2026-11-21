//! The host-side regression suite: one table of cases (`cases()`), each a program run natively
//! (which checks the test itself) and under `unsharek` in every mode it names, and checked from
//! the host: its exit status or signal, its stdio (input given, output read late), its CPU time,
//! files on the host, the CLI's flags, programs from nixpkgs. A run is a trial named
//! `<case>::<native|coroutine|threaded|fork>`, with a timeout and an optional CPU budget, so
//! `cargo nextest run -E 'test(/::fork$/)'` runs one mode and a hang fails in seconds. What a
//! program observes inside the guest is crates/guest-tests' (Rust #[test]s, a sandbox each).

use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::str::FromStr;
use std::time::Duration;
use std::env;

use unsharek_fixtures as fx;

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
    /// The directory `Marker` is in (empty at the start), which `Case::rw_dir` serves read-write.
    MarkerDir,
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
    /// store paths are given (`--closure`), closures and all.
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
    /// `--rw` the run's own directory (`Arg::MarkerDir`): a host directory served live.
    rw_dir: bool,
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
        rw_dir: false,
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
    /// More the sandbox's stdout must have, and must not.
    fn expect_also(mut self, has: &[&'static str], hasnt: &[&'static str]) -> Self {
        self.sandbox.stdout.extend(has);
        self.sandbox.not_stdout.extend(hasnt);
        self
    }
    fn renamed(mut self, name: &'static str) -> Self {
        self.name = name;
        self
    }
}

fn runtime_panic(from: &'static str) -> Case {
    let name = Box::leak(format!("runtime_panic_{from}").into_boxed_str());
    let expect = Expect {
        stderr: vec!["the runtime panicked: "],
        not_stdout: vec!["RUNTIME_PANIC_OK"],
        ..status(Status::Signal(6))
    };
    Case {
        native: Some(ok("RUNTIME_PANIC_OK")),
        timeout: Duration::from_secs(3),
        ..case(name, Prog::Fixture("runtime_panic"), ALL, expect).args(vec![Arg::Lit(from)])
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
        fixture("escape", ALL).args(vec![Arg::Secret]).native(None),
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
        // A panic in the runtime ends the sandbox at once, by SIGABRT (it hung in threaded and
        // fork mode): the debug build's test hook, from the main thread, from another, and in a
        // thread's clone (the guest left mid-change).
        runtime_panic("main"),
        runtime_panic("thread"),
        runtime_panic("clone"),
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
            ..case("xz_pipe", Prog::External("UNSHAREK_TEST_XZ"), ALL, Expect { stdout: vec!["7zXZ"], ..status(Status::Code(0)) })
                .args(vec![Arg::Lit("-T2"), Arg::Lit("-3"), Arg::Lit("--block-size=128KiB"), Arg::Lit("-c"), Arg::Env("UNSHAREK_TEST_BASH")])
                .uses(&["UNSHAREK_TEST_BASH"])
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
            Prog::External("UNSHAREK_TEST_BASH"),
            FORK,
            Expect { stdout: vec!["PIPELINE_OK"], ..status(Status::Code(0)) },
        )
        .args(vec![
            Arg::Lit("-c"),
            Arg::Lit("for i in 1 2 3 4 5; do v=$($UNSHAREK_TEST_PATCHELF --version | $UNSHAREK_TEST_COREUTILS/bin/cat) || exit 1; [ -n \"$v\" ] || exit 1; $UNSHAREK_TEST_COREUTILS/bin/true | $UNSHAREK_TEST_PATCHELF --version >/dev/null || exit 1; done; echo PIPELINE_OK"),
        ])
        .uses(&["UNSHAREK_TEST_PATCHELF", "UNSHAREK_TEST_COREUTILS"]),
        // A compile and link: gcc's driver, collect2 and the ld wrapper (posix_spawn, a bash
        // script) in processes made one from another. The link failed in ld.so ("Inconsistency
        // detected ... elf_machine_rela_relative") when a library's data pages, written by an
        // earlier program in the chain, were mapped in place again (arena: high-water's zone).
        Case {
            timeout: Duration::from_secs(15),
            ..case("gcc", Prog::External("UNSHAREK_TEST_BASH"), FORK, ok("GCC_OK"))
                .args(vec![
                    Arg::Lit("-c"),
                    Arg::Lit("export PATH=$UNSHAREK_TEST_COREUTILS/bin:$PATH; d=$(mktemp -d -p /tmp) && cd $d && printf 'int main(void) { return 7; }\\n' > m.c && $UNSHAREK_TEST_GCC -o m m.c; ./m; [ $? = 7 ] && echo GCC_OK; rm -rf $d"),
                ])
                .uses(&["UNSHAREK_TEST_GCC", "UNSHAREK_TEST_COREUTILS"])
        },
        // Libraries mapped in place at every exec, from a forked child too, their code never
        // writable (crates/unsharek-fixtures/c/libcode.c).
        case("libcode_inplace", Prog::Fixture("libcode"), ALL, ok("LIBCODE_OK")).args(vec![Arg::Lit("inplace"), Arg::Lit("4")]),
        case("libcode_inplace_fork", Prog::Fixture("libcode"), FORK, ok("LIBCODE_OK"))
            .args(vec![Arg::Lit("inplace"), Arg::Lit("6"), Arg::Lit("fork")]),
        case("libcode_write", Prog::Fixture("libcode"), ALL, Expect { not_stdout: vec!["LIBCODE_WROTE"], ..status(Status::Signal(11)) })
            .args(vec![Arg::Lit("write")]),
        case("libcode_mprotect", Prog::Fixture("libcode"), ALL, ok("MPROTECT_EACCES"))
            .args(vec![Arg::Lit("mprotect")])
            .native(Some(ok("MPROTECT_OK"))),
        // The CPUs a program is told: the host's where its threads run in parallel, one in
        // coroutine mode (rustc sized its codegen from it).
        Case { check: Some(nproc_is_hosts), ..case("nproc", Prog::Fixture("nproc"), THREADED_FORK, ok("NPROC ")) },
        case("nproc_one", Prog::Fixture("nproc"), &[Mode::Coroutine], ok("NPROC 1")).native(None),
        // A thread kept busy mustn't keep another's timer from being serviced (with one CPU passed
        // between host threads, main's sleep never ended). Busy in user code: not coroutine mode
        // (one host thread, and user code isn't preempted).
        fixture("busy_sleep", THREADED_FORK).args(vec![Arg::Lit("user")]),
        fixture("busy_sleep", ALL).renamed("busy_sleep_calls").args(vec![Arg::Lit("calls")]),
        fixture("signal_futex_race", ALL),
        // cargo, rustup-less: Rust's std probes statx with NULLs (statx_probe), which crashed every
        // cargo at startup. Its build in fork mode: cargo, rustc and cc, each a process of its own.
        case("cargo_version", Prog::External("UNSHAREK_TEST_CARGO"), ALL, ok("cargo ")).args(vec![Arg::Lit("--version")]),
        Case {
            timeout: Duration::from_secs(20),
            ..case("cargo_build", Prog::External("UNSHAREK_TEST_BASH"), FORK, ok("CARGO_BUILD_OK"))
                .args(vec![
                    Arg::Lit("-c"),
                    Arg::Lit("export PATH=$UNSHAREK_TEST_COREUTILS/bin:${UNSHAREK_TEST_RUSTC%/*}:${UNSHAREK_TEST_GCC%/*}:$PATH; d=$(mktemp -d -p /tmp) && cd $d && export CARGO_HOME=$d/home && mkdir src && printf '[package]\\nname = \"t\"\\nversion = \"0.1.0\"\\nedition = \"2021\"\\n' > Cargo.toml && printf 'fn main() { std::process::exit(7) }\\n' > src/main.rs && $UNSHAREK_TEST_CARGO build --offline -q && ./target/debug/t; [ $? = 7 ] && echo CARGO_BUILD_OK; rm -rf $d"),
                ])
                .uses(&["UNSHAREK_TEST_CARGO", "UNSHAREK_TEST_RUSTC", "UNSHAREK_TEST_GCC", "UNSHAREK_TEST_COREUTILS"])
        },
        // The CLI's environment is empty by default: the run's own variables reach the program only
        // when kept (the suite keeps its UNSHAREK_TEST_* ones), `--setenv`'s do, and one the host
        // sets but nobody keeps doesn't. Before, the program got all of the host's.
        fixture("env_dump", ALL)
            .flags(&["--setenv", "SET_BY_FLAG=1"])
            .native(None)
            .expect_also(&["SET_BY_FLAG=1", "UNSHAREK_TEST_MODE="], &["UNSHAREK_TEST_HOST_ONLY"]),
        // Host directories served live (the CLI's --ro DIR and --rw DIR: virtio-fs, served by
        // unsharek-fs-server's process). The suite's own --ro of the fixtures' directory is one
        // already: every fixture runs from it.
        Case {
            rw_dir: true,
            ..case("hostdir_write", Prog::Fixture("hostdir"), ALL, Expect { creates: Some(true), ..ok("HOSTDIR_WRITE") })
        }
        .args(vec![Arg::Lit("write"), Arg::MarkerDir]),
        // A read-only directory refuses every change (the server's early EROFS, and Landlock's
        // read-only rules under it): on the fixture's own binary, in the suite's --ro directory.
        // Not natively: there the file is writable, and it would be changed.
        fixture("hostdir", ALL)
            .renamed("hostdir_ro")
            .args(vec![Arg::Lit("ro"), Arg::Fixture("hostdir")])
            .native(None)
            .expect_also(&["HOSTDIR_RO"], &[]),
        // A symlink or a hard link to a host file outside the directory doesn't reach it: the guest
        // resolves links in its own tree, where the file isn't. Natively the links work: not run.
        Case { rw_dir: true, ..case("hostdir_escape", Prog::Fixture("hostdir"), ALL, ok("HOSTDIR_ESCAPE")) }
            .args(vec![Arg::Lit("escape"), Arg::MarkerDir, Arg::Secret])
            .native(None),
        Case { rw_dir: true, timeout: Duration::from_secs(20), ..case("hostdir_big", Prog::Fixture("hostdir"), ALL, ok("HOSTDIR_BIG")) }
            .args(vec![Arg::Lit("big"), Arg::MarkerDir]),
        // Requests from several host threads (threaded mode) and processes (fork mode) at once.
        Case { rw_dir: true, timeout: Duration::from_secs(20), ..case("hostdir_par", Prog::Fixture("hostdir"), THREADED_FORK, ok("HOSTDIR_PAR")) }
            .args(vec![Arg::Lit("par"), Arg::MarkerDir]),
        fixture("forkbomb", FORK).flags(&["--max-procs=16"]).env(&[("UNSHAREK_TEST_MAX_PROCS", "16")]).native(None),
        Case {
            timeout: Duration::from_secs(15),
            check: Some(sysaudit_check),
            ..case("sysaudit", Prog::Fixture("sysaudit"), FORK, ok("SYSAUDIT_DONE")).native(None)
        },
        // Programs from nixpkgs.
        case("python", Prog::External("UNSHAREK_TEST_PYTHON"), ALL, ok("{\"a\": 42}"))
            .args(vec![Arg::Lit("-c"), Arg::Lit("import json; print(json.dumps({'a': 6 * 7}))")]),
        case(
            "bash",
            Prog::External("UNSHAREK_TEST_BASH"),
            FORK,
            Expect { stdout: vec!["42", "sub=ok", "st=3", "bg=done"], ..status(Status::Code(0)) },
        )
        .args(vec![
            Arg::Lit("-c"),
            Arg::Lit("echo $((6 * 7)) | { read x; echo $x; }; s=$(echo ok); echo sub=$s; (exit 3); echo st=$?; { sleep 0.05; echo bg=done; } & wait"),
        ]),
    ];
    c.extend(static_programs());
    c.extend(escape_gate());
    c.sort_by_key(|c| c.name);
    c
}

/// The filter in a real sandbox: each forbidden host call through the gate (escape_gate.c's
/// probes) kills the sandbox with SIGSYS before it can say it survived. Every number's verdict is
/// unsharek-tcb's (tests/filter.rs, against its model); these are the calls an escape would try.
fn escape_gate() -> Vec<Case> {
    const THREADS: &[Mode] = &[Mode::Threaded, Mode::Fork];
    let probes: &[(&'static str, &'static str, &'static [Mode])] = &[
        ("escape_gate_openat", "openat", ALL),
        ("escape_gate_socket", "socket", ALL),
        ("escape_gate_getppid", "getppid", ALL),
        ("escape_gate_writev_stderr", "writev_stderr", ALL),
        ("escape_gate_kill_other", "kill_other", ALL),
        ("escape_gate_tgkill_other", "tgkill_other", ALL),
        ("escape_gate_madvise_arena", "madvise_arena", ALL),
        ("escape_gate_madvise_vdso", "madvise_vdso", ALL),
        ("escape_gate_mmap", "mmap", ALL),
        ("escape_gate_clone_vm_sigchld", "clone_vm_sigchld", ALL),
        ("escape_gate_clone_newuser", "clone_newuser", ALL),
        ("escape_gate_clone_sigchld_stack", "clone_sigchld_stack", ALL),
        ("escape_gate_clone_thread_settls", "clone_thread_settls", THREADS),
        ("escape_gate_clone_thread_high_bit", "clone_thread_high_bit", THREADS),
        ("escape_gate_clone3", "clone3", ALL),
        ("escape_gate_exit_1", "exit_1", THREADS),
        ("escape_gate_sigaltstack", "sigaltstack", ALL),
        ("escape_gate_prctl", "prctl", ALL),
        ("escape_gate_seccomp", "seccomp", ALL),
    ];
    probes
        .iter()
        .map(|&(name, probe, modes)| {
            case(name, Prog::Fixture("escape_gate"), modes, Expect { not_stdout: vec!["ESCAPE_GATE_SURVIVED"], ..status(Status::Signal(SIGSYS)) })
                .args(vec![Arg::Lit(probe)])
                .native(None)
        })
        .collect()
}

/// Static programs from three toolchains (nix/test-programs.nix): no interpreter, nothing but the
/// program's own startup code between unsharek's loader and its main.
fn static_programs() -> Vec<Case> {
    let bb = |name, modes, args: &[&'static str], expect| {
        case(name, Prog::External("UNSHAREK_TEST_BUSYBOX"), modes, expect).args(args.iter().map(|a| Arg::Lit(a)).collect())
    };
    vec![
        // Go's runtime (goprobe, CGO off): goroutines, timers, parallel work and GC, an HTTP
        // server and its clients on loopback through the netpoller. With "preempt", a spinning
        // goroutine preempted at its calls while GOMAXPROCS is 1 (not coroutine mode: one of its
        // threads in user code keeps the others from running); with "exec", os.StartProcess and
        // its status (fork mode). Not tested, a known limit: Go's asynchronous preemption, of a
        // loop with no calls, by SIGURG, which the runtime delivers only at the thread's next call.
        Case { timeout: Duration::from_secs(10), ..case("go", Prog::External("UNSHAREK_TEST_GOPROBE"), ALL, ok("GOPROBE_OK")) },
        Case {
            timeout: Duration::from_secs(10),
            ..case("go_preempt", Prog::External("UNSHAREK_TEST_GOPROBE"), THREADED_FORK, ok("preemption ok"))
                .args(vec![Arg::Lit("preempt")])
        },
        Case {
            timeout: Duration::from_secs(10),
            ..case("go_exec", Prog::External("UNSHAREK_TEST_GOPROBE"), FORK, Expect { stdout: vec!["exec ok", "GOPROBE_OK"], ..status(Status::Code(0)) })
                .args(vec![Arg::Lit("exec")])
        },
        // A real Go server from nixpkgs (go-httpbin, static), busybox's wget its client: a
        // response, a timed one (/delay), a streamed one, and its end by SIGTERM.
        Case {
            timeout: Duration::from_secs(10),
            ..bb("go_httpbin", FORK, &["sh", "-c", HTTPBIN], Expect { stdout: vec!["get=1", "delay=ok", "stream=5", "HTTPBIN_OK"], ..status(Status::Code(0)) })
                .uses(&["UNSHAREK_TEST_HTTPBIN", "UNSHAREK_TEST_BUSYBOX"])
        },
        // musl's (busybox): applets alone in every mode, and a shell's forks in fork mode.
        bb("busybox_ls", ALL, &["ls", "/"], ok("proc\n")),
        Case { stdin: Some("b\nc\na\n"), ..bb("busybox_sort", ALL, &["sort"], ok("a\nb\nc\n")) },
        Case { stdin: Some("one two\nthree\n"), ..bb("busybox_wc", ALL, &["wc", "-lw"], ok("2         3")) },
        Case { stdin: Some("through cat\n"), ..bb("busybox_cat", ALL, &["cat"], ok("through cat")) },
        bb("busybox_sh", ALL, &["sh", "-c", "x=$((6*7)); read -r y </proc/self/comm; echo $x $y; case $x in 4*) echo SH_OK;; esac"], ok("42 busybox\nSH_OK")),
        bb(
            "busybox_pipeline",
            FORK,
            &["sh", "-c", "b=$UNSHAREK_TEST_BUSYBOX; n=$($b ls / | $b sort -r | $b grep -c .) && echo n=$n; printf '3\\n1\\n2\\n' | $b sort | $b tr '\\n' ' ' | $b wc -w; $b sh -c 'exit 5'; echo st=$?"],
            Expect { stdout: vec!["n=", "\n3\n", "st=5"], ..status(Status::Code(0)) },
        )
        .uses(&["UNSHAREK_TEST_BUSYBOX"]),
        // glibc's, -static-pie (crates/unsharek-fixtures/c/static_glibc.c): self-relocation, IFUNCs, TLS
        // and threads without ld.so; a fork in fork mode.
        fixture("static_glibc", ALL),
        fixture("static_glibc", FORK).renamed("static_glibc_fork").args(vec![Arg::Lit("fork")]),
    ]
}

/// go_httpbin's script (busybox sh): the server in the background on a port of its own (natively
/// the host's loopback is shared), polled until it answers.
const HTTPBIN: &str = r#"b=$UNSHAREK_TEST_BUSYBOX; p=$((20000 + $$ % 20000)); u=http://127.0.0.1:$p
$UNSHAREK_TEST_HTTPBIN -host 127.0.0.1 -port $p >/dev/null 2>&1 &
pid=$!
i=0; until $b wget -q -O /dev/null $u/status/200 2>/dev/null; do i=$((i+1)); [ $i -gt 250 ] && { echo NO_SERVER; exit 1; }; $b usleep 20000; done
echo get=$($b wget -q -O - "$u/get?x=42" | $b grep -c '"42"')
$b wget -q -O - $u/delay/0.2 | $b grep -q '"url"' && echo delay=ok
echo stream=$($b wget -q -O - $u/stream/5 | $b wc -l)
kill $pid; wait $pid; echo HTTPBIN_OK"#;

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
            None => return Err(format!("{var} unset: run in the devshell (cargo xtask test)").into()),
        },
    };
    let marker_dir = tempfile::tempdir()?;
    let marker = marker_dir.path().join("created-by-the-program");
    let args = c.args.iter().map(|a| match a {
        Arg::Lit(s) => PathBuf::from(s),
        Arg::Secret => secret.clone(),
        Arg::Marker => marker.clone(),
        Arg::MarkerDir => marker_dir.path().to_owned(),
        Arg::Fixture(name) => fx::bin(name),
        Arg::Denied(name) => fx::denied_dir().join(name),
        Arg::Env(var) => env::var_os(var).map(PathBuf::from).unwrap_or_default(),
    });
    let mut cmd = if mode == Mode::Native {
        Command::new(&prog)
    } else {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_unsharek"));
        // The fixtures' directory, live, and the store paths its programs reference.
        cmd.args(["--mode", mode.name(), "--ro"]).arg(fx::bin_dir()).arg("--closure").arg(fx::bin_dir());
        // A program from the store (an external case's): its closure, given as any other is.
        if prog.starts_with("/nix/store") {
            cmd.arg("--closure").arg(&prog);
        }
        for var in &c.uses {
            let Some(p) = env::var_os(var) else { return Err(format!("{var} unset: run in the devshell (cargo xtask test)").into()) };
            let p = PathBuf::from(p);
            // Its store path (`/nix/store/<hash>-<name>`), which brings its closure.
            let store = p.ancestors().find(|a| a.parent() == Some(std::path::Path::new("/nix/store"))).unwrap_or(&p);
            cmd.arg("--closure").arg(store);
        }
        // The environment is empty but for what's kept: the variables this run sets below, the
        // programs the case uses (its scripts name them: `$UNSHAREK_TEST_GCC`), and the
        // devshell's PATH and HOME (programs that run others, like cargo and bash, need them).
        let fixed = ["UNSHAREK_TEST_MODE", "UNSHAREK_TEST_SECRET", "UNSHAREK_TEST_TARGET", "PATH", "HOME"];
        for k in fixed.into_iter().chain(c.env.iter().map(|e| e.0)).chain(c.uses.iter().copied()) {
            cmd.arg("--keep-env").arg(k);
        }
        if c.rw_dir {
            cmd.arg("--rw").arg(marker_dir.path());
        }
        cmd.args(&c.flags).arg("--").arg(&prog);
        cmd
    };
    cmd.args(args)
        .env("UNSHAREK_TEST_MODE", mode.name())
        .env("UNSHAREK_TEST_SECRET", secret)
        .env("UNSHAREK_TEST_TARGET", std::process::id().to_string())
        // set for every run and kept for none: a sandboxed program never sees it (env_dump)
        .env("UNSHAREK_TEST_HOST_ONLY", "1")
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
