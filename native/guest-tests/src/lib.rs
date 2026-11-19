//! The in-guest tests: what a program observes inside the sandbox. Each test is an ordinary
//! function here; the test targets (tests/guest_*.rs) each expand [`all!`] into `#[test]`s calling
//! them, and nextest runs each test as its own process: natively (guest_native, which checks the
//! test itself: it must pass on Linux) or under `exobox run --mode M` (native/guest-tests/
//! run-in-guest, nextest's run-wrapper), so every test gets a sandbox of its own. What the host
//! sees of a run (its exit status, its CPU time, its stdio, the host's files) is
//! native/exobox/tests/suite.rs's.
//!
//! What a test may assume: it is the only test in its process (nextest), on a thread of libtest's
//! (not the main thread, which waits for it): a process-directed signal (`kill(getpid())`, an
//! itimer) may be delivered to that main thread, so a test wanting a signal on its own thread
//! sends it there (`raise`, `pthread_kill`, a timer with `SIGEV_THREAD_ID`). A forked child of a
//! test is a copy of a multi-threaded process: it keeps to async-signal-safe calls and `_exit`s.

#![allow(clippy::missing_safety_doc)]

pub mod exec;
pub mod files;
pub mod host_side;
pub mod memory;
pub mod net;
pub mod process;
pub mod procfs;
pub mod signals;
pub mod stdio;
pub mod threads;
pub mod time;

use std::path::PathBuf;
use std::time::Duration;

/// The mode this test runs in: `native`, `coroutine`, `threaded` or `fork` (the wrapper's
/// EXOBOX_TEST_MODE, which the sandbox passes on with the rest of the environment).
pub fn mode() -> String {
    std::env::var("EXOBOX_TEST_MODE").unwrap_or_else(|_| "native".into())
}

/// Whether this run has processes besides its own (natively, and in fork mode).
pub fn forks() -> bool {
    matches!(mode().as_str(), "native" | "fork")
}

/// A path of this test's own in /tmp (natively the host's /tmp, which other tests share; in the
/// guest its own). Not `temp_dir()`: the host's TMPDIR is passed on but names nothing in the guest.
pub fn tmp(name: &str) -> PathBuf {
    PathBuf::from(format!("/tmp/guest-tests-{}-{name}", std::process::id()))
}

/// A pipe: (read end, write end).
pub fn pipe() -> (i32, i32) {
    let mut p = [0; 2];
    // SAFETY: a two-int buffer.
    assert_eq!(unsafe { libc::pipe(p.as_mut_ptr()) }, 0, "pipe: {}", errno());
    (p[0], p[1])
}

pub fn errno() -> std::io::Error {
    std::io::Error::last_os_error()
}

pub fn raw_errno() -> i32 {
    errno().raw_os_error().unwrap_or(0)
}

pub fn gettid() -> i32 {
    // SAFETY: no arguments.
    unsafe { libc::gettid() }
}

/// Waits until `f` holds, up to 2 s (a process-directed signal's handler, on whichever thread).
pub fn eventually(what: &str, f: impl Fn() -> bool) {
    let t0 = std::time::Instant::now();
    while !f() {
        assert!(t0.elapsed() < Duration::from_secs(2), "{what}: not in 2 s");
        std::thread::sleep(Duration::from_millis(1));
    }
}

/// One module's tests as `#[test]`s calling this crate's functions of the same names.
#[macro_export]
macro_rules! group {
    ($m:ident: $($(#[$attr:meta])* $name:ident),* $(,)?) => {
        mod $m {
            $( #[test] $(#[$attr])* fn $name() { $crate::$m::$name() } )*
        }
    };
}

/// Every test, for a target: `all!(native)`, `all!(coroutine)`, `all!(threaded)`, `all!(fork)`.
/// The modes differ in which tests they have (`process` only where there are processes) and in
/// which known bugs they ignore: each such test is `#[ignore = "<why>"]` where it fails, until
/// the fix un-ignores it.
#[macro_export]
macro_rules! all {
    (native) => { $crate::all!(@one [] []); $crate::all!(@processes); };
    (coroutine) => {
        $crate::all!(@one [] []);
    };
    (threaded) => {
        $crate::all!(@one []
            [ignore = "guest: threaded/fork exec from a thread panics the runtime"]);
    };
    (fork) => {
        $crate::all!(@one []
            [ignore = "guest: threaded/fork exec from a thread panics the runtime"]);
        $crate::all!(@processes);
    };
    // `idle`: of idle_cpu (none ignore it now). `exec`: of exec_reset, which in threaded
    // and fork mode panics the runtime (native/rt/src/context.rs:62, a subtraction's overflow)
    // after an exec from libtest's test thread while its main thread waits, and the sandbox hangs.
    (@one [$($idle:meta)*] [$($exec:meta)*]) => {
        $crate::group!(files: file_rw, dirs, shmap, statx_probe, devnodes);
        $crate::group!(memory: big_alloc, rwx, small_stack, gsbase);
        $crate::group!(threads: thread_fds, futex_wake, std_sync, sleepy, threadpoll, futex_timeout);
        $crate::group!(signals:
            handler_at_raise, blocked_pending, kill_process, sigqueue_info, timer_eintr, altstack,
            sa_restart, longjmp_out, nested_and_vector_regs, thread_in_waits, every_signal, sigsys,
        );
        $crate::group!(net: tcp_loopback, udp_loopback, unix_sockets, unreachable);
        $crate::group!(procfs: meminfo, proc_self, uname);
        $crate::group!(stdio: stdio_types, stdin_eof, stdout_large);
        $crate::group!(time: clock);
        $crate::group!(exec: $(#[$exec])* exec_reset);
        $crate::group!(host_side:
            $(#[$idle])* idle_cpu,
            #[should_panic(expected = "boom")] should_panic,
            // Run by hand (--run-ignored only) to see how failures look.
            #[ignore] demo_assert_fails,
            #[ignore] demo_abort,
            #[ignore] demo_hang,
        );
    };
    (@processes) => {
        $crate::group!(process:
            fork_pipe_status, fork_children, grandchild, fork_late_read, spawn_self, child_signals,
            siginfo_from_child, child_killed, forkthreads, fork_rng, settid,
            // What spawn_self, child_signals and settid run (by --exact, with GUEST_TESTS_HELPER).
            #[ignore] child_helper,
        );
    };
}
