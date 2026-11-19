//! Tests that run inside the guest. Each test is an ordinary function here; the test targets
//! (tests/guest_*.rs) each expand [`all!`] into `#[test]`s calling them, and nextest runs each
//! test as its own process: natively (guest_native, which checks the tests themselves) or under
//! `exobox run --mode M` (native/guest-tests/run-in-guest, nextest's run-wrapper), so every test
//! gets a sandbox of its own.
//!
//! What a test may assume: it is the only test in its process (nextest), on a thread of libtest's
//! (not the main thread, which waits for it): a process-directed signal (`kill(getpid())`, an
//! itimer) may be delivered to that main thread, so a test wanting a signal on its own thread
//! sends it there (`raise`, `pthread_kill`, a timer with `SIGEV_THREAD_ID`).

#![allow(clippy::missing_safety_doc)]

pub mod exec;
pub mod files;
pub mod host_side;
pub mod net;
pub mod process;
pub mod procfs;
pub mod signals;
pub mod stdio;
pub mod threads;

use std::path::PathBuf;

/// The mode this test runs in: `native`, `coroutine`, `threaded` or `fork` (the wrapper's
/// EXOBOX_TEST_MODE, which the sandbox passes on with the rest of the environment).
pub fn mode() -> String {
    std::env::var("EXOBOX_TEST_MODE").unwrap_or_else(|_| "native".into())
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

pub fn gettid() -> i32 {
    // SAFETY: no arguments.
    unsafe { libc::gettid() }
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

/// Every test, for a target: `all!(one_process)` in the modes with one process (coroutine,
/// threaded), `all!(processes)` where there are more (natively, fork mode).
#[macro_export]
macro_rules! all {
    (common) => {
        $crate::group!(files: file_rw, dirs, shmap);
        $crate::group!(threads: thread_fds, futex_wake, std_sync,
            // Found by this spike, every mode: FUTEX_WAIT's timeout returns 0 after ~1 ms.
            #[ignore = "guest: a timed FUTEX_WAIT returns 0 early"] futex_timeout,
        );
        $crate::group!(signals: handler_at_raise, blocked_pending, kill_process, timer_eintr, pthread_kill_read);
        $crate::group!(net: tcp_loopback, udp_loopback, unix_sockets);
        $crate::group!(procfs: meminfo, proc_self, uname);
        $crate::group!(stdio: stdio_types, stdin_eof, stdout_large);
        // Passes natively and in coroutine mode; in threaded and fork mode the runtime panics
        // (native/rt/src/context.rs:62, a subtraction's overflow) after the exec and the sandbox
        // hangs. Exec'd from libtest's test thread while its main thread waits.
        $crate::group!(exec: #[ignore = "guest: threaded/fork exec from a thread panics the runtime"] exec_reset);
        $crate::group!(host_side:
            // std's Condvar::wait_timeout returns early in the guest (futex_timeout's bug).
            #[ignore = "guest: a timed FUTEX_WAIT returns 0 early"] idle_cpu,
            #[should_panic(expected = "boom")] should_panic,
            // Run by hand (--run-ignored only) to see how failures look.
            #[ignore] demo_assert_fails,
            #[ignore] demo_abort,
            #[ignore] demo_hang,
        );
    };
    (one_process) => {
        $crate::all!(common);
    };
    (processes) => {
        $crate::all!(common);
        $crate::group!(process:
            fork_pipe_status, fork_children, grandchild, spawn_self, child_signals, siginfo_from_child,
            // What spawn_self and child_signals run (by --exact, with GUEST_TESTS_HELPER set).
            #[ignore] child_helper,
        );
    };
}
