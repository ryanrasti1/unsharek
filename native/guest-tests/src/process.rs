//! Processes: natively and in fork mode only (fork.c's checks, signals.c's 11-12, and std's
//! process::Command, which spawns with clone(CLONE_VM | CLONE_VFORK) through posix_spawn).
//!
//! A forked child of a test is a copy of a multi-threaded process (libtest's main thread is in
//! the parent only), so it keeps to async-signal-safe calls and `_exit`s.

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::pipe;

static COUNTER: AtomicI32 = AtomicI32::new(100);

fn wait(pid: i32) -> i32 {
    let mut st = 0;
    loop {
        // SAFETY: waiting on a child of ours.
        let w = unsafe { libc::waitpid(pid, &mut st, 0) };
        if w == pid {
            return st;
        }
        assert_eq!(crate::errno().raw_os_error(), Some(libc::EINTR), "waitpid({pid}) = {w}");
    }
}

/// A child writes to a pipe and exits with a status; the parent's memory is its own.
pub fn fork_pipe_status() {
    let (r, w) = pipe();
    // SAFETY: the child only writes, and _exits.
    unsafe {
        let c = libc::fork();
        assert!(c >= 0, "fork: {}", crate::errno());
        if c == 0 {
            libc::close(r);
            COUNTER.fetch_add(1, Ordering::SeqCst);
            let msg = if COUNTER.load(Ordering::SeqCst) == 101 { b"child 101" } else { b"child ???" };
            if libc::write(w, msg.as_ptr().cast(), msg.len()) != msg.len() as isize {
                libc::_exit(99);
            }
            libc::_exit(7);
        }
        libc::close(w);
        let mut b = [0u8; 64];
        let n = libc::read(r, b.as_mut_ptr().cast(), b.len());
        assert_eq!(&b[..n.max(0) as usize], b"child 101");
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 7, "status {st:#x}");
        assert_eq!(COUNTER.load(Ordering::SeqCst), 100, "the parent's counter changed");
    }
}

/// Several children at once, reaped in any order; then none left.
pub fn fork_children() {
    const N: i32 = 4;
    let mut kids = vec![];
    for i in 0..N {
        // SAFETY: the child computes and _exits.
        let c = unsafe { libc::fork() };
        assert!(c >= 0);
        if c == 0 {
            let mut x = 0u64;
            for k in 0..2_000_000u64 * (N - i) as u64 {
                x = std::hint::black_box(x + k);
            }
            unsafe { libc::_exit(10 + i) };
        }
        kids.push(c);
    }
    let mut seen = 0;
    for _ in 0..N {
        let mut st = 0;
        // SAFETY: waiting on our children.
        let w = unsafe { libc::wait(&mut st) };
        let idx = kids.iter().position(|&k| k == w).unwrap_or_else(|| panic!("wait: {w}"));
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 10 + idx as i32, "pid {w} status {st:#x}");
        seen |= 1 << idx;
    }
    assert_eq!(seen, (1 << N) - 1);
    let mut st = 0;
    assert_eq!(unsafe { libc::wait(&mut st) }, -1, "a fifth child?");
}

/// A grandchild: the child forks, waits, and passes its status on.
pub fn grandchild() {
    // SAFETY: the children fork, wait and _exit.
    unsafe {
        let c = libc::fork();
        if c == 0 {
            let g = libc::fork();
            if g == 0 {
                libc::_exit(3);
            }
            let mut gs = 0;
            if libc::waitpid(g, &mut gs, 0) != g || !libc::WIFEXITED(gs) {
                libc::_exit(98);
            }
            libc::_exit(libc::WEXITSTATUS(gs) + 20);
        }
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 23, "status {st:#x}");
    }
}

/// This binary, run again as `child_helper` with GUEST_TESTS_HELPER=`what`.
fn helper(what: &str) -> Command {
    let mut c = Command::new(std::env::current_exe().unwrap());
    c.args(["--exact", "process::child_helper", "--ignored", "--nocapture"]).env("GUEST_TESTS_HELPER", what);
    c
}

/// std's Command (posix_spawn: clone(CLONE_VM | CLONE_VFORK), then execve): the child's stdout
/// through a pipe, its exit status.
pub fn spawn_self() {
    let out = helper("exit7").stderr(Stdio::inherit()).output().unwrap();
    assert_eq!(out.status.code(), Some(7), "{:?}", out);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(stdout.contains("HELPER_RAN"), "stdout: {stdout}");
}

/// A child's death by a signal, as its parent sees it: its own abort, and the parent's SIGTERM
/// while it sleeps (the guest half of the suite's abort and sigterm cases).
pub fn child_signals() {
    let st = helper("abort").stdout(Stdio::null()).stderr(Stdio::null()).status().unwrap();
    assert_eq!(st.signal(), Some(libc::SIGABRT), "{st:?}");
    let mut c = helper("sleep").stdout(Stdio::piped()).spawn().unwrap();
    // Until it's asleep (it says so, after libtest's "running 1 test"), so the signal ends the
    // sleep and not libtest's start.
    let out = std::io::BufReader::new(c.stdout.take().unwrap());
    let lines: Vec<String> =
        std::io::BufRead::lines(out).map(|l| l.unwrap()).take_while(|l| !l.contains("HELPER_SLEEPING")).collect();
    assert!(lines.len() < 10, "no HELPER_SLEEPING: {lines:?}");
    // SAFETY: a child of ours, not yet reaped.
    unsafe { libc::kill(c.id() as i32, libc::SIGTERM) };
    let st = c.wait().unwrap();
    assert_eq!(st.signal(), Some(libc::SIGTERM), "{st:?}");
}

static INFO_PID: AtomicI32 = AtomicI32::new(0);
static CHLD: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_usr2(_: libc::c_int, si: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: kill's siginfo.
    INFO_PID.store(unsafe { (*si).si_pid() }, Ordering::SeqCst);
}
extern "C" fn on_chld(_: libc::c_int) {
    CHLD.fetch_add(1, Ordering::SeqCst);
}

/// SA_SIGINFO from another process, and SIGCHLD when it exits.
pub fn siginfo_from_child() {
    crate::signals::set(
        libc::SIGUSR2,
        on_usr2 as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) as usize,
        libc::SA_SIGINFO,
    );
    crate::signals::set(libc::SIGCHLD, on_chld as extern "C" fn(libc::c_int) as usize, 0);
    // SAFETY: the child signals its parent and _exits.
    unsafe {
        let parent = libc::getpid();
        let c = libc::fork();
        if c == 0 {
            libc::kill(parent, libc::SIGUSR2);
            libc::_exit(0);
        }
        wait(c);
        // Process-directed: maybe on libtest's main thread, so maybe not yet.
        let t0 = Instant::now();
        while (INFO_PID.load(Ordering::SeqCst) == 0 || CHLD.load(Ordering::SeqCst) == 0) && t0.elapsed() < Duration::from_secs(2) {
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(INFO_PID.load(Ordering::SeqCst), c, "si_pid");
        assert!(CHLD.load(Ordering::SeqCst) >= 1, "no SIGCHLD");
    }
}

/// Not a test: what spawn_self and child_signals run.
pub fn child_helper() {
    match std::env::var("GUEST_TESTS_HELPER").as_deref() {
        Ok("exit7") => {
            println!("HELPER_RAN");
            std::process::exit(7);
        }
        Ok("abort") => std::process::abort(),
        Ok("sleep") => {
            println!("HELPER_SLEEPING");
            thread::sleep(Duration::from_secs(30));
        }
        _ => {}
    }
}
