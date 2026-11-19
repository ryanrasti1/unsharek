//! Processes: natively and in fork mode only. Fork mode: a guest fork is a host fork, the
//! processes share one guest kernel: pipes between processes, wait statuses, separate memory,
//! signals between processes (`signals`' 11-13), threads in a forked process, and std's
//! process::Command, which spawns with clone(CLONE_VM | CLONE_VFORK) through posix_spawn.
//!
//! A forked child of a test is a copy of a multi-threaded process (libtest's main thread is in
//! the parent only), so it keeps to async-signal-safe calls (or to what libtest's waiting main
//! thread can't hold a lock of) and `_exit`s.

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

/// 11: SA_SIGINFO from another process, and SIGCHLD when it exits.
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

/// A child that outlives a while: the parent blocks in read until it writes, then sees EOF.
pub fn fork_late_read() {
    let (r, w) = pipe();
    // SAFETY: the child sleeps, writes and _exits.
    unsafe {
        let c = libc::fork();
        if c == 0 {
            libc::close(r);
            libc::usleep(50_000);
            libc::_exit((libc::write(w, b"late".as_ptr().cast(), 4) != 4) as i32);
        }
        libc::close(w);
        let mut b = [0u8; 8];
        assert_eq!(libc::read(r, b.as_mut_ptr().cast(), 4), 4, "the late read");
        assert_eq!(&b[..4], b"late");
        assert_eq!(libc::read(r, b.as_mut_ptr().cast(), 4), 0, "EOF after the child's exit");
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "status {st:#x}");
    }
}

/// A default action ends a child: SIGTERM while it waits in pause, SIGINT while it sleeps; its
/// parent sees the signal in wait (12, 13).
pub fn child_killed() {
    for (sig, sleeps) in [(libc::SIGTERM, false), (libc::SIGINT, true)] {
        // SAFETY: the child waits until killed.
        unsafe {
            let c = libc::fork();
            if c == 0 {
                if sleeps {
                    libc::sleep(30);
                    libc::_exit(0);
                }
                loop {
                    libc::pause();
                }
            }
            libc::usleep(20_000);
            libc::kill(c, sig);
            let st = wait(c);
            assert!(libc::WIFSIGNALED(st) && libc::WTERMSIG(st) == sig, "wanted death by {sig}: status {st:#x}");
        }
    }
}

/// Threads in a forked process (fork mode, src/fork.c "threads"): a child makes 4 threads that
/// share a counter under a mutex and wait on a condition variable, joins them, checks their tids
/// are its process's (getpid, distinct gettid, tgkill to its main thread), and a second child
/// exits with a thread still waiting (exit_group reaches it). Threads made and joined one after
/// another return their values (a join waits for each, so the next reuses a finished thread's
/// stack).
pub fn forkthreads() {
    fn one_after_another() -> Result<(), String> {
        for i in 1..=4u64 {
            let r = thread::spawn(move || i).join().map_err(|_| "a thread panicked")?;
            if r != i {
                return Err(format!("thread {i} joined with {r}"));
            }
        }
        Ok(())
    }
    static GOT_USR1: AtomicI32 = AtomicI32::new(0);
    extern "C" fn on_usr1(_: libc::c_int) {
        GOT_USR1.store(1, Ordering::SeqCst);
    }
    fn child_threads() -> Result<(), String> {
        use std::sync::{Arc, Condvar, Mutex};
        one_after_another().map_err(|e| format!("in the forked process: {e}"))?;
        let state = Arc::new((Mutex::new((false, 0u32)), Condvar::new()));
        // SAFETY: no arguments.
        let pid = unsafe { libc::getpid() };
        let ts: Vec<_> = (0..4)
            .map(|_| {
                let s = state.clone();
                thread::spawn(move || {
                    let (m, cv) = &*s;
                    drop(cv.wait_while(m.lock().unwrap(), |(go, _)| !*go).unwrap());
                    for k in 0..1000 {
                        m.lock().unwrap().1 += 1;
                        if k % 100 == 0 {
                            thread::yield_now();
                        }
                    }
                    // SAFETY: no arguments.
                    (unsafe { libc::getpid() }, crate::gettid())
                })
            })
            .collect();
        state.0.lock().unwrap().0 = true;
        state.1.notify_all();
        let mut tids = vec![crate::gettid()];
        for t in ts {
            let (p, tid) = t.join().map_err(|_| "a worker panicked")?;
            if p != pid {
                return Err(format!("a worker saw pid {p}, not {pid}"));
            }
            if tids.contains(&tid) {
                return Err(format!("tids not distinct: {tid} in {tids:?}"));
            }
            tids.push(tid);
        }
        let count = state.0.lock().unwrap().1;
        if count != 4000 {
            return Err(format!("count {count}, not 4000"));
        }
        // A signal to one thread of this process, by its tid.
        crate::signals::set(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as usize, 0);
        // SAFETY: a signal to this thread, with a handler installed.
        let r = unsafe { libc::syscall(libc::SYS_tgkill, pid, tids[0], libc::SIGUSR1) };
        if r != 0 || GOT_USR1.load(Ordering::SeqCst) == 0 {
            return Err("tgkill to the forked process's main thread".into());
        }
        Ok(())
    }
    one_after_another().unwrap();
    // SAFETY: the children run threads (a copy of a multi-threaded process: libtest's waiting main
    // thread holds no lock they need) and _exit.
    unsafe {
        let c = libc::fork();
        if c == 0 {
            let r = child_threads();
            if let Err(why) = &r {
                println!("FAIL: {why}");
            }
            libc::_exit(r.is_err() as i32);
        }
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "the threads child: status {st:#x}");
        let c = libc::fork();
        if c == 0 {
            // exit_group with a thread waiting.
            thread::spawn(|| {
                loop {
                    thread::park();
                }
            });
            libc::usleep(10_000);
            libc::_exit(7);
        }
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 7, "the exit child: status {st:#x}");
    }
}

/// A forked child's randomness is its own: parent and child each read getrandom after the fork
/// and must differ. (A fork copies the guest kernel's RNG state; without a reseed per child, every
/// child of one template sees the same stream.)
pub fn fork_rng() {
    let (r, w) = pipe();
    // SAFETY: the child reads getrandom, writes it and _exits.
    unsafe {
        let c = libc::fork();
        assert!(c >= 0);
        let mut mine = [0u8; 16];
        assert_eq!(libc::getrandom(mine.as_mut_ptr().cast(), 16, 0), 16, "getrandom");
        if c == 0 {
            libc::_exit((libc::write(w, mine.as_ptr().cast(), 16) != 16) as i32);
        }
        let mut theirs = [0u8; 16];
        assert_eq!(libc::read(r, theirs.as_mut_ptr().cast(), 16), 16, "the child's bytes");
        let st = wait(c);
        assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "status {st:#x}");
        assert_ne!(mine, theirs, "parent and child read the same random bytes");
    }
}

const SETTID_ROUNDS: usize = 50;

/// CLONE_CHILD_SETTID is written once (fork mode). Linux writes a fork child's tid at that address
/// at the child's first schedule; LKL's host tasks go through schedule_tail() again at every switch
/// back to them, so the tid used to be written there for the task's whole life: after an exec, into
/// the new program's memory (capnix tier A: a forked bash's thread pointer area became the exec'd
/// program's ld.so heap, and the tid landed in a version table: "undefined symbol:
/// __isoc23_strtoul, version GLIBC_2.38" on a pipeline's C++ program). Ported from capnix.
///
/// The parent forks with CLONE_CHILD_SETTID at an address A of its own memory; the child execs this
/// binary (`child_helper`, `settid:A:rd:wr`), which maps A again (zeros), then ping-pongs with the
/// parent over pipes, so that every one of its syscalls enters the kernel with another task
/// current. A must still be 0 after.
pub fn settid() {
    use std::ffi::CString;
    // Far into a large mapping: in the sandbox the exec'd child's arena starts over, and its own
    // stack and ld.so's heap are at the start.
    let len = 64usize << 20;
    // SAFETY: a fresh mapping of our own, never unmapped (the address must stay ours).
    let a = unsafe {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        libc::mmap(std::ptr::null_mut(), len, libc::PROT_READ | libc::PROT_WRITE, flags, -1, 0)
    };
    assert_ne!(a, libc::MAP_FAILED);
    let tid = (a as usize + len - 4096 + 400) as *mut i32;
    let ((up_r, up_w), (down_r, down_w)) = (pipe(), pipe());
    // Everything the child needs, made before the clone: it only execs.
    let exe = CString::new(std::env::current_exe().unwrap().into_os_string().into_encoded_bytes()).unwrap();
    let args: Vec<CString> =
        ["--exact", "process::child_helper", "--ignored", "--nocapture"].iter().map(|a| CString::new(*a).unwrap()).collect();
    let mut argv: Vec<*const libc::c_char> = vec![exe.as_ptr()];
    argv.extend(args.iter().map(|a| a.as_ptr()));
    argv.push(std::ptr::null());
    let env = CString::new(format!("GUEST_TESTS_HELPER=settid:{:x}:{down_r}:{up_w}", tid as usize)).unwrap();
    let envp: [*const libc::c_char; 2] = [env.as_ptr(), std::ptr::null()];
    // SAFETY: a plain fork with the tid at our own address (glibc's fork puts it in its thread
    // pointer); the child only execs, or _exits.
    let pid = unsafe { libc::syscall(libc::SYS_clone, libc::CLONE_CHILD_SETTID | libc::SIGCHLD, 0, 0, tid, 0) };
    if pid == 0 {
        // SAFETY: as above.
        unsafe {
            libc::execve(exe.as_ptr(), argv.as_ptr(), envp.as_ptr());
            libc::_exit(3);
        }
    }
    assert!(pid > 0, "clone: {}", crate::errno());
    // SAFETY: our pipes, one-byte buffers.
    unsafe {
        libc::close(up_w); // (a child that could not exec ends the rounds: EOF)
        libc::close(down_r);
        let mut c = 0u8;
        for _ in 0..SETTID_ROUNDS {
            if libc::read(up_r, (&raw mut c).cast(), 1) != 1 || libc::write(down_w, (&raw const c).cast(), 1) != 1 {
                break;
            }
        }
    }
    let st = wait(pid as i32);
    assert!(
        libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0,
        "the exec'd child: status {st:#x} (exit 1: the tid was written after the exec)"
    );
}

/// settid's exec'd child: A mapped again, the rounds, A still 0.
fn settid_child(spec: &str) {
    let v: Vec<&str> = spec.split(':').collect();
    let a = usize::from_str_radix(v[0], 16).unwrap();
    let (rd, wr): (i32, i32) = (v[1].parse().unwrap(), v[2].parse().unwrap());
    // SAFETY: a fresh mapping at A's page, which must not be in use (NOREPLACE says so); then
    // one-byte pipe transfers.
    unsafe {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE;
        let p = libc::mmap((a & !4095) as *mut libc::c_void, 4096, libc::PROT_READ | libc::PROT_WRITE, flags, -1, 0);
        assert_eq!(p as usize, a & !4095, "mapping the old CLONE_CHILD_SETTID page again: {}", crate::errno());
        let w = a as *mut i32;
        w.write_volatile(0);
        let mut c = 0u8;
        for _ in 0..SETTID_ROUNDS {
            assert!(libc::write(wr, (&raw const c).cast(), 1) == 1 && libc::read(rd, (&raw mut c).cast(), 1) == 1, "a round");
        }
        let got = w.read_volatile();
        if got != 0 {
            println!("SETTID_FAIL: {got} written at the old CLONE_CHILD_SETTID address after the exec");
            libc::_exit(1);
        }
    }
}

/// Not a test: what spawn_self, child_signals and settid run.
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
        Ok(s) if s.starts_with("settid:") => settid_child(&s["settid:".len()..]),
        _ => {}
    }
}
