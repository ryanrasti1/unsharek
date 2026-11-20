//! Signals: the guest kernel's dispositions, masks, delivery and default actions, and handlers the
//! runtime runs as the program (the kernel series' item 8). Before the runtime ran handlers, a
//! handler was recorded and never run, and a fatal default action was faked as exit 128 + it.
//! The numbers are the checks' of the C program these were (1-10); 11-13, with other processes,
//! are `process`'s.
//!
//! The test runs on a thread of libtest's, so each signal meant for it is sent to it (`raise` is
//! a tgkill of the calling thread, timers are SIGEV_THREAD_ID); a process-directed one (`kill`,
//! `sigqueue`) may run its handler on libtest's main thread, and the test waits for it.

use std::arch::asm;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::{errno, eventually, gettid, pipe, raw_errno};

static COUNT: AtomicI32 = AtomicI32::new(0);
static SIGNO: AtomicI32 = AtomicI32::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);
static PID: AtomicI32 = AtomicI32::new(0);
static UID: AtomicI32 = AtomicI32::new(0);
static VALUE: AtomicI32 = AtomicI32::new(0);
static TID: AtomicI32 = AtomicI32::new(0);
/// In the handler: whether its signal was blocked, and whether uc_sigmask had it.
static BLOCKED: AtomicI32 = AtomicI32::new(-1);
static UC_HAS: AtomicI32 = AtomicI32::new(-1);

extern "C" fn on_sig(s: libc::c_int) {
    COUNT.fetch_add(1, Ordering::SeqCst);
    SIGNO.store(s, Ordering::SeqCst);
    TID.store(gettid(), Ordering::SeqCst);
}

extern "C" fn on_info(s: libc::c_int, si: *mut libc::siginfo_t, uc: *mut libc::c_void) {
    // SAFETY: the kernel's siginfo and ucontext for this delivery; a query of the mask.
    unsafe {
        let si = &*si;
        CODE.store(si.si_code, Ordering::SeqCst);
        // si_pid and si_uid are valid for the codes these tests send (SI_USER, SI_TKILL, SI_QUEUE).
        PID.store(si.si_pid(), Ordering::SeqCst);
        UID.store(si.si_uid() as i32, Ordering::SeqCst);
        if si.si_code == libc::SI_QUEUE {
            VALUE.store(si.si_value().sival_ptr as usize as i32, Ordering::SeqCst);
        }
        let mut now: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut now);
        BLOCKED.store(libc::sigismember(&now, s), Ordering::SeqCst);
        UC_HAS.store(libc::sigismember(&(*(uc as *mut libc::ucontext_t)).uc_sigmask, s), Ordering::SeqCst);
    }
    on_sig(s);
}

pub(crate) fn set(sig: i32, handler: usize, flags: i32) {
    // SAFETY: a zeroed sigaction with a handler of this crate's.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler;
        sa.sa_flags = flags;
        libc::sigemptyset(&mut sa.sa_mask);
        assert_eq!(libc::sigaction(sig, &sa, std::ptr::null_mut()), 0, "sigaction({sig}): {}", errno());
    }
}

fn info_handler() -> usize {
    on_info as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) as usize
}

fn plain_handler() -> usize {
    on_sig as extern "C" fn(libc::c_int) as usize
}

fn raise(sig: i32) {
    // SAFETY: a signal to this thread, with a handler installed.
    assert_eq!(unsafe { libc::raise(sig) }, 0);
}

/// A POSIX timer firing `sig` once at this thread after `ms` (an itimer's SIGALRM is the
/// process's, and might interrupt libtest's main thread instead).
fn thread_timer(sig: i32, ms: i64) -> libc::timer_t {
    // SAFETY: a timer of our own, for this thread.
    unsafe {
        let mut sev: libc::sigevent = std::mem::zeroed();
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = sig;
        sev.sigev_notify_thread_id = gettid();
        let mut timer: libc::timer_t = std::mem::zeroed();
        assert_eq!(libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer), 0, "timer_create: {}", errno());
        let it = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: ms / 1000, tv_nsec: (ms % 1000) * 1_000_000 },
        };
        assert_eq!(libc::timer_settime(timer, 0, &it, std::ptr::null_mut()), 0);
        timer
    }
}

/// 1, 3: a handler, run at raise's return, on this thread; tgkill's siginfo; the signal blocked
/// in the handler and not in its uc_sigmask.
pub fn handler_at_raise() {
    set(libc::SIGUSR1, info_handler(), libc::SA_SIGINFO);
    raise(libc::SIGUSR1);
    assert_eq!(COUNT.load(Ordering::SeqCst), 1, "the handler hadn't run at raise's return");
    assert_eq!(SIGNO.load(Ordering::SeqCst), libc::SIGUSR1);
    assert_eq!(TID.load(Ordering::SeqCst), gettid(), "the handler ran on another thread");
    assert_eq!(CODE.load(Ordering::SeqCst), libc::SI_TKILL);
    // SAFETY: no arguments.
    assert_eq!(PID.load(Ordering::SeqCst), unsafe { libc::getpid() });
    assert_eq!((BLOCKED.load(Ordering::SeqCst), UC_HAS.load(Ordering::SeqCst)), (1, 0), "in the handler: (blocked, in uc_sigmask)");
}

/// 2: blocked, pending until unblocked, then delivered.
pub fn blocked_pending() {
    set(libc::SIGUSR1, plain_handler(), 0);
    // SAFETY: this thread's own mask.
    unsafe {
        let mut m: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut m);
        libc::sigaddset(&mut m, libc::SIGUSR1);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &m, &mut old), 0);
        raise(libc::SIGUSR1);
        let mut pend: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut pend);
        assert_eq!(COUNT.load(Ordering::SeqCst), 0, "a blocked signal was delivered");
        assert_eq!(libc::sigismember(&pend, libc::SIGUSR1), 1, "not pending");
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
    }
    assert_eq!(COUNT.load(Ordering::SeqCst), 1, "not delivered once unblocked");
}

/// 3: kill(getpid()): a process-directed signal, delivered to some thread of the process; its
/// siginfo is kill's (SI_USER, our pid and uid).
pub fn kill_process() {
    set(libc::SIGUSR2, info_handler(), libc::SA_SIGINFO);
    // SAFETY: a signal to ourselves, with a handler installed.
    unsafe { assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR2), 0) };
    eventually("kill(getpid())'s handler", || COUNT.load(Ordering::SeqCst) == 1);
    assert_eq!(CODE.load(Ordering::SeqCst), libc::SI_USER);
    // SAFETY: no arguments.
    unsafe {
        assert_eq!(PID.load(Ordering::SeqCst), libc::getpid());
        assert_eq!(UID.load(Ordering::SeqCst), libc::getuid() as i32);
    }
}

/// 3: sigqueue's siginfo: SI_QUEUE and its value.
pub fn sigqueue_info() {
    set(libc::SIGUSR2, info_handler(), libc::SA_SIGINFO);
    // SAFETY: a signal to ourselves, with a handler installed.
    unsafe {
        let v = libc::sigval { sival_ptr: 42usize as *mut libc::c_void };
        assert_eq!(libc::sigqueue(libc::getpid(), libc::SIGUSR2, v), 0, "sigqueue");
    }
    eventually("sigqueue's handler", || COUNT.load(Ordering::SeqCst) == 1);
    assert_eq!((CODE.load(Ordering::SeqCst), VALUE.load(Ordering::SeqCst)), (libc::SI_QUEUE, 42), "(si_code, value)");
}

/// 5: a sleep interrupted by a signal: EINTR, the time left.
pub fn timer_eintr() {
    set(libc::SIGALRM, plain_handler(), 0);
    let timer = thread_timer(libc::SIGALRM, 20);
    let ts = libc::timespec { tv_sec: 5, tv_nsec: 0 };
    let mut left = libc::timespec { tv_sec: 0, tv_nsec: 0 };
    let t0 = Instant::now();
    // SAFETY: a plain nanosleep.
    let r = unsafe { libc::nanosleep(&ts, &mut left) };
    let e = raw_errno();
    let took = t0.elapsed();
    assert_eq!((r, e), (-1, libc::EINTR), "nanosleep");
    assert_eq!(COUNT.load(Ordering::SeqCst), 1);
    assert_eq!(TID.load(Ordering::SeqCst), gettid());
    assert!(took < Duration::from_secs(3) && left.tv_sec >= 3, "took {took:?}, {}s left", left.tv_sec);
    // SAFETY: our timer.
    unsafe { libc::timer_delete(timer) };
}

static HANDLER_SP: AtomicUsize = AtomicUsize::new(0);
extern "C" fn on_stack(_: libc::c_int) {
    let here = 0u8;
    HANDLER_SP.store(std::hint::black_box(&here) as *const u8 as usize, Ordering::SeqCst);
}

/// 4: SA_ONSTACK: the handler runs on the alternate stack; without it, on the thread's.
pub fn altstack() {
    let alt = vec![0u8; 64 << 10].leak();
    let range = alt.as_ptr() as usize..alt.as_ptr() as usize + alt.len();
    // SAFETY: a stack of ours for the rest of the process's life (leaked).
    unsafe {
        let ss = libc::stack_t { ss_sp: alt.as_mut_ptr().cast(), ss_flags: 0, ss_size: alt.len() };
        assert_eq!(libc::sigaltstack(&ss, std::ptr::null_mut()), 0, "sigaltstack");
    }
    let handler = on_stack as extern "C" fn(libc::c_int) as usize;
    set(libc::SIGURG, handler, libc::SA_ONSTACK);
    raise(libc::SIGURG);
    let sp = HANDLER_SP.load(Ordering::SeqCst);
    assert!(range.contains(&sp), "the SA_ONSTACK handler ran at {sp:#x}, not on {range:x?}");
    set(libc::SIGURG, handler, 0);
    raise(libc::SIGURG);
    let sp = HANDLER_SP.load(Ordering::SeqCst);
    assert!(!range.contains(&sp), "a handler without SA_ONSTACK ran on the alternate stack");
    // SAFETY: an out-struct.
    let cur = unsafe {
        let mut cur: libc::stack_t = std::mem::zeroed();
        assert_eq!(libc::sigaltstack(std::ptr::null(), &mut cur), 0);
        cur
    };
    assert!(cur.ss_sp as usize == range.start && cur.ss_flags & libc::SS_ONSTACK == 0, "the alternate stack after");
}

static RESTART_W: AtomicI32 = AtomicI32::new(-1);
/// The handler makes the byte the interrupted read then gets.
extern "C" fn on_restart(_: libc::c_int) {
    // SAFETY: a one-byte write to our pipe.
    if unsafe { libc::write(RESTART_W.load(Ordering::SeqCst), b"r".as_ptr().cast(), 1) } != 1 {
        // SAFETY: ends the process at once.
        unsafe { libc::_exit(9) };
    }
}

/// 6: SA_RESTART: a pipe read the handler's signal interrupted runs again (and gets the byte the
/// handler wrote); without it, EINTR.
pub fn sa_restart() {
    let (r, w) = pipe();
    RESTART_W.store(w, Ordering::SeqCst);
    let read = || {
        let mut c = 0u8;
        // SAFETY: a one-byte read into a local.
        let n = unsafe { libc::read(r, (&raw mut c).cast(), 1) };
        (n, if n < 0 { raw_errno() } else { c as i32 })
    };
    set(libc::SIGALRM, on_restart as extern "C" fn(libc::c_int) as usize, libc::SA_RESTART);
    let t = thread_timer(libc::SIGALRM, 20);
    assert_eq!(read(), (1, b'r' as i32), "the SA_RESTART read");
    set(libc::SIGALRM, plain_handler(), 0);
    let t2 = thread_timer(libc::SIGALRM, 20);
    assert_eq!(read(), (-1, libc::EINTR), "the read without SA_RESTART");
    // SAFETY: our timers.
    unsafe {
        libc::timer_delete(t);
        libc::timer_delete(t2);
    }
}

unsafe extern "C" {
    /// crates/guest-tests/c/longjmp.c.
    fn guest_tests_longjmp_out(n: libc::c_int) -> libc::c_int;
}

/// 7: siglongjmp out of a handler, 50 times (no rt_sigreturn: the kernel's signal frame is
/// abandoned), then syscalls still work and siglongjmp(jb, 1) restored the mask. In C
/// (c/longjmp.c): Rust can't sigsetjmp.
pub fn longjmp_out() {
    // SAFETY: the C function installs its handler and keeps to its own frames.
    let r = unsafe { guest_tests_longjmp_out(50) };
    assert_eq!(r, 50, "siglongjmps out of the handler");
    // SAFETY: syscalls; a query of the mask.
    unsafe {
        assert!(libc::getppid() >= 0 && libc::write(1, c"".as_ptr().cast(), 0) == 0, "syscalls after the jumps");
        let mut m: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut m);
        assert_eq!(libc::sigismember(&m, libc::SIGUSR1), 0, "siglongjmp(jb, 1) kept SIGUSR1 blocked");
    }
}

static NESTED: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_outer(_: libc::c_int) {
    // Delivered inside this handler, at raise's return.
    // SAFETY: a signal to this thread.
    unsafe { libc::raise(libc::SIGUSR2) };
    NESTED.store(NESTED.load(Ordering::SeqCst) * 10 + 1, Ordering::SeqCst);
}
extern "C" fn on_inner(_: libc::c_int) {
    NESTED.store(NESTED.load(Ordering::SeqCst) * 10 + 2, Ordering::SeqCst);
}
/// A handler that clobbers the vector registers: the interrupted code's must come back.
extern "C" fn on_clobber(_: libc::c_int) {
    // SAFETY: registers only.
    unsafe { asm!("pcmpeqd xmm8, xmm8", "xorps xmm9, xmm9", out("xmm8") _, out("xmm9") _) };
}

/// 8: a signal delivered inside a handler (raise there), and the vector registers of the
/// interrupted code restored after a handler clobbers them.
pub fn nested_and_vector_regs() {
    set(libc::SIGUSR1, on_outer as extern "C" fn(libc::c_int) as usize, libc::SA_NODEFER);
    set(libc::SIGUSR2, on_inner as extern "C" fn(libc::c_int) as usize, 0);
    raise(libc::SIGUSR1);
    assert_eq!(NESTED.load(Ordering::SeqCst), 21, "the inner handler ran inside the outer");
    set(libc::SIGUSR1, on_clobber as extern "C" fn(libc::c_int) as usize, 0);
    let want = 0x0123_4567_89ab_cdefu64;
    let (got, ret): (u64, i64);
    // SAFETY: tgkill to this thread, whose handler clobbers xmm8 and xmm9 (declared clobbered).
    unsafe {
        asm!(
            "movq xmm8, {w}",
            "syscall",
            "movq {g}, xmm8",
            w = in(reg) want,
            g = lateout(reg) got,
            inlateout("rax") libc::SYS_tgkill => ret,
            in("rdi") libc::getpid() as i64,
            in("rsi") gettid() as i64,
            in("rdx") libc::SIGUSR1 as i64,
            out("rcx") _,
            out("r11") _,
            out("xmm8") _,
            out("xmm9") _,
        );
    }
    assert_eq!(ret, 0, "tgkill");
    assert_eq!(got, want, "xmm8 after a handler: {got:#x}");
}

/// 9: a signal for a thread blocked in a futex wait (a Condvar's) and for one in a pipe read: the
/// handler runs on that thread, the read is EINTR, the condition wait carries on.
pub fn thread_in_waits() {
    use std::os::unix::thread::JoinHandleExt;
    static TIDS: [AtomicI32; 2] = [AtomicI32::new(0), AtomicI32::new(0)];
    extern "C" fn on_thread(_: libc::c_int) {
        let me = gettid();
        for t in &TIDS {
            if t.load(Ordering::SeqCst) == me {
                COUNT.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
    set(libc::SIGUSR1, on_thread as extern "C" fn(libc::c_int) as usize, 0);
    let state = Arc::new((Mutex::new(false), Condvar::new()));
    let s = state.clone();
    let waiter = thread::spawn(move || {
        TIDS[0].store(gettid(), Ordering::SeqCst);
        let (m, cv) = &*s;
        let _g = cv.wait_while(m.lock().unwrap(), |go| !*go).unwrap();
    });
    let (r, w) = pipe();
    let reader = thread::spawn(move || {
        TIDS[1].store(gettid(), Ordering::SeqCst);
        let mut c = 0u8;
        // SAFETY: a one-byte read into a local.
        let n = unsafe { libc::read(r, (&raw mut c).cast(), 1) };
        (n, raw_errno())
    });
    thread::sleep(Duration::from_millis(20));
    // SAFETY: live threads of ours (joined below).
    unsafe {
        assert_eq!(libc::pthread_kill(waiter.as_pthread_t(), libc::SIGUSR1), 0);
        assert_eq!(libc::pthread_kill(reader.as_pthread_t(), libc::SIGUSR1), 0);
    }
    eventually("both threads' handlers", || COUNT.load(Ordering::SeqCst) == 2);
    assert_eq!(reader.join().unwrap(), (-1, libc::EINTR), "the pipe reader's read");
    *state.0.lock().unwrap() = true;
    state.1.notify_all();
    waiter.join().unwrap();
    // SAFETY: our pipe.
    unsafe {
        libc::close(r);
        libc::close(w);
    }
}

static GO_COUNT: [AtomicI32; 65] = [const { AtomicI32::new(0) }; 65];
extern "C" fn go_handler(s: libc::c_int, _: *mut libc::siginfo_t, _: *mut libc::c_void) {
    GO_COUNT[s as usize].fetch_add(1, Ordering::SeqCst);
}

/// 10: a Go-style runtime: a handler for every signal (SIGSYS among them: the host's SIGSYS
/// handler is the runtime's), SA_SIGINFO | SA_ONSTACK | SA_RESTART, all blocked in it; then the
/// sandbox still serves calls and threads, and handlers run.
pub fn every_signal() {
    let sigs: Vec<i32> = (1..65).filter(|&s| s != libc::SIGKILL && s != libc::SIGSTOP && !(32..libc::SIGRTMIN()).contains(&s)).collect();
    // SAFETY: a handler that only counts, for each signal; then the defaults back.
    unsafe {
        let mut g: libc::sigaction = std::mem::zeroed();
        g.sa_sigaction = go_handler as extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) as usize;
        g.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK | libc::SA_RESTART;
        libc::sigfillset(&mut g.sa_mask);
        for &s in &sigs {
            assert_eq!(libc::sigaction(s, &g, std::ptr::null_mut()), 0, "sigaction({s}) for every signal");
        }
        for _ in 0..100 {
            assert!(libc::getppid() >= 0 && libc::write(1, c"".as_ptr().cast(), 0) == 0, "syscalls under every handler");
        }
    }
    let (r, w) = pipe();
    let t = thread::spawn(move || {
        let mut c = 0u8;
        // SAFETY: a one-byte read into a local.
        unsafe { libc::read(r, (&raw mut c).cast(), 1) }
    });
    // SAFETY: a one-byte write to our pipe.
    assert_eq!(unsafe { libc::write(w, b"x".as_ptr().cast(), 1) }, 1);
    assert_eq!(t.join().unwrap(), 1, "a thread's read under every handler");
    for s in [libc::SIGURG, libc::SIGWINCH, libc::SIGUSR1, libc::SIGSYS, libc::SIGRTMIN() + 1] {
        raise(s);
        assert_eq!(GO_COUNT[s as usize].load(Ordering::SeqCst), 1, "the handler for {s}");
    }
    for &s in &sigs {
        // SAFETY: the default disposition back.
        unsafe { libc::signal(s, libc::SIG_DFL) };
    }
    println!("a handler for each of {} signals; calls, threads and delivery work", sigs.len());
}

/// A program may read and set SIGSYS's disposition, and its syscalls are still served afterwards:
/// the host's SIGSYS handler is the runtime's, and the program's is only recorded. (capnix tier A:
/// Go installs a handler for every signal and throws "sigaction failed" on an error; Node reads
/// every disposition at startup and asserts.)
pub fn sigsys() {
    extern "C" fn on_sigsys(_: libc::c_int) {}
    let h = on_sigsys as extern "C" fn(libc::c_int) as usize;
    // SAFETY: sigaction with out-structs; syscalls.
    unsafe {
        let mut old: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(libc::SIGSYS, std::ptr::null(), &mut old), 0, "reading SIGSYS's disposition");
        set(libc::SIGSYS, h, libc::SA_ONSTACK | libc::SA_SIGINFO);
        assert_eq!(libc::sigaction(libc::SIGSYS, std::ptr::null(), &mut old), 0);
        assert_eq!(old.sa_sigaction, h, "SIGSYS's disposition reads back as set");
        assert!(libc::getppid() >= 0 && libc::write(1, c"".as_ptr().cast(), 0) == 0, "syscalls after the program's SIGSYS handler");
    }
}
