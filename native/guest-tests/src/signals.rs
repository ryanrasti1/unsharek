//! Signals (a few of signals.c's checks). The test runs on a thread of libtest's, so each signal
//! meant for it is sent to it (`raise` is a tgkill of the calling thread); `kill_process` sends
//! one to the process and accepts either thread.

use std::sync::atomic::{AtomicI32, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use crate::{errno, gettid, pipe};

static COUNT: AtomicI32 = AtomicI32::new(0);
static SIGNO: AtomicI32 = AtomicI32::new(0);
static CODE: AtomicI32 = AtomicI32::new(0);
static PID: AtomicI32 = AtomicI32::new(0);
static TID: AtomicI32 = AtomicI32::new(0);

extern "C" fn on_sig(s: libc::c_int) {
    COUNT.fetch_add(1, Ordering::SeqCst);
    SIGNO.store(s, Ordering::SeqCst);
    TID.store(gettid(), Ordering::SeqCst);
}

extern "C" fn on_info(s: libc::c_int, si: *mut libc::siginfo_t, _uc: *mut libc::c_void) {
    // SAFETY: the kernel's siginfo for this delivery.
    let si = unsafe { &*si };
    CODE.store(si.si_code, Ordering::SeqCst);
    // SAFETY: si_pid is valid for the codes these tests send (SI_USER, SI_TKILL, SI_QUEUE).
    PID.store(unsafe { si.si_pid() }, Ordering::SeqCst);
    on_sig(s);
}

pub(crate) fn set(sig: i32, handler: usize, flags: i32) {
    // SAFETY: a zeroed sigaction with a handler of this module's, which only touches atomics.
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

/// A handler, run at raise's return, on this thread; tgkill's siginfo.
pub fn handler_at_raise() {
    set(libc::SIGUSR1, info_handler(), libc::SA_SIGINFO);
    // SAFETY: signals to ourselves, with a handler installed.
    unsafe {
        assert_eq!(libc::raise(libc::SIGUSR1), 0);
        assert_eq!(COUNT.load(Ordering::SeqCst), 1, "the handler hadn't run at raise's return");
        assert_eq!(SIGNO.load(Ordering::SeqCst), libc::SIGUSR1);
        assert_eq!(TID.load(Ordering::SeqCst), gettid(), "the handler ran on another thread");
        assert_eq!(CODE.load(Ordering::SeqCst), libc::SI_TKILL);
        assert_eq!(PID.load(Ordering::SeqCst), libc::getpid());
    }
}

/// Blocked: pending until unblocked, then delivered.
pub fn blocked_pending() {
    set(libc::SIGUSR1, plain_handler(), 0);
    // SAFETY: this thread's own mask, signals to itself.
    unsafe {
        let mut m: libc::sigset_t = std::mem::zeroed();
        let mut old: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut m);
        libc::sigaddset(&mut m, libc::SIGUSR1);
        assert_eq!(libc::pthread_sigmask(libc::SIG_BLOCK, &m, &mut old), 0);
        libc::raise(libc::SIGUSR1);
        let mut pend: libc::sigset_t = std::mem::zeroed();
        libc::sigpending(&mut pend);
        assert_eq!(COUNT.load(Ordering::SeqCst), 0, "a blocked signal was delivered");
        assert_eq!(libc::sigismember(&pend, libc::SIGUSR1), 1, "not pending");
        libc::pthread_sigmask(libc::SIG_SETMASK, &old, std::ptr::null_mut());
        assert_eq!(COUNT.load(Ordering::SeqCst), 1, "not delivered once unblocked");
    }
}

/// kill(getpid()): a process-directed signal, delivered to some thread of the process (libtest's
/// main thread or this one); its siginfo is kill's.
pub fn kill_process() {
    set(libc::SIGUSR2, info_handler(), libc::SA_SIGINFO);
    // SAFETY: a signal to ourselves, with a handler installed.
    unsafe { assert_eq!(libc::kill(libc::getpid(), libc::SIGUSR2), 0) };
    let start = Instant::now();
    while COUNT.load(Ordering::SeqCst) == 0 && start.elapsed() < Duration::from_secs(2) {
        thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(COUNT.load(Ordering::SeqCst), 1, "not delivered in 2 s");
    assert_eq!(CODE.load(Ordering::SeqCst), libc::SI_USER);
    // SAFETY: no arguments.
    assert_eq!(PID.load(Ordering::SeqCst), unsafe { libc::getpid() });
    let tid = TID.load(Ordering::SeqCst);
    // (Which thread is Linux's choice: the main thread first if it doesn't block it.)
    println!("kill(getpid()) ran its handler on tid {tid}; the test thread is {}, the main {}", gettid(), unsafe {
        libc::getpid()
    });
}

/// A sleep interrupted by a signal: EINTR, the time left. The signal is a POSIX timer's for this
/// thread (SIGEV_THREAD_ID): signals.c's itimer is process-directed and here would interrupt
/// libtest's main thread instead.
pub fn timer_eintr() {
    set(libc::SIGALRM, plain_handler(), 0);
    // SAFETY: a timer of our own, its signal handled; a plain nanosleep.
    unsafe {
        let mut sev: libc::sigevent = std::mem::zeroed();
        sev.sigev_notify = libc::SIGEV_THREAD_ID;
        sev.sigev_signo = libc::SIGALRM;
        sev.sigev_notify_thread_id = gettid();
        let mut timer: libc::timer_t = std::mem::zeroed();
        assert_eq!(libc::timer_create(libc::CLOCK_MONOTONIC, &mut sev, &mut timer), 0, "timer_create: {}", errno());
        let it = libc::itimerspec {
            it_interval: libc::timespec { tv_sec: 0, tv_nsec: 0 },
            it_value: libc::timespec { tv_sec: 0, tv_nsec: 20_000_000 },
        };
        assert_eq!(libc::timer_settime(timer, 0, &it, std::ptr::null_mut()), 0);
        let ts = libc::timespec { tv_sec: 5, tv_nsec: 0 };
        let mut left = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        let t0 = Instant::now();
        let r = libc::nanosleep(&ts, &mut left);
        let e = errno();
        let took = t0.elapsed();
        assert_eq!((r, e.raw_os_error()), (-1, Some(libc::EINTR)), "nanosleep");
        assert_eq!(COUNT.load(Ordering::SeqCst), 1);
        assert_eq!(TID.load(Ordering::SeqCst), gettid());
        assert!(took < Duration::from_secs(3) && left.tv_sec >= 3, "took {took:?}, {}s left", left.tv_sec);
        libc::timer_delete(timer);
    }
}

/// A signal for a thread blocked in a pipe read: the handler runs on that thread, the read is
/// EINTR (no SA_RESTART).
pub fn pthread_kill_read() {
    use std::os::unix::thread::JoinHandleExt;
    set(libc::SIGUSR1, plain_handler(), 0);
    let (r, w) = pipe();
    let t = thread::spawn(move || {
        let mut c = 0u8;
        // SAFETY: a one-byte read into a local.
        let n = unsafe { libc::read(r, (&raw mut c).cast(), 1) };
        (n, errno().raw_os_error(), gettid())
    });
    thread::sleep(Duration::from_millis(20));
    // SAFETY: a live thread of ours (joined below).
    assert_eq!(unsafe { libc::pthread_kill(t.as_pthread_t(), libc::SIGUSR1) }, 0);
    let (n, e, tid) = t.join().unwrap();
    assert_eq!((n, e), (-1, Some(libc::EINTR)), "the read");
    assert_eq!(TID.load(Ordering::SeqCst), tid, "the handler ran on another thread");
    // SAFETY: closing our own pipe.
    unsafe {
        libc::close(r);
        libc::close(w);
    }
}
