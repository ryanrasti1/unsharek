//! Threads and futexes, and std's own synchronization.

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Barrier, Condvar, Mutex, mpsc};
use std::thread;
use std::time::Duration;

use crate::pipe;

/// Threads share their process's fd table: a thread waits on the test thread's epoll fd, and the
/// test thread reads a pipe the thread made.
pub fn thread_fds() {
    // SAFETY: plain fd calls on fds of this test's own.
    unsafe {
        let ep = libc::epoll_create1(0);
        assert!(ep >= 0);
        let (wr, ww) = pipe();
        let mut ev = libc::epoll_event { events: libc::EPOLLIN as u32, u64: wr as u64 };
        assert_eq!(libc::epoll_ctl(ep, libc::EPOLL_CTL_ADD, wr, &mut ev), 0);
        let t = thread::spawn(move || {
            let mut ev = libc::epoll_event { events: 0, u64: 0 };
            let n = libc::epoll_wait(ep, &mut ev, 1, 2000);
            assert!(n == 1 && ev.u64 == wr as u64, "epoll_wait {n} on the test thread's epoll fd");
            let (mr, mw) = pipe();
            assert_eq!(libc::write(mw, b"t".as_ptr().cast(), 1), 1);
            mr
        });
        thread::sleep(Duration::from_millis(10));
        assert_eq!(libc::write(ww, b"m".as_ptr().cast(), 1), 1);
        let mr = t.join().unwrap();
        let mut b = 0u8;
        assert_eq!(libc::read(mr, (&raw mut b).cast(), 1), 1);
        assert_eq!(b, b't');
    }
}

const N: usize = 32;
static WORDS: [AtomicU32; N] = [const { AtomicU32::new(0) }; N];
static WAITING: AtomicU32 = AtomicU32::new(0);

fn futex(w: &AtomicU32, op: i32, v: u32) -> i64 {
    // SAFETY: a futex call on a word of ours, no timeout.
    unsafe { libc::syscall(libc::SYS_futex, w.as_ptr(), op | libc::FUTEX_PRIVATE_FLAG, v, 0usize, 0usize, 0) }
}

/// FUTEX_WAKE wakes a waiter on that address, not another one waiting at the same time: 32 threads
/// on 32 adjacent words, each word woken on its own and its thread must finish (else a hang).
pub fn futex_wake() {
    let ts: Vec<_> = (0..N)
        .map(|i| {
            thread::spawn(move || {
                WAITING.fetch_add(1, Ordering::SeqCst);
                while WORDS[i].load(Ordering::SeqCst) == 0 {
                    futex(&WORDS[i], libc::FUTEX_WAIT, 0);
                }
            })
        })
        .collect();
    while WAITING.load(Ordering::SeqCst) < N as u32 {
        thread::sleep(Duration::from_millis(1));
    }
    thread::sleep(Duration::from_millis(20));
    for (i, t) in ts.into_iter().enumerate().rev() {
        WORDS[i].store(1, Ordering::SeqCst);
        futex(&WORDS[i], libc::FUTEX_WAKE, 1);
        t.join().unwrap();
    }
}

/// std's channels, mutex, condvar and barrier across eight threads.
pub fn std_sync() {
    let (tx, rx) = mpsc::channel();
    let barrier = Arc::new(Barrier::new(8));
    let state = Arc::new((Mutex::new(0), Condvar::new()));
    thread::scope(|s| {
        for i in 0..8 {
            let (tx, barrier, state) = (tx.clone(), barrier.clone(), state.clone());
            s.spawn(move || {
                barrier.wait();
                let (m, cv) = &*state;
                *m.lock().unwrap() += 1;
                cv.notify_all();
                tx.send(i).unwrap();
            });
        }
        let (m, cv) = &*state;
        let g = cv.wait_timeout_while(m.lock().unwrap(), Duration::from_secs(3), |n| *n < 8).unwrap();
        assert_eq!(*g.0, 8, "timed out: {}", g.1.timed_out());
    });
    drop(tx);
    let mut got: Vec<i32> = rx.iter().collect();
    got.sort();
    assert_eq!(got, (0..8).collect::<Vec<_>>());
}

/// A futex wait with a timeout, nobody waking it: ETIMEDOUT after the time (relative, FUTEX_WAIT;
/// absolute on CLOCK_MONOTONIC, FUTEX_WAIT_BITSET, std's Condvar::wait_timeout's call).
pub fn futex_timeout() {
    let w = AtomicU32::new(0);
    // Three in a row, all reported: whether an early return is the first wait's only.
    let tries: Vec<_> = (0..3)
        .map(|_| {
            let t0 = std::time::Instant::now();
            let rel = libc::timespec { tv_sec: 0, tv_nsec: 60_000_000 };
            // SAFETY: a futex wait on a local word, with a timeout.
            let r = unsafe {
                libc::syscall(libc::SYS_futex, w.as_ptr(), libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, 0, &rel, 0usize, 0)
            };
            (r, crate::errno().raw_os_error().unwrap_or(0), t0.elapsed())
        })
        .collect();
    for &(r, e, took) in &tries {
        assert!(
            r == -1 && e == libc::ETIMEDOUT && took >= Duration::from_millis(60),
            "FUTEX_WAIT for 60 ms, nobody waking it: (return, errno, after) {tries:?}"
        );
    }

    // SAFETY: as above, with an absolute deadline.
    let (r, e, took) = unsafe {
        let mut now = std::mem::zeroed::<libc::timespec>();
        libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now);
        let mut abs = now;
        abs.tv_nsec += 60_000_000;
        if abs.tv_nsec >= 1_000_000_000 {
            abs.tv_sec += 1;
            abs.tv_nsec -= 1_000_000_000;
        }
        let t0 = std::time::Instant::now();
        let r = libc::syscall(
            libc::SYS_futex,
            w.as_ptr(),
            libc::FUTEX_WAIT_BITSET | libc::FUTEX_PRIVATE_FLAG,
            0,
            &abs,
            0usize,
            !0u32,
        );
        (r, crate::errno(), t0.elapsed())
    };
    assert_eq!((r, e.raw_os_error()), (-1, Some(libc::ETIMEDOUT)), "FUTEX_WAIT_BITSET after {took:?}");
    assert!(took >= Duration::from_millis(59), "FUTEX_WAIT_BITSET timed out after {took:?}");
}

/// The test thread sleeps (a nanosleep, then pthread_cond_timedwait) while a thread works. In
/// coroutine mode the thread must run meanwhile (a sleep used to be a host wait, which stopped
/// every coroutine, a hosted program's too), and the timed wait must time out (its coroutine
/// wasn't on the list the scheduler times waits out from). glibc's timed wait waits again after
/// an early return until its deadline, so futex_timeout's bug doesn't show here.
pub fn sleepy() {
    static TICKS: AtomicU32 = AtomicU32::new(0);
    let t = thread::spawn(|| {
        for _ in 0..20 {
            TICKS.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(2));
        }
    });
    thread::sleep(Duration::from_millis(20));
    let seen = TICKS.load(Ordering::SeqCst);
    // SAFETY: a mutex and condvar of our own, initialized, on this stack for the whole wait.
    let r = unsafe {
        let mut m: libc::pthread_mutex_t = libc::PTHREAD_MUTEX_INITIALIZER;
        let mut c: libc::pthread_cond_t = libc::PTHREAD_COND_INITIALIZER;
        let mut ts: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts);
        ts.tv_nsec += 30_000_000;
        if ts.tv_nsec >= 1_000_000_000 {
            ts.tv_sec += 1;
            ts.tv_nsec -= 1_000_000_000;
        }
        libc::pthread_mutex_lock(&mut m);
        let r = libc::pthread_cond_timedwait(&mut c, &mut m, &ts);
        libc::pthread_mutex_unlock(&mut m);
        r
    };
    t.join().unwrap();
    assert!(seen > 0, "the thread didn't run during the test thread's 20 ms sleep");
    assert_eq!(r, libc::ETIMEDOUT, "pthread_cond_timedwait");
}

/// A thread making syscalls while another sleeps in short poll timeouts (curl's threaded resolver
/// pattern: the main thread polls a socketpair with a timeout while the resolver thread works, then
/// writes to wake it). A new thread's first syscall makes its LKL task as a thread of init's
/// process; that used to take init's task over from the caller's host thread
/// (switch_to_host_task), so a later switch to init handed the CPU to the wrong thread:
/// "lkl_cpu_put: unbalanced put".
pub fn threadpoll() {
    // (the thread's syscalls: none, open/close, a pipe's round trip; how many; the poll's timeout)
    let runs = [(0, 0, 1), (1, 1000, 1), (2, 1000, 1), (1, 1000, 10), (2, 200, 0)];
    for (run, (what, iters, timeout)) in runs.into_iter().enumerate() {
        let mut sv = [0; 2];
        // SAFETY: a two-int buffer.
        assert_eq!(unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_STREAM, 0, sv.as_mut_ptr()) }, 0);
        let w = sv[1];
        let t = thread::spawn(move || {
            for _ in 0..iters {
                // SAFETY: fds of this thread's own; one-byte buffers.
                unsafe {
                    if what == 1 {
                        libc::close(libc::open(c"/".as_ptr(), libc::O_RDONLY));
                    } else if what == 2 {
                        let (r, w) = pipe();
                        let mut b = 0u8;
                        assert!(libc::write(w, b"x".as_ptr().cast(), 1) == 1 && libc::read(r, (&raw mut b).cast(), 1) == 1);
                        libc::close(r);
                        libc::close(w);
                    }
                }
            }
            // SAFETY: a one-byte write to our socket.
            assert_eq!(unsafe { libc::write(w, b"x".as_ptr().cast(), 1) }, 1);
        });
        let mut p = libc::pollfd { fd: sv[0], events: libc::POLLIN, revents: 0 };
        let mut polls = 0;
        // SAFETY: one pollfd.
        while unsafe { libc::poll(&mut p, 1, timeout) } == 0 {
            polls += 1;
        }
        t.join().unwrap_or_else(|_| panic!("run {run}: the thread failed"));
        let mut b = 0u8;
        // SAFETY: a one-byte read; our fds.
        unsafe {
            assert_eq!(libc::read(sv[0], (&raw mut b).cast(), 1), 1, "run {run}");
            libc::close(sv[0]);
            libc::close(sv[1]);
        }
        println!("run {run} ok: {iters} syscalls of kind {what} on a thread, {polls} polls of {timeout} ms meanwhile");
    }
}
