//! Threads and futexes (thread_fds.c, futex_wake.c), and std's own synchronization.

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
    let t0 = std::time::Instant::now();
    let rel = libc::timespec { tv_sec: 0, tv_nsec: 60_000_000 };
    // SAFETY: a futex wait on a local word, with a timeout.
    let r = unsafe {
        libc::syscall(libc::SYS_futex, w.as_ptr(), libc::FUTEX_WAIT | libc::FUTEX_PRIVATE_FLAG, 0, &rel, 0usize, 0)
    };
    let e = crate::errno();
    let took = t0.elapsed();
    assert_eq!((r, e.raw_os_error()), (-1, Some(libc::ETIMEDOUT)), "FUTEX_WAIT after {took:?}");
    assert!(took >= Duration::from_millis(60), "FUTEX_WAIT timed out after {took:?}");

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
