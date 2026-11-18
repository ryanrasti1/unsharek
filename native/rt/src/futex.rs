//! The program's futexes, emulated over the scheduler (coroutine mode has no host futex): a fixed
//! hash of wait queues keyed by address.
//!
//! - **Exact addresses.** A bucket is shared by every address that hashes to it; each waiter is
//!   tagged with its own address, and a wake takes only waiters on the woken address. (capnix once
//!   woke whatever was first in the slot, an aliasing address's waiter, losing the real wakeup.)
//! - **No lost wakeups.** `*uaddr` is compared with the expected value and the waiter queued with
//!   nothing else running in between: scheduling is cooperative, so that is atomic, as the kernel's
//!   bucket lock makes it.
//! - **Private and shared are the same.** One address space: the key is the address either way.
//!   (Fork mode, with several processes, would key shared futexes by mapping instead.)
//! - **Timeouts** become absolute CLOCK_MONOTONIC deadlines on the scheduler's heap. A realtime
//!   absolute deadline is converted once, at the call: a later jump of the realtime clock doesn't
//!   move it (Linux would follow it).

use core::sync::atomic::{AtomicU32, Ordering};

use rustix::io::Errno;

use crate::sched::{Sched, Wake, WaitQueue, WaitTag};

/// Hash buckets. Power of two.
pub const BUCKETS: usize = 256;
const _: () = assert!(BUCKETS.is_power_of_two());

pub const FUTEX_WAIT: u32 = 0;
pub const FUTEX_WAKE: u32 = 1;
pub const FUTEX_WAIT_BITSET: u32 = 9;
pub const FUTEX_WAKE_BITSET: u32 = 10;
pub const FUTEX_PRIVATE_FLAG: u32 = 128;
pub const FUTEX_CLOCK_REALTIME: u32 = 256;
pub const FUTEX_BITSET_MATCH_ANY: u32 = u32::MAX;
const CMD_MASK: u32 = !(FUTEX_PRIVATE_FLAG | FUTEX_CLOCK_REALTIME);

/// The kernel's `struct timespec` (x86-64).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

impl Timespec {
    fn to_ns(self) -> Result<u64, Errno> {
        if self.tv_sec < 0 || !(0..1_000_000_000).contains(&self.tv_nsec) {
            return Err(Errno::INVAL);
        }
        Ok((self.tv_sec as u64).saturating_mul(1_000_000_000).saturating_add(self.tv_nsec as u64))
    }
}

pub struct Futexes {
    buckets: [WaitQueue; BUCKETS],
}

impl Default for Futexes {
    fn default() -> Self {
        Self::new()
    }
}

/// The bucket an address hashes to (Fibonacci hashing of the 4-byte-aligned address).
pub fn bucket_of(addr: usize) -> usize {
    (((addr >> 2) as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> (64 - BUCKETS.trailing_zeros())) as usize
}

impl Futexes {
    pub const fn new() -> Self {
        Futexes { buckets: [const { WaitQueue::new() }; BUCKETS] }
    }

    /// The `futex` syscall for the commands above (others: ENOSYS). `timeout` is the syscall's
    /// pointer argument already read from the program's memory. Returns what the syscall would.
    ///
    /// # Safety
    /// `uaddr`, if 4-byte aligned, is readable (the SIGSYS handler checks it is mapped; a fault
    /// here would be the handler's, not EFAULT).
    pub unsafe fn futex(
        &self,
        s: &Sched,
        uaddr: *const u32,
        op: u32,
        val: u32,
        timeout: Option<&Timespec>,
        val3: u32,
    ) -> Result<usize, Errno> {
        let cmd = op & CMD_MASK;
        let realtime = op & FUTEX_CLOCK_REALTIME != 0;
        if realtime && cmd != FUTEX_WAIT && cmd != FUTEX_WAIT_BITSET {
            return Err(Errno::NOSYS);
        }
        if !(uaddr as usize).is_multiple_of(4) {
            return Err(Errno::INVAL);
        }
        match cmd {
            FUTEX_WAIT | FUTEX_WAIT_BITSET => {
                let bitset = if cmd == FUTEX_WAIT { FUTEX_BITSET_MATCH_ANY } else { val3 };
                if bitset == 0 {
                    return Err(Errno::INVAL);
                }
                let deadline = match timeout {
                    None => None,
                    Some(ts) => {
                        let t = ts.to_ns()?;
                        let now = s.now();
                        let d = if cmd == FUTEX_WAIT {
                            // Relative, whichever clock: a duration.
                            now.saturating_add(t)
                        } else if realtime {
                            now.saturating_add(t.saturating_sub(s.realtime()))
                        } else {
                            t
                        };
                        Some((d, now))
                    }
                };
                // SAFETY: aligned, readable (the caller's contract); the program writes it
                // atomically.
                let cur = unsafe { AtomicU32::from_ptr(uaddr as *mut u32) }.load(Ordering::SeqCst);
                if cur != val {
                    return Err(Errno::AGAIN);
                }
                if let Some((d, now)) = deadline
                    && d <= now
                {
                    return Err(Errno::TIMEDOUT);
                }
                let q = &self.buckets[bucket_of(uaddr as usize)];
                let tag = WaitTag { key: uaddr as usize, mask: bitset };
                match s.wait(q, tag, deadline.map(|(d, _)| d)) {
                    Wake::Woken => Ok(0),
                    Wake::TimedOut => Err(Errno::TIMEDOUT),
                    Wake::Interrupted => Err(Errno::INTR),
                }
            }
            FUTEX_WAKE | FUTEX_WAKE_BITSET => {
                let bitset = if cmd == FUTEX_WAKE { FUTEX_BITSET_MATCH_ANY } else { val3 };
                if bitset == 0 {
                    return Err(Errno::INVAL);
                }
                Ok(self.wake(s, uaddr as usize, val, bitset))
            }
            _ => Err(Errno::NOSYS),
        }
    }

    /// Wake up to `n` waiters on `addr` whose bitset meets `bitset`; how many. As Linux, `n` is the
    /// syscall's int and anything below 1 still wakes one. Also for the end of a thread with
    /// CLONE_CHILD_CLEARTID.
    pub fn wake(&self, s: &Sched, addr: usize, n: u32, bitset: u32) -> usize {
        let max = (n as i32).max(1) as usize;
        s.wake_where(&self.buckets[bucket_of(addr)], max, |t| t.key == addr && t.mask & bitset != 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::Tid;
    use crate::testutil::{FakeClock, new_sched};
    use std::cell::Cell;

    struct W {
        s: &'static Sched,
        f: &'static Futexes,
        addr: *const u32,
        op: u32,
        bitset: u32,
        timeout: Option<Timespec>,
        result: Cell<Option<Result<usize, Errno>>>,
    }

    fn waiter(p: usize) -> usize {
        let w = unsafe { &*(p as *const W) };
        let r = unsafe { w.f.futex(w.s, w.addr, w.op, 0, w.timeout.as_ref(), w.bitset) };
        w.result.set(Some(r));
        0
    }

    fn spawn_waiter(
        s: &'static Sched,
        f: &'static Futexes,
        addr: *const u32,
        op: u32,
        bitset: u32,
        timeout: Option<Timespec>,
    ) -> (&'static W, Tid) {
        let w: &'static W =
            Box::leak(Box::new(W { s, f, addr, op, bitset, timeout, result: Cell::new(None) }));
        (w, s.spawn(waiter, w as *const W as usize).unwrap())
    }

    fn setup(n: usize) -> (&'static Sched, &'static Futexes, &'static FakeClock) {
        let clock = FakeClock::leak();
        (new_sched(n, clock), Box::leak(Box::new(Futexes::new())), clock)
    }

    #[test]
    fn wake_takes_only_its_address_in_a_shared_bucket() {
        let (s, f, _) = setup(16);
        // Words (all 0) of which eight share one bucket.
        let words: &'static [u32] = Box::leak(vec![0u32; 1 << 16].into_boxed_slice());
        let target = bucket_of(&words[0] as *const u32 as usize);
        let same: Vec<*const u32> =
            words.iter().map(|w| w as *const u32).filter(|&a| bucket_of(a as usize) == target).take(8).collect();
        assert_eq!(same.len(), 8);
        let ws: Vec<(&W, Tid)> =
            same.iter().map(|&a| spawn_waiter(s, f, a, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, None)).collect();
        s.yield_now(); // all wait
        // Wake from the back of the queue: the first waiter in the bucket is on another address.
        for (k, &a) in same.iter().enumerate().rev() {
            let n = unsafe { f.futex(s, a, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1, None, 0) };
            assert_eq!(n, Ok(1));
            s.yield_now();
            for (j, (w, _)) in ws.iter().enumerate() {
                let want = if j >= k { Some(Ok(0)) } else { None };
                assert_eq!(w.result.get(), want, "waking #{k}: waiter #{j}");
            }
        }
        for (_, t) in ws {
            s.join(t).unwrap();
        }
        // Nobody left: a wake wakes none.
        assert_eq!(unsafe { f.futex(s, same[0], FUTEX_WAKE, 1, None, 0) }, Ok(0));
    }

    #[test]
    fn wake_counts() {
        let (s, f, _) = setup(8);
        let word: &'static u32 = Box::leak(Box::new(0));
        let ws: Vec<_> = (0..5).map(|_| spawn_waiter(s, f, word, FUTEX_WAIT, 0, None)).collect();
        s.yield_now();
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 2, None, 0) }, Ok(2));
        // Linux: a count below 1 still wakes one.
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 0, None, 0) }, Ok(1));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, i32::MAX as u32, None, 0) }, Ok(2));
        s.yield_now();
        // FIFO.
        assert!(ws.iter().all(|(w, _)| w.result.get() == Some(Ok(0))));
        for (_, t) in ws {
            s.join(t).unwrap();
        }
    }

    #[test]
    fn bitsets() {
        let (s, f, _) = setup(8);
        let word: &'static u32 = Box::leak(Box::new(0));
        let (a, _) = spawn_waiter(s, f, word, FUTEX_WAIT_BITSET, 0b01, None);
        let (b, _) = spawn_waiter(s, f, word, FUTEX_WAIT_BITSET, 0b10, None);
        let (c, _) = spawn_waiter(s, f, word, FUTEX_WAIT_BITSET, 0b11, None);
        let (d, _) = spawn_waiter(s, f, word, FUTEX_WAIT, 0, None); // any
        s.yield_now();
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE_BITSET, 10, None, 0b10) }, Ok(3));
        s.yield_now();
        assert_eq!(
            [a, b, c, d].map(|w| w.result.get()),
            [None, Some(Ok(0)), Some(Ok(0)), Some(Ok(0))]
        );
        // A plain wake matches any bitset.
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 10, None, 0) }, Ok(1));
        s.yield_now();
        assert_eq!(a.result.get(), Some(Ok(0)));
        // A zero bitset is invalid, for wait and wake.
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT_BITSET, 0, None, 0) }, Err(Errno::INVAL));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE_BITSET, 1, None, 0) }, Err(Errno::INVAL));
    }

    #[test]
    fn value_mismatch_is_eagain() {
        let (s, f, clock) = setup(1);
        let word: &'static u32 = Box::leak(Box::new(5));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT, 4, None, 0) }, Err(Errno::AGAIN));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT_BITSET, 6, None, 1) }, Err(Errno::AGAIN));
        assert_eq!(clock.idles(), 0, "never blocked");
        // Misaligned, unknown command, realtime on a wake.
        let p = (word as *const u32 as usize + 1) as *const u32;
        assert_eq!(unsafe { f.futex(s, p, FUTEX_WAKE, 1, None, 0) }, Err(Errno::INVAL));
        assert_eq!(unsafe { f.futex(s, word, 3, 1, None, 0) }, Err(Errno::NOSYS));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE | FUTEX_CLOCK_REALTIME, 1, None, 0) }, Err(Errno::NOSYS));
    }

    #[test]
    fn timeouts() {
        let (s, f, clock) = setup(1);
        clock.set(1_000);
        clock.set_realtime_offset(1_000_000_000_000); // realtime = monotonic + 1000 s
        let word: &'static u32 = Box::leak(Box::new(0));
        let ts = |ns: u64| Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
        // Relative: 500 ns from now.
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT, 0, Some(&ts(500)), 0) }, Err(Errno::TIMEDOUT));
        assert_eq!(clock.now_ns(), 1_500);
        // Absolute monotonic.
        let r = unsafe { f.futex(s, word, FUTEX_WAIT_BITSET, 0, Some(&ts(4_000)), u32::MAX) };
        assert_eq!(r, Err(Errno::TIMEDOUT));
        assert_eq!(clock.now_ns(), 4_000);
        // Absolute realtime.
        let op = FUTEX_WAIT_BITSET | FUTEX_CLOCK_REALTIME;
        let r = unsafe { f.futex(s, word, op, 0, Some(&ts(1_000_000_000_000 + 9_000)), u32::MAX) };
        assert_eq!(r, Err(Errno::TIMEDOUT));
        assert_eq!(clock.now_ns(), 9_000);
        // Already past: at once, no idle.
        let idles = clock.idles();
        let r = unsafe { f.futex(s, word, FUTEX_WAIT_BITSET, 0, Some(&ts(100)), u32::MAX) };
        assert_eq!(r, Err(Errno::TIMEDOUT));
        assert_eq!(clock.idles(), idles);
        // Invalid timespecs.
        let bad = Timespec { tv_sec: 0, tv_nsec: 1_000_000_000 };
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT, 0, Some(&bad), 0) }, Err(Errno::INVAL));
        let neg = Timespec { tv_sec: -1, tv_nsec: 0 };
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAIT, 0, Some(&neg), 0) }, Err(Errno::INVAL));
        // A huge relative timeout saturates instead of wrapping into the past: woken, not timed out.
        let (w, t) = spawn_waiter(s, f, word, FUTEX_WAIT, 0, Some(Timespec { tv_sec: i64::MAX, tv_nsec: 0 }));
        s.yield_now();
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 1, None, 0) }, Ok(1));
        s.join(t).unwrap();
        assert_eq!(w.result.get(), Some(Ok(0)));
    }

    #[test]
    fn a_timed_out_waiter_leaves_the_queue() {
        // Its wake mustn't be spent on it after it gave up.
        let (s, f, _) = setup(4);
        let word: &'static u32 = Box::leak(Box::new(0));
        let (early, t1) = spawn_waiter(s, f, word, FUTEX_WAIT, 0, Some(Timespec { tv_sec: 0, tv_nsec: 100 }));
        let (late, t2) = spawn_waiter(s, f, word, FUTEX_WAIT, 0, None);
        s.yield_now();
        s.sleep_until(1_000);
        assert_eq!(early.result.get(), Some(Err(Errno::TIMEDOUT)));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 1, None, 0) }, Ok(1));
        s.join(t1).unwrap();
        s.join(t2).unwrap();
        assert_eq!(late.result.get(), Some(Ok(0)));
    }

    #[test]
    fn interrupted_wait_is_eintr() {
        let (s, f, _) = setup(2);
        let word: &'static u32 = Box::leak(Box::new(0));
        let (w, t) = spawn_waiter(s, f, word, FUTEX_WAIT, 0, None);
        s.yield_now();
        assert!(s.wake(t));
        s.join(t).unwrap();
        assert_eq!(w.result.get(), Some(Err(Errno::INTR)));
        assert_eq!(unsafe { f.futex(s, word, FUTEX_WAKE, 1, None, 0) }, Ok(0), "off the queue");
    }
}
