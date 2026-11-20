//! Test helpers (std is fine here): stacks, schedulers, and clocks for the scheduler's host hook.

use std::cell::Cell;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::sched::{Config, Host, Sched, Stacks};

/// Each test coroutine's stack. Generous: a failed assertion formats on it before aborting.
pub const STACK: usize = 256 * 1024;

/// A heap-allocated stack for the raw context tests.
pub struct Stack(Box<[u8]>);

impl Stack {
    pub fn new(size: usize) -> Stack {
        Stack(vec![0u8; size].into_boxed_slice())
    }
    pub fn top(&self) -> usize {
        self.0.as_ptr() as usize + self.0.len()
    }
}

fn region(n: usize) -> *mut u8 {
    // Reserved, not committed: a thousand stacks cost only what they touch.
    unsafe {
        rustix::mm::mmap_anonymous(
            std::ptr::null_mut(),
            n * STACK,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE | rustix::mm::MapFlags::NORESERVE,
        )
        .unwrap() as *mut u8
    }
}

fn sched(n: usize, host: &'static dyn Host, guard: bool) -> &'static Sched {
    let s: &'static Sched = Box::leak(Box::new(Sched::new()));
    let stacks = Stacks { base: region(n), len: n * STACK, size: STACK, guard };
    let got = unsafe { s.init(Config { stacks, switch_fs: false, host }) }.unwrap();
    assert_eq!(got, n.min(crate::sched::CAPACITY - 1));
    s
}

/// A scheduler with room for `n` coroutines besides the calling thread (the root).
pub fn new_sched(n: usize, host: &'static dyn Host) -> &'static Sched {
    sched(n, host, false)
}

pub fn new_sched_guarded(n: usize, host: &'static dyn Host) -> &'static Sched {
    sched(n, host, true)
}

/// A clock that moves only when the scheduler idles: straight to the deadline. Counts idles, so
/// a test can tell a wait from a spin. Idle with no deadline is a deadlock: the test fails.
pub struct FakeClock {
    now: Cell<u64>,
    realtime_offset: Cell<u64>,
    idles: Cell<usize>,
}

impl FakeClock {
    pub fn leak() -> &'static FakeClock {
        Box::leak(Box::new(FakeClock { now: Cell::new(0), realtime_offset: Cell::new(0), idles: Cell::new(0) }))
    }
    pub fn idles(&self) -> usize {
        self.idles.get()
    }
    pub fn now_ns(&self) -> u64 {
        self.now.get()
    }
    pub fn set(&self, ns: u64) {
        self.now.set(ns)
    }
    pub fn set_realtime_offset(&self, ns: u64) {
        self.realtime_offset.set(ns)
    }
}

impl Host for FakeClock {
    fn monotonic(&self) -> u64 {
        self.now.get()
    }
    fn realtime(&self) -> u64 {
        self.now.get() + self.realtime_offset.get()
    }
    fn idle(&self, deadline: Option<u64>) {
        self.idles.set(self.idles.get() + 1);
        let d = deadline.expect("deadlock: nothing runnable and no timer");
        self.now.set(self.now.get().max(d));
    }
}

/// The real clocks; idle sleeps.
pub struct RealClock(Instant);

impl RealClock {
    pub fn leak() -> &'static RealClock {
        Box::leak(Box::new(RealClock(Instant::now())))
    }
}

impl Host for RealClock {
    fn monotonic(&self) -> u64 {
        self.0.elapsed().as_nanos() as u64
    }
    fn realtime(&self) -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos() as u64
    }
    fn idle(&self, deadline: Option<u64>) {
        let d = deadline.expect("deadlock: nothing runnable and no timer");
        let now = self.monotonic();
        if d > now {
            std::thread::sleep(std::time::Duration::from_nanos(d - now));
        }
    }
}
