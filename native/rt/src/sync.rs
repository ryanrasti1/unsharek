//! What LKL's host operations need, on top of the scheduler: semaphores, mutexes, TLS keys, a
//! one-shot timer, and `jmp_buf_set`/`jmp_buf_longjmp`.
//!
//! Cooperative scheduling makes each operation atomic: nothing else runs between a check and the
//! block that follows it. Semaphores and mutexes **hand off**: an `up`/`unlock` with waiters gives
//! the unit or the lock straight to the first waiter, so waiters are served in FIFO order and a
//! coroutine that never blocks can't overtake them.
//!
//! Storage is the caller's (LKL's `*_alloc` ops will take these from fixed pools); each type is
//! `const`-constructible.

use core::cell::Cell;
use core::ffi::c_void;

use crate::context::{self, JmpBuf};
use crate::sched::{Sched, SpawnError, Tid, Wake, WaitQueue, WaitTag};

/// A counting semaphore (LKL's `sem_*`).
pub struct Semaphore {
    count: Cell<u64>,
    q: WaitQueue,
}

impl Semaphore {
    pub const fn new(count: u64) -> Self {
        Semaphore { count: Cell::new(count), q: WaitQueue::new() }
    }

    pub fn up(&self, s: &Sched) {
        if s.wake_one(&self.q).is_none() {
            self.count.set(self.count.get() + 1);
        }
    }

    pub fn down(&self, s: &Sched) {
        if self.try_down() {
            return;
        }
        // Woken through the queue = handed a unit by `up`. Interrupted: not handed one; take one
        // if an `up` came while it was off the queue (it found no waiter and counted it), else
        // wait again.
        while s.wait(&self.q, WaitTag::default(), None) != Wake::Woken {
            if self.try_down() {
                return;
            }
        }
    }

    pub fn try_down(&self) -> bool {
        let c = self.count.get();
        if c == 0 {
            return false;
        }
        self.count.set(c - 1);
        true
    }
}

/// A mutex, recursive or not (LKL's `mutex_*`).
pub struct Mutex {
    owner: Cell<Option<Tid>>,
    depth: Cell<u32>,
    recursive: bool,
    q: WaitQueue,
}

impl Mutex {
    pub const fn new(recursive: bool) -> Self {
        Mutex { owner: Cell::new(None), depth: Cell::new(0), recursive, q: WaitQueue::new() }
    }

    pub fn lock(&self, s: &Sched) {
        if self.try_lock(s) {
            return;
        }
        let me = s.current();
        assert!(self.owner.get() != Some(me), "a non-recursive mutex locked twice by its owner");
        // Woken through the queue = `unlock` made us the owner.
        while s.wait(&self.q, WaitTag::default(), None) != Wake::Woken {}
        debug_assert_eq!(self.owner.get(), Some(me));
    }

    pub fn try_lock(&self, s: &Sched) -> bool {
        let me = s.current();
        match self.owner.get() {
            None => {
                self.owner.set(Some(me));
                self.depth.set(1);
                true
            }
            Some(o) if o == me && self.recursive => {
                self.depth.set(self.depth.get() + 1);
                true
            }
            Some(_) => false,
        }
    }

    pub fn unlock(&self, s: &Sched) {
        debug_assert_eq!(self.owner.get(), Some(s.current()), "unlocked by a non-owner");
        let d = self.depth.get() - 1;
        self.depth.set(d);
        if d > 0 {
            return;
        }
        match s.wake_one(&self.q) {
            Some(t) => {
                self.owner.set(Some(t));
                self.depth.set(1);
            }
            None => self.owner.set(None),
        }
    }
}

/// A TLS key (LKL's `tls_*`): a value per coroutine, 0 until set, and an optional destructor run
/// at the coroutine's exit for a nonzero value (POSIX's rules: the value is cleared first, and
/// destructors that set values again get up to 4 rounds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlsKey(pub(crate) usize);

impl TlsKey {
    /// `None` when all `sched::TLS_KEYS` keys are taken.
    pub fn alloc(s: &Sched, dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> Option<TlsKey> {
        s.tls_alloc(dtor).map(TlsKey)
    }
    pub fn free(self, s: &Sched) {
        s.tls_free(self.0)
    }
    pub fn get(self, s: &Sched) -> usize {
        s.tls_get(self.0)
    }
    pub fn set(self, s: &Sched, v: usize) {
        s.tls_set(self.0, v)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TimerState {
    Idle,
    Armed,
    Freed,
}

/// A one-shot timer (LKL's `timer_*`): when it fires, its function runs on the timer's own
/// coroutine, as LKL expects (the function takes LKL's CPU lock, so it must be able to block, and
/// must not run on whoever happened to be idling).
///
/// The coroutine sleeps on the scheduler's timer heap; `set_oneshot`/`cancel` re-arm it by waking
/// it, and it re-reads its state. A deadline that passed while the coroutine waited to run is
/// still noticed: it fires only if the deadline it slept for is still the armed one.
pub struct Timer {
    sched: Cell<Option<&'static Sched>>,
    f: Cell<Option<(unsafe extern "C" fn(*mut c_void), *mut c_void)>>,
    state: Cell<TimerState>,
    deadline: Cell<u64>,
    tid: Cell<Option<Tid>>,
}

impl Default for Timer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer {
    pub const fn new() -> Self {
        Timer {
            sched: Cell::new(None),
            f: Cell::new(None),
            state: Cell::new(TimerState::Idle),
            deadline: Cell::new(0),
            tid: Cell::new(None),
        }
    }

    /// Start the timer's coroutine (LKL's `timer_alloc`); disarmed. Takes a coroutine slot.
    ///
    /// # Safety
    /// `f(arg)` is safe to call on the timer's coroutine whenever it fires.
    pub unsafe fn start(
        &'static self,
        s: &'static Sched,
        f: unsafe extern "C" fn(*mut c_void),
        arg: *mut c_void,
    ) -> Result<(), SpawnError> {
        self.sched.set(Some(s));
        self.f.set(Some((f, arg)));
        self.state.set(TimerState::Idle);
        let tid = s.spawn(timer_main, self as *const Timer as usize)?;
        self.tid.set(Some(tid));
        Ok(())
    }

    fn sched(&self) -> &'static Sched {
        self.sched.get().expect("timer not started")
    }

    /// Fire once, `delta_ns` from now (re-arming replaces the previous deadline). Saturates: LKL
    /// arms "no event" as ULONG_MAX, and `now + ULONG_MAX` wrapped would be a deadline in the past
    /// (capnix fired at once and spun). A saturated deadline is "never".
    pub fn set_oneshot(&self, delta_ns: u64) {
        let s = self.sched();
        self.deadline.set(s.now().saturating_add(delta_ns));
        self.state.set(TimerState::Armed);
        self.poke();
    }

    pub fn cancel(&self) {
        if self.state.get() == TimerState::Armed {
            self.state.set(TimerState::Idle);
            self.poke();
        }
    }

    /// Disarm and end the timer's coroutine (LKL's `timer_free`). From another coroutine it waits
    /// for that end, so the Timer's storage can be reused at once; from the timer's own function,
    /// the coroutine ends when the function returns.
    pub fn free(&self) {
        let s = self.sched();
        self.state.set(TimerState::Freed);
        let Some(tid) = self.tid.take() else { return };
        if tid == s.current() {
            let _ = s.detach(tid);
        } else {
            s.wake(tid);
            let _ = s.join(tid);
        }
    }

    fn poke(&self) {
        if let Some(t) = self.tid.get() {
            // Not blocked (runnable, or running its function): it re-reads the state anyway.
            self.sched().wake(t);
        }
    }
}

fn timer_main(p: usize) -> usize {
    // SAFETY: `start` passed a &'static Timer.
    let t = unsafe { &*(p as *const Timer) };
    let s = t.sched();
    loop {
        match t.state.get() {
            TimerState::Freed => return 0,
            TimerState::Idle => {
                s.block(None);
            }
            TimerState::Armed => {
                let d = t.deadline.get();
                if s.block(Some(d)) == Wake::TimedOut
                    && t.state.get() == TimerState::Armed
                    && t.deadline.get() == d
                {
                    t.state.set(TimerState::Idle);
                    let (f, arg) = t.f.get().expect("timer without a function");
                    // SAFETY: `start`'s caller vouched for it.
                    unsafe { f(arg) };
                }
            }
        }
    }
}

/// LKL's `jmp_buf_set`: call `f(arg)`, which may come back here with [`jmp_buf_longjmp`]. Returns
/// 0 if `f` returned, else the (nonzero) value passed to the longjmp.
///
/// Built on the context primitive (`context::call_with_jump_back`), not `setjmp`: it returns once
/// either way, so Rust never sees a function return twice. `f` may block and yield in between: the
/// jump-back point is on this coroutine's stack, which stays put.
///
/// # Safety
/// As `context::call_with_jump_back`: the frames a longjmp skips have nothing to drop; the longjmp
/// comes from this coroutine, while this call is active.
pub unsafe fn jmp_buf_set(buf: *mut JmpBuf, f: unsafe extern "C" fn(usize), arg: usize) -> usize {
    // SAFETY: the caller's contract.
    unsafe { context::call_with_jump_back(buf, f, arg) }
}

/// LKL's `jmp_buf_longjmp`: return from the active [`jmp_buf_set`] on `buf` with `val` (1 if 0, so
/// it differs from `f` returning, as C's longjmp).
///
/// # Safety
/// As [`jmp_buf_set`].
pub unsafe fn jmp_buf_longjmp(buf: *const JmpBuf, val: usize) -> ! {
    // SAFETY: the caller's contract.
    unsafe { context::jump(buf, if val == 0 { 1 } else { val }) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeClock, new_sched};
    use std::cell::RefCell;

    #[test]
    fn semaphore_producer_consumer() {
        const SLOTS: usize = 4;
        const ITEMS: usize = 2000;
        struct Q {
            s: &'static Sched,
            empty: Semaphore,
            full: Semaphore,
            lock: Mutex,
            buf: RefCell<std::collections::VecDeque<usize>>,
            got: RefCell<Vec<usize>>,
        }
        fn producer(p: usize) -> usize {
            let (q, base) = unsafe { &*(p as *const (&'static Q, usize)) };
            for i in 0..ITEMS {
                q.empty.down(q.s);
                q.lock.lock(q.s);
                assert!(q.buf.borrow().len() < SLOTS);
                q.buf.borrow_mut().push_back(base + i);
                // Hold the lock across a yield: the others must queue on it.
                if i % 7 == 0 {
                    q.s.yield_now();
                }
                q.lock.unlock(q.s);
                q.full.up(q.s);
            }
            0
        }
        fn consumer(p: usize) -> usize {
            let q = unsafe { &*(p as *const Q) };
            for _ in 0..ITEMS {
                q.full.down(q.s);
                q.lock.lock(q.s);
                let v = q.buf.borrow_mut().pop_front().unwrap();
                q.lock.unlock(q.s);
                q.got.borrow_mut().push(v);
                q.empty.up(q.s);
            }
            0
        }
        let s = new_sched(8, FakeClock::leak());
        let q: &'static Q = Box::leak(Box::new(Q {
            s,
            empty: Semaphore::new(SLOTS as u64),
            full: Semaphore::new(0),
            lock: Mutex::new(false),
            buf: RefCell::new(Default::default()),
            got: RefCell::new(Vec::new()),
        }));
        let pa: &'static [(&'static Q, usize); 2] = Box::leak(Box::new([(q, 0), (q, 1_000_000)]));
        let mut tids = vec![];
        for a in pa {
            tids.push(s.spawn(producer, a as *const _ as usize).unwrap());
        }
        for _ in 0..2 {
            tids.push(s.spawn(consumer, q as *const Q as usize).unwrap());
        }
        for t in tids {
            s.join(t).unwrap();
        }
        let mut got = q.got.borrow().clone();
        // Each producer's items arrive in its order.
        let a: Vec<usize> = got.iter().copied().filter(|&v| v < 1_000_000).collect();
        assert_eq!(a, (0..ITEMS).collect::<Vec<_>>());
        got.sort();
        let want: Vec<usize> = (0..ITEMS).chain((0..ITEMS).map(|i| 1_000_000 + i)).collect();
        assert_eq!(got, want);
        assert_eq!(q.empty.count.get(), SLOTS as u64);
    }

    #[test]
    fn recursive_mutex() {
        struct T {
            s: &'static Sched,
            m: Mutex,
            log: RefCell<Vec<&'static str>>,
        }
        fn other(p: usize) -> usize {
            let t = unsafe { &*(p as *const T) };
            t.log.borrow_mut().push("other wants");
            t.m.lock(t.s);
            t.log.borrow_mut().push("other has");
            t.m.unlock(t.s);
            0
        }
        let s = new_sched(2, FakeClock::leak());
        let t: &'static T = Box::leak(Box::new(T { s, m: Mutex::new(true), log: RefCell::new(vec![]) }));
        t.m.lock(s);
        t.m.lock(s);
        assert!(t.m.try_lock(s));
        let o = s.spawn(other, t as *const T as usize).unwrap();
        s.yield_now(); // other blocks on the mutex
        t.m.unlock(s);
        t.m.unlock(s);
        s.yield_now();
        assert_eq!(*t.log.borrow(), ["other wants"], "still held once");
        t.log.borrow_mut().push("root releases");
        t.m.unlock(s);
        assert_eq!(t.m.owner.get(), Some(o), "handed to the waiter");
        s.join(o).unwrap();
        assert_eq!(*t.log.borrow(), ["other wants", "root releases", "other has"]);
        assert_eq!(t.m.owner.get(), None);
        let nr = Mutex::new(false);
        assert!(nr.try_lock(s));
        assert!(!nr.try_lock(s), "a non-recursive mutex isn't re-entered");
        nr.unlock(s);
    }

    thread_local! {
        static DTOR_LOG: RefCell<Vec<usize>> = const { RefCell::new(Vec::new()) };
    }
    unsafe extern "C" fn log_dtor(v: *mut c_void) {
        DTOR_LOG.with(|l| l.borrow_mut().push(v as usize));
    }
    thread_local! {
        static RESET_KEY: Cell<Option<(TlsKey, &'static Sched)>> = const { Cell::new(None) };
    }
    // Sets its own key again once: POSIX runs it another round.
    unsafe extern "C" fn resetting_dtor(v: *mut c_void) {
        DTOR_LOG.with(|l| l.borrow_mut().push(v as usize));
        if v as usize == 100 {
            let (k, s) = RESET_KEY.with(|r| r.get().unwrap());
            k.set(s, 101);
        }
    }

    #[test]
    fn tls_values_and_destructors() {
        struct T {
            s: &'static Sched,
            a: TlsKey,
            b: TlsKey,
            c: TlsKey,
        }
        fn body(p: usize) -> usize {
            let (t, n) = unsafe { &*(p as *const (&'static T, usize)) };
            assert_eq!(t.a.get(t.s), 0, "starts empty");
            t.a.set(t.s, *n);
            t.b.set(t.s, 100);
            t.c.set(t.s, *n + 1000);
            t.s.yield_now();
            assert_eq!(t.a.get(t.s), *n, "per coroutine");
            if *n == 2 {
                t.c.set(t.s, 0); // a zero value isn't destroyed
            }
            0
        }
        let s = new_sched(4, FakeClock::leak());
        let a = TlsKey::alloc(s, Some(log_dtor)).unwrap();
        let b = TlsKey::alloc(s, Some(resetting_dtor)).unwrap();
        let c = TlsKey::alloc(s, None).unwrap();
        RESET_KEY.with(|r| r.set(Some((b, s))));
        let t: &'static T = Box::leak(Box::new(T { s, a, b, c }));
        let args: &'static [(&'static T, usize)] = Box::leak(Box::new([(t, 1), (t, 2)]));
        let ids: Vec<Tid> = args.iter().map(|x| s.spawn(body, x as *const _ as usize).unwrap()).collect();
        a.set(s, 77);
        for id in ids {
            s.join(id).unwrap();
        }
        // Per coroutine, in key order: a's value, then b's 100, then b's 101 in the next round.
        assert_eq!(DTOR_LOG.with(|l| l.borrow().clone()), [1, 100, 101, 2, 100, 101]);
        assert_eq!(a.get(s), 77, "the root's own value untouched");
        // Keys run out, and a freed key comes back empty.
        let more: Vec<TlsKey> = std::iter::from_fn(|| TlsKey::alloc(s, None)).collect();
        assert_eq!(more.len(), crate::sched::TLS_KEYS - 3);
        a.free(s);
        let a2 = TlsKey::alloc(s, None).unwrap();
        assert_eq!(a2, a);
        assert_eq!(a2.get(s), 0);
    }

    struct J {
        s: &'static Sched,
        buf: JmpBuf,
        yields: usize,
        depth_hits: Cell<usize>,
    }
    unsafe extern "C" fn jumper(p: usize) {
        let j = unsafe { &*(p as *const J) };
        for _ in 0..j.yields {
            j.s.yield_now();
        }
        j.depth_hits.set(j.depth_hits.get() + 1);
        unsafe { jmp_buf_longjmp(&j.buf, j.yields) }
    }
    fn jmp_body(p: usize) -> usize {
        // Raw pointers only: `jumper` reads the same J while this frame is active.
        let j = p as *mut J;
        let mut sum = 0;
        for _ in 0..100 {
            sum += unsafe { jmp_buf_set(&raw mut (*j).buf, jumper, p) };
        }
        sum
    }

    #[test]
    fn jmp_buf_round_trips_across_yields() {
        let s = new_sched(2, FakeClock::leak());
        // Two coroutines interleaving their set/longjmp pairs, each on its own stack; yields of 0
        // longjmp with 0, which reads back as 1.
        let js: Vec<&'static mut J> =
            [0usize, 3].iter().map(|&y| Box::leak(Box::new(J { s, buf: JmpBuf::new(), yields: y, depth_hits: Cell::new(0) }))).collect();
        let ids: Vec<Tid> = js.iter().map(|j| s.spawn(jmp_body, &**j as *const J as usize).unwrap()).collect();
        assert_eq!(s.join(ids[0]), Ok(100));
        assert_eq!(s.join(ids[1]), Ok(300));
        assert_eq!(js[1].depth_hits.get(), 100);
    }

    thread_local! {
        static FIRED: RefCell<Vec<(u64, u64)>> = const { RefCell::new(Vec::new()) };
    }
    thread_local! {
        static TIMER_SCHED: Cell<Option<&'static Sched>> = const { Cell::new(None) };
    }
    unsafe extern "C" fn on_fire(id: *mut c_void) {
        let s = TIMER_SCHED.with(|t| t.get().unwrap());
        assert_ne!(s.current(), ROOT_TID.with(|r| r.get().unwrap()), "fired on the idler's coroutine");
        FIRED.with(|f| f.borrow_mut().push((id as u64, s.now())));
    }
    thread_local! {
        static ROOT_TID: Cell<Option<Tid>> = const { Cell::new(None) };
    }

    fn timer_setup() -> (&'static Sched, &'static FakeClock) {
        let clock = FakeClock::leak();
        let s = new_sched(8, clock);
        TIMER_SCHED.with(|t| t.set(Some(s)));
        ROOT_TID.with(|r| r.set(Some(s.current())));
        (s, clock)
    }

    fn timer(s: &'static Sched, id: usize) -> &'static Timer {
        let t: &'static Timer = Box::leak(Box::new(Timer::new()));
        unsafe { t.start(s, on_fire, id as *mut c_void).unwrap() };
        t
    }

    #[test]
    fn timers_fire_in_order_on_their_coroutine() {
        let (s, _) = timer_setup();
        let ts: Vec<&'static Timer> = (0..5).map(|i| timer(s, i)).collect();
        s.yield_now(); // they start, disarmed
        for (i, d) in [(0, 500u64), (1, 100), (2, 300), (3, 300), (4, 200)] {
            ts[i].set_oneshot(d);
        }
        ts[3].set_oneshot(400); // re-armed: replaces 300
        s.sleep_until(1000);
        assert_eq!(FIRED.with(|f| f.borrow().clone()), [(1, 100), (4, 200), (2, 300), (3, 400), (0, 500)]);
        // One-shot: nothing more.
        s.sleep_until(2000);
        assert_eq!(FIRED.with(|f| f.borrow().len()), 5);
        for t in ts {
            t.free();
        }
        assert_eq!(s.live_count(), 1, "freed timers' coroutines are gone");
    }

    #[test]
    fn timer_cancel() {
        let (s, _) = timer_setup();
        let t = timer(s, 1);
        t.set_oneshot(100);
        s.sleep_until(50);
        t.cancel();
        s.sleep_until(1000);
        assert!(FIRED.with(|f| f.borrow().is_empty()));
        t.set_oneshot(10);
        s.sleep_until(2000);
        assert_eq!(FIRED.with(|f| f.borrow().clone()), [(1, 1010)]);
        t.free();
    }

    #[test]
    fn timer_huge_delta_saturates() {
        let (s, clock) = timer_setup();
        let t = timer(s, 1);
        s.sleep_until(1000); // now != 0: now + ULONG_MAX would wrap to 999
        let idles = clock.idles();
        t.set_oneshot(u64::MAX); // LKL's "no event"
        s.sleep_until(5000);
        // No fire, and one idle (to 5000), not a spin: the timer is not in the heap at all.
        assert!(FIRED.with(|f| f.borrow().is_empty()));
        assert_eq!(clock.idles() - idles, 1);
        t.set_oneshot(u64::MAX - 10);
        s.sleep_until(9000);
        assert!(FIRED.with(|f| f.borrow().is_empty()));
        assert_eq!(clock.idles() - idles, 2);
        t.free();
    }
}
