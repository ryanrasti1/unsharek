//! A single-host-thread cooperative scheduler (coroutine mode): LKL's kernel threads and the
//! program's own threads are coroutines on one host thread.
//!
//! - **Storage.** A fixed table of [`CAPACITY`] coroutines inside [`Sched`]; their stacks are
//!   carved at [`Sched::init`] from one region the caller hands in. Nothing is allocated after.
//! - **Switching is direct.** A coroutine that yields or blocks switches straight to the next
//!   runnable one (one context switch, not two through a scheduler stack). When nothing is
//!   runnable, the blocking coroutine itself calls the host's `idle` hook on its own stack.
//! - **Run queue** FIFO. **Timers** (sleeps, timed waits) in a binary min-heap of absolute
//!   CLOCK_MONOTONIC deadlines, ties in arming order.
//! - **Wait queues** ([`WaitQueue`]) are intrusive and doubly linked through the table, so a
//!   timed-out or interrupted waiter leaves its queue at once (it can't eat a later wake).
//! - **Interface.** "The current coroutine" and the run queue are fields of `Sched`, reached only
//!   through its methods. Threaded mode (a host thread per program thread, taking turns on one CPU
//!   token) can replace what's behind `current`/`schedule` without touching the callers.
//!
//! Everything here assumes one host thread runs the coroutines of a `Sched` (interior mutability
//! through `Cell`, no atomics). The tables are reached through `&Sched`, never `&mut`, because a
//! switch suspends code that holds a reference.

use core::cell::{Cell, UnsafeCell};
use core::ffi::c_void;
use core::fmt;

use crate::context::{self, Context, Registers};

/// Coroutines in the table, including the root (the host thread's own stack). LKL's kernel
/// threads number a few dozen; the rest is the program's threads.
pub const CAPACITY: usize = 1024;
/// TLS keys ([`Sched::tls_alloc`]): LKL allocates a handful.
pub const TLS_KEYS: usize = 16;
/// While coroutines keep each other busy, the clock is read (and expired timers woken) once per
/// this many switches; when nothing is runnable, always. Reading it on every switch would put a
/// clock read (a syscall in production, without the vDSO) on the fast path.
const TIMER_CHECK_EVERY: u32 = 64;
/// POSIX's PTHREAD_DESTRUCTOR_ITERATIONS: a destructor may set values again.
const TLS_DESTRUCTOR_ROUNDS: usize = 4;
const PAGE: usize = 4096;

const NONE: u16 = u16::MAX;
const ROOT: u16 = 0;
const _: () = assert!(CAPACITY < NONE as usize && TLS_KEYS <= 32);

/// The host side of the scheduler, provided by the caller: clocks and the wait when nothing can
/// run. Injectable so tests can use a fake clock.
pub trait Host {
    /// CLOCK_MONOTONIC, in ns.
    fn monotonic(&self) -> u64;
    /// CLOCK_REALTIME, in ns (absolute futex timeouts may be against it).
    fn realtime(&self) -> u64;
    /// Nothing is runnable. Wait until `deadline` (CLOCK_MONOTONIC ns), or for an external event
    /// (a signal, input) if `None`, or return early. The scheduler re-checks after it returns. In
    /// the sandbox: a host `ppoll` with a timeout.
    fn idle(&self, deadline: Option<u64>);
}

/// A coroutine's id: its slot and the slot's generation, so an id outlives its coroutine without
/// naming the next one in the slot. Never 0 (LKL's `thread_create` returns 0 for failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Tid(u64);

impl Tid {
    fn new(idx: u16, generation: u32) -> Tid {
        Tid(((generation as u64) << 16) | idx as u64)
    }
    fn idx(self) -> usize {
        (self.0 & 0xffff) as usize
    }
    fn generation(self) -> u32 {
        (self.0 >> 16) as u32
    }
    pub fn raw(self) -> u64 {
        self.0
    }
    pub fn from_raw(raw: u64) -> Tid {
        Tid(raw)
    }
}

/// Why a block returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wake {
    /// Woken: by [`Sched::wake`] (a plain block) or through its wait queue.
    Woken,
    /// Its deadline passed.
    TimedOut,
    /// Taken off a wait queue by [`Sched::wake`] rather than by the queue's owner (later: a
    /// signal). Waiters that need a hand-off (a semaphore unit, a mutex) wait again.
    Interrupted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpawnError {
    /// Every slot with a stack is taken.
    Full,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JoinError {
    /// No such coroutine (exited and joined, never was), or detached, or joined by another.
    Invalid,
    /// Joining itself.
    Deadlock,
}

/// What a waiter is waiting for, for the queue's owner to match on (e.g. a futex's address and
/// bitset). Opaque to the scheduler.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct WaitTag {
    pub key: usize,
    pub mask: u32,
}

/// A FIFO of blocked coroutines, linked through the scheduler's table. It must stay where it is
/// while it has waiters (their slots point at it): keep it in a static or something pinned.
pub struct WaitQueue {
    head: Cell<u16>,
    tail: Cell<u16>,
}

impl WaitQueue {
    pub const fn new() -> Self {
        WaitQueue { head: Cell::new(NONE), tail: Cell::new(NONE) }
    }
    pub fn is_empty(&self) -> bool {
        self.head.get() == NONE
    }
}

impl Default for WaitQueue {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for WaitQueue {
    fn drop(&mut self) {
        // Waiters' slots would point at freed memory.
        debug_assert!(self.is_empty(), "WaitQueue dropped with waiters");
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    /// On the run queue.
    Ready,
    Running,
    Blocked,
    /// Exited, not yet joined (or, detached, not yet reclaimed: see `Sched::reap`).
    Zombie,
}

#[derive(Clone, Copy)]
enum Start {
    None,
    Rust(fn(usize) -> usize, usize),
    C(unsafe extern "C" fn(*mut c_void), *mut c_void),
    /// The copy on the coroutine's own stack (`context::place_registers`).
    Registers(*const Registers),
}

/// One coroutine.
struct Slot {
    ctx: UnsafeCell<Context>,
    state: Cell<State>,
    generation: Cell<u32>,
    stack_lo: Cell<usize>,
    stack_hi: Cell<usize>,
    start: Cell<Start>,
    /// Run-queue link, or free-list link while Free.
    run_next: Cell<u16>,
    /// The wait queue it is on, and its links there.
    wq: Cell<*const WaitQueue>,
    wq_prev: Cell<u16>,
    wq_next: Cell<u16>,
    tag: Cell<WaitTag>,
    /// Timer: absolute deadline, arming order (ties), place in the heap (NONE if not in it).
    deadline: Cell<u64>,
    seq: Cell<u64>,
    heap_pos: Cell<u16>,
    wake: Cell<Wake>,
    detached: Cell<bool>,
    joiner: Cell<u16>,
    exit: Cell<usize>,
    /// Threaded mode: the host-thread slot this coroutine runs on ([`NONE`]: unbound, runs on
    /// whichever host thread holds the CPU token). A program thread's coroutine is bound to its
    /// own host thread; LKL's kernel threads and timers stay unbound. Unused in coroutine mode.
    home: Cell<u16>,
    /// Threaded mode: the host-thread slot an unbound coroutine was last switched to on
    /// ([`Sched::par_context_switch`]), so runtime code on its stack can find its host thread
    /// ([`Sched::par_host_of_stack`]) without a register of its own (the GS base is the program's).
    on_host: Cell<u16>,
    tls: [Cell<usize>; TLS_KEYS],
}

impl Slot {
    const fn new() -> Slot {
        Slot {
            ctx: UnsafeCell::new(Context::empty()),
            state: Cell::new(State::Free),
            generation: Cell::new(0),
            stack_lo: Cell::new(0),
            stack_hi: Cell::new(0),
            start: Cell::new(Start::None),
            run_next: Cell::new(NONE),
            wq: Cell::new(core::ptr::null()),
            wq_prev: Cell::new(NONE),
            wq_next: Cell::new(NONE),
            tag: Cell::new(WaitTag { key: 0, mask: 0 }),
            deadline: Cell::new(0),
            seq: Cell::new(0),
            heap_pos: Cell::new(NONE),
            wake: Cell::new(Wake::Woken),
            detached: Cell::new(false),
            joiner: Cell::new(NONE),
            exit: Cell::new(0),
            home: Cell::new(NONE),
            on_host: Cell::new(NONE),
            tls: [const { Cell::new(0) }; TLS_KEYS],
        }
    }
}

/// The region coroutine stacks are carved from.
pub struct Stacks {
    pub base: *mut u8,
    pub len: usize,
    /// Each coroutine's stack, guard page included. A multiple of the page size.
    pub size: usize,
    /// Leave the lowest page of each stack unmapped (`mprotect(PROT_NONE)`), so an overflow faults
    /// instead of silently corrupting the coroutine below. Only while host `mprotect` is still
    /// allowed (before lockdown); it costs a page of each stack and splits the region into a
    /// mapping per stack (two VMAs each). Without it, stacks must be sized with margin: an
    /// overflow writes into the neighbour's stack.
    pub guard: bool,
}

pub struct Config {
    pub stacks: Stacks,
    /// Save and load the FS base on every switch (production: each program thread has its TLS).
    /// Off in tests inside std's harness, whose TLS must stay put.
    pub switch_fs: bool,
    pub host: &'static dyn Host,
}

/// The scheduler. Make one with [`Sched::new`] (const: a static works), then [`Sched::init`] it
/// from the host thread, which becomes the root coroutine.
pub struct Sched {
    slots: [Slot; CAPACITY],
    current: Cell<u16>,
    run_head: Cell<u16>,
    run_tail: Cell<u16>,
    free_head: Cell<u16>,
    /// Slots `fresh..fresh_end` were never used: not on the free list, their stacks not yet
    /// recorded in them. `stacks`: the region's base, each stack's size, and whether it has guards.
    fresh: Cell<u16>,
    fresh_end: Cell<u16>,
    stacks: Cell<(usize, usize, bool)>,
    heap: [Cell<u16>; CAPACITY],
    heap_len: Cell<usize>,
    seq: Cell<u64>,
    ticks: Cell<u32>,
    /// A detached coroutine that exited: freed by whoever runs next (its stack was in use until
    /// the switch away from it).
    reap: Cell<u16>,
    live: Cell<usize>,
    host: Cell<Option<&'static dyn Host>>,
    switch_fs: Cell<bool>,
    /// The root's FS base at init: what coroutines spawned with a function start with (LKL's
    /// kernel threads share the host thread's TLS).
    default_fs: Cell<usize>,
    tls_used: Cell<u32>,
    tls_dtors: [Cell<Option<unsafe extern "C" fn(*mut c_void)>>; TLS_KEYS],
    /// Threaded mode's driver ([`Par`]): when set, [`Sched::schedule`] delegates to it (a host
    /// thread per program thread, taking turns on one CPU token). `None` in coroutine mode.
    par: Cell<Option<&'static dyn Par>>,
}

/// Threaded mode's scheduler driver (`par`): the single hook [`Sched::schedule`] delegates to when
/// it is installed. It runs on the token holder, like coroutine mode's `schedule`, but switching to
/// a coroutine bound to another host thread becomes a CPU-token hand-off instead of a local switch.
/// It returns when the coroutine that called the blocking operation is running again.
pub trait Par: Sync {
    fn schedule(&self, s: &'static Sched);
}

// SAFETY: a Sched is used by one host thread at a time: in coroutine mode only ever one; threaded
// mode will hand a CPU token between host threads, so still one at a time. The impl lets it be a
// static (LKL's host ops reach it with no argument).
unsafe impl Sync for Sched {}

impl Default for Sched {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sched {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sched").field("live", &self.live.get()).finish_non_exhaustive()
    }
}

/// The first code of every coroutine the scheduler starts (`arg` is the `Sched`).
extern "C" fn coroutine_entry(sched: usize) -> ! {
    // SAFETY: spawn passed `&'static Sched`.
    let s = unsafe { &*(sched as *const Sched) };
    s.after_switch();
    let me = s.current.get() as usize;
    match s.slots[me].start.get() {
        Start::Rust(f, arg) => {
            let v = f(arg);
            s.exit(v)
        }
        Start::C(f, arg) => {
            // SAFETY: the spawner vouched for f.
            unsafe { f(arg) };
            s.exit(0)
        }
        // SAFETY: spawn_registers placed it, and vouched it can run.
        Start::Registers(regs) => unsafe { context::restore(regs) },
        Start::None => unreachable!("coroutine started without an entry"),
    }
}

impl Sched {
    pub const fn new() -> Self {
        Sched {
            slots: [const { Slot::new() }; CAPACITY],
            current: Cell::new(ROOT),
            run_head: Cell::new(NONE),
            run_tail: Cell::new(NONE),
            free_head: Cell::new(NONE),
            fresh: Cell::new(1),
            fresh_end: Cell::new(1),
            stacks: Cell::new((0, 0, false)),
            heap: [const { Cell::new(NONE) }; CAPACITY],
            heap_len: Cell::new(0),
            seq: Cell::new(0),
            ticks: Cell::new(0),
            reap: Cell::new(NONE),
            live: Cell::new(0),
            host: Cell::new(None),
            switch_fs: Cell::new(false),
            default_fs: Cell::new(0),
            tls_used: Cell::new(0),
            tls_dtors: [const { Cell::new(None) }; TLS_KEYS],
            par: Cell::new(None),
        }
    }

    /// Make the calling host thread the root coroutine and carve the stacks. Returns how many
    /// coroutines (besides the root) can exist at once: `min(len / size, CAPACITY - 1)`.
    ///
    /// # Safety
    /// `cfg.stacks` is memory this scheduler owns from now on, readable and writable, page-aligned
    /// if `guard`. Called once, on the host thread that will run the coroutines.
    pub unsafe fn init(&'static self, cfg: Config) -> rustix::io::Result<usize> {
        assert!(self.host.get().is_none(), "Sched::init twice");
        let st = &cfg.stacks;
        assert!(st.size.is_multiple_of(PAGE) && st.size >= 2 * PAGE, "stack size {:#x}", st.size);
        assert!(!st.guard || (st.base as usize).is_multiple_of(PAGE), "unaligned stack region");
        self.host.set(Some(cfg.host));
        self.switch_fs.set(cfg.switch_fs);
        let fs = if cfg.switch_fs { context::read_fs() } else { 0 };
        self.default_fs.set(fs);
        let root = &self.slots[ROOT as usize];
        root.state.set(State::Running);
        root.generation.set(1);
        // SAFETY: not running anywhere else; the switch away from the root fills it in.
        unsafe { (*root.ctx.get()).set_fs(fs) };
        self.current.set(ROOT);
        self.live.set(1);
        let n = (st.len / st.size).min(CAPACITY - 1);
        // The guards now (no host mprotect after lockdown); the slots when first spawned
        // (`fresh`), in table order: the table is in .data, and writing every slot here made all
        // of it private to each sandbox, though it runs a few dozen coroutines.
        if st.guard {
            for i in 0..n {
                // SAFETY: the caller gave us the region.
                unsafe {
                    rustix::mm::mprotect((st.base as usize + i * st.size) as *mut c_void, PAGE, rustix::mm::MprotectFlags::empty())?
                };
            }
        }
        self.stacks.set((st.base as usize, st.size, st.guard));
        self.fresh.set(1);
        self.fresh_end.set(n as u16 + 1);
        Ok(n)
    }

    fn host(&self) -> &'static dyn Host {
        self.host.get().expect("Sched not initialized")
    }

    /// CLOCK_MONOTONIC ns, from the host hook.
    pub fn now(&self) -> u64 {
        self.host().monotonic()
    }

    /// CLOCK_REALTIME ns, from the host hook.
    pub fn realtime(&self) -> u64 {
        self.host().realtime()
    }

    pub fn current(&self) -> Tid {
        let i = self.current.get();
        Tid::new(i, self.slots[i as usize].generation.get())
    }

    /// The current coroutine's usable stack: (lowest address, size). The root's is unknown: (0, 0).
    pub fn stack(&self) -> (usize, usize) {
        let s = &self.slots[self.current.get() as usize];
        (s.stack_lo.get(), s.stack_hi.get() - s.stack_lo.get())
    }

    /// Coroutines alive (not freed), the root included.
    pub fn live_count(&self) -> usize {
        self.live.get()
    }

    /// Call `f` with every live coroutine (the table is the list of all coroutines: a freed slot
    /// can't be on it, unlike capnix's separate list, which once kept freed coroutines).
    pub fn for_each_live(&self, mut f: impl FnMut(Tid)) {
        for (i, s) in self.slots.iter().enumerate() {
            if s.state.get() != State::Free {
                f(Tid::new(i as u16, s.generation.get()));
            }
        }
    }

    /// Whether `tid` names a coroutine that hasn't been reclaimed (it may have exited, unjoined).
    pub fn is_alive(&self, tid: Tid) -> bool {
        self.lookup(tid).is_some()
    }

    fn lookup(&self, tid: Tid) -> Option<u16> {
        let i = tid.idx();
        let s = self.slots.get(i)?;
        (s.state.get() != State::Free && s.generation.get() == tid.generation()).then_some(i as u16)
    }

    // ---- spawning ----

    /// A coroutine running `f(arg)`; its return value is its exit value. Runnable, at the run
    /// queue's tail.
    pub fn spawn(&'static self, f: fn(usize) -> usize, arg: usize) -> Result<Tid, SpawnError> {
        self.spawn_start(Start::Rust(f, arg), None, self.default_fs.get())
    }

    /// A coroutine running a C function (LKL's `thread_create`); exit value 0.
    ///
    /// # Safety
    /// `f(arg)` is safe to call on a fresh coroutine.
    pub unsafe fn spawn_c(
        &'static self,
        f: unsafe extern "C" fn(*mut c_void),
        arg: *mut c_void,
    ) -> Result<Tid, SpawnError> {
        self.spawn_start(Start::C(f, arg), None, self.default_fs.get())
    }

    /// A coroutine that resumes a program thread at `regs` with FS base `fs` (after a `clone`).
    /// The coroutine's own stack is its control stack (the scheduler's code and, later, the
    /// syscalls it serves run there); the program runs on `regs.rsp`. It never returns to the
    /// scheduler's entry: it ends with [`Sched::exit`] from a served `exit`.
    ///
    /// # Safety
    /// `regs` is a state the program can run from.
    pub unsafe fn spawn_registers(&'static self, regs: &Registers, fs: usize) -> Result<Tid, SpawnError> {
        self.spawn_start(Start::None, Some(regs), fs)
    }

    /// A free slot: from the free list, else one never used yet (whose stack is carved now). Every
    /// allocation goes through here, so slots are only written when first used.
    fn take_slot(&self) -> Result<u16, SpawnError> {
        let i = self.free_head.get();
        if i != NONE {
            self.free_head.set(self.slots[i as usize].run_next.get());
            return Ok(i);
        }
        let i = self.fresh.get();
        if i == self.fresh_end.get() {
            return Err(SpawnError::Full);
        }
        self.fresh.set(i + 1);
        let (base, size, guard) = self.stacks.get();
        let lo = base + (i as usize - 1) * size;
        let s = &self.slots[i as usize];
        s.stack_lo.set(if guard { lo + PAGE } else { lo });
        s.stack_hi.set(lo + size);
        Ok(i)
    }

    fn spawn_start(&'static self, start: Start, regs: Option<&Registers>, fs: usize) -> Result<Tid, SpawnError> {
        let i = self.take_slot()?;
        let s = &self.slots[i as usize];
        // Generation 0 is never used, so a Tid is never 0.
        let g = s.generation.get().wrapping_add(1).max(1);
        s.generation.set(g);
        let mut top = s.stack_hi.get();
        let start = match regs {
            Some(r) => {
                // SAFETY: the slot's stack is free (it was on the free list).
                let at = unsafe { context::place_registers(top, r) };
                top = at as usize;
                Start::Registers(at)
            }
            None => start,
        };
        s.start.set(start);
        // SAFETY: as above; nothing runs on this stack.
        unsafe { *s.ctx.get() = Context::new(top, coroutine_entry, self as *const Sched as usize, fs) };
        self.live.set(self.live.get() + 1);
        self.make_ready(i);
        Ok(Tid::new(i, g))
    }

    // ---- the run queue and switching ----

    fn make_ready(&self, i: u16) {
        let s = &self.slots[i as usize];
        s.state.set(State::Ready);
        s.run_next.set(NONE);
        match self.run_tail.get() {
            NONE => self.run_head.set(i),
            t => self.slots[t as usize].run_next.set(i),
        }
        self.run_tail.set(i);
    }

    fn pop_ready(&self) -> u16 {
        let i = self.run_head.get();
        if i != NONE {
            let n = self.slots[i as usize].run_next.get();
            self.run_head.set(n);
            if n == NONE {
                self.run_tail.set(NONE);
            }
        }
        i
    }

    /// Run the next runnable coroutine. The caller has already set the current one's state (on
    /// the run queue, blocked, exited). Returns when the current coroutine runs again.
    fn schedule(&self) {
        if let Some(par) = self.par.get() {
            // SAFETY: a Sched that has a `par` installed is the `&'static` one (install_par takes
            // `&'static self`); the driver only ever runs on it.
            let s: &'static Sched = unsafe { &*(self as *const Sched) };
            par.schedule(s);
            return;
        }
        loop {
            self.expire_timers(self.run_head.get() == NONE);
            let next = self.pop_ready();
            if next != NONE {
                self.switch_to(next);
                return;
            }
            let deadline = (self.heap_len.get() > 0).then(|| self.slots[self.heap[0].get() as usize].deadline.get());
            self.host().idle(deadline);
        }
    }

    // ---- threaded mode (par) ----

    /// Install the threaded-mode driver; [`Sched::schedule`] delegates to it from now on. Once.
    pub fn install_par(&'static self, par: &'static dyn Par) {
        assert!(self.par.get().is_none(), "install_par twice");
        self.par.set(Some(par));
    }

    /// The current coroutine's slot index (threaded mode's host records key on it).
    pub fn current_raw(&self) -> Tid {
        self.current()
    }

    /// Bind `tid` to host-thread slot `home` (threaded mode): its coroutine runs only on that
    /// host thread. `home == NONE` (`u16::MAX`) leaves it unbound.
    pub fn bind(&self, tid: Tid, home: u16) {
        if let Some(i) = self.lookup(tid) {
            self.slots[i as usize].home.set(home);
        }
    }

    /// Make `current` bound to `home` (for the main thread and newly started program threads,
    /// which set their own binding).
    pub fn bind_current(&self, home: u16) {
        self.slots[self.current.get() as usize].home.set(home);
    }

    /// A coroutine running `par_loop(arg)` that is **not** placed on the run queue: threaded mode's
    /// per-host scheduler coroutine, entered only by explicit [`Sched::par_switch`]. Bound to
    /// `home` so nothing else runs it.
    pub fn spawn_sched_loop(&'static self, f: fn(usize) -> usize, arg: usize, home: u16, fs: usize) -> Result<Tid, SpawnError> {
        let i = self.take_slot()?;
        let s = &self.slots[i as usize];
        let g = s.generation.get().wrapping_add(1).max(1);
        s.generation.set(g);
        s.home.set(home);
        s.start.set(Start::Rust(f, arg));
        // SAFETY: the slot's stack is free (it was on the free list); nothing runs on it.
        unsafe { *s.ctx.get() = Context::new(s.stack_hi.get(), coroutine_entry, self as *const Sched as usize, fs) };
        s.state.set(State::Blocked); // off the run queue; only par_switch enters it
        self.live.set(self.live.get() + 1);
        Ok(Tid::new(i, g))
    }

    /// Switch to `tid` (threaded mode: the driver's explicit switch, between a coroutine and its
    /// host's scheduler coroutine, or to a runnable coroutine the holder may run).
    pub fn par_switch(&self, tid: Tid) {
        if let Some(i) = self.lookup(tid) {
            self.switch_to(i);
        }
    }

    /// Switch from `from` to `to` (threaded mode: the host thread tracks its own running coroutine,
    /// since the shared `current` is set by whichever host last held the token).
    pub fn par_context_switch(&self, from: Tid, to: Tid) {
        if let (Some(f), Some(t)) = (self.lookup(from), self.lookup(to)) {
            // `to` runs on the host thread `from` is running on.
            let h = self.host_of(f);
            self.slots[t as usize].on_host.set(h);
            self.do_switch(f, t);
        }
    }

    /// The host-thread slot coroutine `i` runs on: its binding, else where it was last switched to.
    fn host_of(&self, i: u16) -> u16 {
        let s = &self.slots[i as usize];
        if s.home.get() != NONE { s.home.get() } else { s.on_host.get() }
    }

    /// Threaded mode: the host-thread slot running the coroutine whose stack holds `sp`, if `sp`
    /// is in the coroutines' stack region (a subtraction and a divide: the stacks are carved in
    /// order, slot `i`'s at `base + (i - 1) * size`). `None` outside it (a host thread's own
    /// stack), or for a coroutine never switched to.
    pub fn par_host_of_stack(&self, sp: usize) -> Option<u16> {
        let (base, size, _) = self.stacks.get();
        if size == 0 {
            return None;
        }
        let i = sp.wrapping_sub(base) / size + 1;
        if i >= self.fresh.get() as usize {
            return None;
        }
        let h = self.host_of(i as u16);
        (h != NONE).then_some(h)
    }

    /// Make `tid` the current coroutine without a switch: threaded mode, when a host thread takes
    /// the token to serve a trap on its bound coroutine (already running on its control stack).
    pub fn par_set_current(&self, tid: Tid) {
        if let Some(i) = self.lookup(tid) {
            self.slots[i as usize].state.set(State::Running);
            self.current.set(i);
        }
    }

    /// A "root-like" coroutine bound to host `home`: a control stack but no entry, entered by a
    /// trap (not a switch), its context filled when it first blocks. For a lazy program thread,
    /// which runs user code on its own host thread and needs a Sched task only for its traps.
    pub fn adopt_root(&self, home: u16) -> Result<Tid, SpawnError> {
        let i = self.take_slot()?;
        let s = &self.slots[i as usize];
        let g = s.generation.get().wrapping_add(1).max(1);
        s.generation.set(g);
        s.home.set(home);
        s.start.set(Start::None);
        s.state.set(State::Blocked); // off the run queue until a trap makes it current
        // SAFETY: the slot's stack is free; its context is filled by the first switch away.
        unsafe { *s.ctx.get() = Context::empty() };
        self.live.set(self.live.get() + 1);
        Ok(Tid::new(i, g))
    }

    /// Free an adopted (or sched-loop) coroutine that never ran (threaded mode, on a spawn
    /// failure).
    pub fn drop_adopted(&self, tid: Tid) {
        if let Some(i) = self.lookup(tid) {
            self.free_slot(i);
        }
    }

    /// A coroutine's control stack `[lo, hi)` (threaded mode: where its traps' frames go).
    pub fn stack_of(&self, tid: Tid) -> (usize, usize) {
        match self.lookup(tid) {
            Some(i) => (self.slots[i as usize].stack_lo.get(), self.slots[i as usize].stack_hi.get()),
            None => (0, 0),
        }
    }

    /// Pop the first runnable coroutine that `host` may run (unbound, or bound to `host`), off the
    /// run queue. Coroutines bound to other host threads are left in place for their own host.
    pub fn par_pick(&self, host: u16) -> Option<Tid> {
        let mut prev = NONE;
        let mut i = self.run_head.get();
        while i != NONE {
            let next = self.slots[i as usize].run_next.get();
            let home = self.slots[i as usize].home.get();
            if home == NONE || home == host {
                // Unlink i.
                if prev == NONE {
                    self.run_head.set(next);
                } else {
                    self.slots[prev as usize].run_next.set(next);
                }
                if self.run_tail.get() == i {
                    self.run_tail.set(prev);
                }
                return Some(Tid::new(i, self.slots[i as usize].generation.get()));
            }
            prev = i;
            i = next;
        }
        None
    }

    /// The home of the first runnable coroutine bound to a host other than `host` (the CPU token's
    /// directed hand-off target), or `None`.
    pub fn par_bound_elsewhere(&self, host: u16) -> Option<u16> {
        let mut i = self.run_head.get();
        while i != NONE {
            let home = self.slots[i as usize].home.get();
            if home != NONE && home != host {
                return Some(home);
            }
            i = self.slots[i as usize].run_next.get();
        }
        None
    }

    /// Whether a runnable coroutine is bound to no host (threaded mode: the kernel thread can run
    /// it).
    pub fn par_unbound_ready(&self) -> bool {
        let mut i = self.run_head.get();
        while i != NONE {
            if self.slots[i as usize].home.get() == NONE {
                return true;
            }
            i = self.slots[i as usize].run_next.get();
        }
        false
    }

    /// Fire due timers (threaded mode drives this from the token holder's idle).
    pub fn par_expire(&self, force: bool) {
        self.expire_timers(force);
    }

    /// The earliest armed timer deadline (CLOCK_MONOTONIC ns), or `None`.
    pub fn par_next_deadline(&self) -> Option<u64> {
        (self.heap_len.get() > 0).then(|| self.slots[self.heap[0].get() as usize].deadline.get())
    }

    fn switch_to(&self, next: u16) {
        self.do_switch(self.current.get(), next);
    }

    /// Switch from `prev` to `next`, saving `prev`'s context and running `next`. `prev` is the
    /// coroutine actually running (coroutine mode: always `current`; threaded mode: the host
    /// thread's own running coroutine, passed explicitly).
    fn do_switch(&self, prev: u16, next: u16) {
        self.slots[next as usize].state.set(State::Running);
        if next == prev {
            return;
        }
        self.current.set(next);
        let from = self.slots[prev as usize].ctx.get();
        let to = self.slots[next as usize].ctx.get();
        // SAFETY: `next` was suspended by a switch or freshly made; `prev` is us.
        unsafe {
            if self.switch_fs.get() {
                context::switch_fs(from, to)
            } else {
                context::switch(from, to)
            }
        }
        self.after_switch();
    }

    /// Run on every coroutine's resumption: reclaim a detached coroutine that just switched away
    /// for the last time. (Reclaiming it before the switch would let anything that spawns in
    /// between, such as the idle hook, build a frame on the stack still in use.)
    fn after_switch(&self) {
        let r = self.reap.replace(NONE);
        if r != NONE {
            self.free_slot(r);
        }
    }

    fn free_slot(&self, i: u16) {
        let s = &self.slots[i as usize];
        debug_assert!(s.heap_pos.get() == NONE && s.wq.get().is_null());
        s.state.set(State::Free);
        s.start.set(Start::None);
        s.detached.set(false);
        s.joiner.set(NONE);
        s.exit.set(0);
        for v in &s.tls {
            v.set(0);
        }
        s.run_next.set(self.free_head.get());
        self.free_head.set(i);
        self.live.set(self.live.get() - 1);
    }

    /// Let every other runnable coroutine run once, then continue.
    pub fn yield_now(&self) {
        self.make_ready(self.current.get());
        self.schedule();
    }

    /// Block the current coroutine until [`Sched::wake`] or, if given, the CLOCK_MONOTONIC
    /// `deadline` (`u64::MAX`: none; a saturated "never" must not become a deadline in the past).
    pub fn block(&self, deadline: Option<u64>) -> Wake {
        let i = self.current.get();
        let s = &self.slots[i as usize];
        s.state.set(State::Blocked);
        s.wake.set(Wake::Woken);
        if let Some(d) = deadline.filter(|&d| d != u64::MAX) {
            self.heap_insert(i, d);
        }
        self.schedule();
        s.wake.get()
    }

    /// Sleep until `deadline` (CLOCK_MONOTONIC ns), or until woken.
    pub fn sleep_until(&self, deadline: u64) -> Wake {
        self.block(Some(deadline))
    }

    /// Make a blocked coroutine runnable. If it was on a wait queue it leaves it, with
    /// [`Wake::Interrupted`]. Returns false (and does nothing) if it isn't blocked.
    pub fn wake(&self, tid: Tid) -> bool {
        match self.lookup(tid) {
            Some(i) if self.slots[i as usize].state.get() == State::Blocked => {
                let why = if self.slots[i as usize].wq.get().is_null() { Wake::Woken } else { Wake::Interrupted };
                self.resume(i, why);
                true
            }
            _ => false,
        }
    }

    /// Blocked → runnable, leaving its timer and wait queue.
    fn resume(&self, i: u16, why: Wake) {
        let s = &self.slots[i as usize];
        debug_assert_eq!(s.state.get(), State::Blocked);
        self.heap_remove(i);
        if !s.wq.get().is_null() {
            self.unlink(i);
        }
        s.wake.set(why);
        self.make_ready(i);
    }

    // ---- exit and join ----

    /// End the current coroutine with `value` (for [`Sched::join`]). Runs its TLS destructors.
    /// The root can't exit (it is the host thread).
    pub fn exit(&self, value: usize) -> ! {
        let i = self.current.get();
        assert!(i != ROOT, "the root coroutine can't exit");
        self.run_tls_destructors(i);
        let s = &self.slots[i as usize];
        s.exit.set(value);
        s.state.set(State::Zombie);
        if s.detached.get() {
            self.reap.set(i);
        } else {
            let j = s.joiner.replace(NONE);
            if j != NONE && self.slots[j as usize].state.get() == State::Blocked {
                self.resume(j, Wake::Woken);
            }
        }
        self.schedule();
        unreachable!("an exited coroutine was resumed")
    }

    /// Wait for `tid` to exit and reclaim it; its exit value.
    pub fn join(&self, tid: Tid) -> Result<usize, JoinError> {
        let i = self.lookup(tid).ok_or(JoinError::Invalid)?;
        let me = self.current.get();
        if i == me {
            return Err(JoinError::Deadlock);
        }
        let s = &self.slots[i as usize];
        let j = s.joiner.get();
        if s.detached.get() || (j != NONE && j != me) {
            return Err(JoinError::Invalid);
        }
        while s.state.get() != State::Zombie {
            s.joiner.set(me);
            self.block(None);
        }
        let v = s.exit.get();
        self.free_slot(i);
        Ok(v)
    }

    /// Nobody will join `tid`: reclaim it when it exits (now, if it has). LKL's `thread_detach`
    /// detaches the current coroutine.
    pub fn detach(&self, tid: Tid) -> Result<(), JoinError> {
        let i = self.lookup(tid).ok_or(JoinError::Invalid)?;
        let s = &self.slots[i as usize];
        if s.detached.get() || s.joiner.get() != NONE {
            return Err(JoinError::Invalid);
        }
        if s.state.get() == State::Zombie {
            self.free_slot(i);
        } else {
            s.detached.set(true);
        }
        Ok(())
    }

    // ---- wait queues ----

    /// Block the current coroutine on `q` (at its tail), tagged `tag`, until woken through `q`,
    /// interrupted ([`Sched::wake`]), or the deadline. It is off `q` when this returns.
    pub fn wait(&self, q: &WaitQueue, tag: WaitTag, deadline: Option<u64>) -> Wake {
        let i = self.current.get();
        let s = &self.slots[i as usize];
        s.tag.set(tag);
        s.wq.set(q);
        s.wq_next.set(NONE);
        s.wq_prev.set(q.tail.get());
        match q.tail.get() {
            NONE => q.head.set(i),
            t => self.slots[t as usize].wq_next.set(i),
        }
        q.tail.set(i);
        self.block(deadline)
    }

    fn unlink(&self, i: u16) {
        let s = &self.slots[i as usize];
        // SAFETY: a queue with waiters stays put (WaitQueue's contract).
        let q = unsafe { &*s.wq.get() };
        let (p, n) = (s.wq_prev.get(), s.wq_next.get());
        match p {
            NONE => q.head.set(n),
            p => self.slots[p as usize].wq_next.set(n),
        }
        match n {
            NONE => q.tail.set(p),
            n => self.slots[n as usize].wq_prev.set(p),
        }
        s.wq.set(core::ptr::null());
        s.wq_prev.set(NONE);
        s.wq_next.set(NONE);
    }

    /// Wake the first waiter on `q`; who it was.
    pub fn wake_one(&self, q: &WaitQueue) -> Option<Tid> {
        let i = q.head.get();
        if i == NONE {
            return None;
        }
        self.resume(i, Wake::Woken);
        Some(Tid::new(i, self.slots[i as usize].generation.get()))
    }

    /// Wake, in queue order, up to `max` waiters on `q` whose tag `matches`; how many.
    pub fn wake_where(&self, q: &WaitQueue, max: usize, mut matches: impl FnMut(WaitTag) -> bool) -> usize {
        let mut n = 0;
        let mut i = q.head.get();
        while i != NONE && n < max {
            let next = self.slots[i as usize].wq_next.get();
            if matches(self.slots[i as usize].tag.get()) {
                self.resume(i, Wake::Woken);
                n += 1;
            }
            i = next;
        }
        n
    }

    // ---- timers: a min-heap of (deadline, seq) over slot indices ----

    fn earlier(&self, a: u16, b: u16) -> bool {
        let (a, b) = (&self.slots[a as usize], &self.slots[b as usize]);
        (a.deadline.get(), a.seq.get()) < (b.deadline.get(), b.seq.get())
    }

    fn heap_set(&self, pos: usize, i: u16) {
        self.heap[pos].set(i);
        self.slots[i as usize].heap_pos.set(pos as u16);
    }

    fn heap_insert(&self, i: u16, deadline: u64) {
        let s = &self.slots[i as usize];
        debug_assert_eq!(s.heap_pos.get(), NONE);
        s.deadline.set(deadline);
        let seq = self.seq.get();
        self.seq.set(seq + 1);
        s.seq.set(seq);
        let pos = self.heap_len.get();
        self.heap_len.set(pos + 1);
        self.heap_set(pos, i);
        self.sift_up(pos);
    }

    fn heap_remove(&self, i: u16) {
        let pos = self.slots[i as usize].heap_pos.replace(NONE);
        if pos == NONE {
            return;
        }
        let pos = pos as usize;
        let last = self.heap_len.get() - 1;
        self.heap_len.set(last);
        if pos != last {
            self.heap_set(pos, self.heap[last].get());
            self.sift_down(pos);
            self.sift_up(pos);
        }
    }

    fn sift_up(&self, mut pos: usize) {
        while pos > 0 {
            let parent = (pos - 1) / 2;
            let (c, p) = (self.heap[pos].get(), self.heap[parent].get());
            if !self.earlier(c, p) {
                break;
            }
            self.heap_set(pos, p);
            self.heap_set(parent, c);
            pos = parent;
        }
    }

    fn sift_down(&self, mut pos: usize) {
        let len = self.heap_len.get();
        loop {
            let (l, r) = (2 * pos + 1, 2 * pos + 2);
            let mut m = pos;
            if l < len && self.earlier(self.heap[l].get(), self.heap[m].get()) {
                m = l;
            }
            if r < len && self.earlier(self.heap[r].get(), self.heap[m].get()) {
                m = r;
            }
            if m == pos {
                break;
            }
            let (a, b) = (self.heap[pos].get(), self.heap[m].get());
            self.heap_set(pos, b);
            self.heap_set(m, a);
            pos = m;
        }
    }

    /// Wake every coroutine whose deadline has passed. Unless `force`, only every
    /// TIMER_CHECK_EVERY calls (see there).
    fn expire_timers(&self, force: bool) {
        if self.heap_len.get() == 0 {
            return;
        }
        if !force {
            let t = self.ticks.get() + 1;
            if t < TIMER_CHECK_EVERY {
                self.ticks.set(t);
                return;
            }
        }
        self.ticks.set(0);
        let now = self.now();
        while self.heap_len.get() > 0 {
            let i = self.heap[0].get();
            if self.slots[i as usize].deadline.get() > now {
                break;
            }
            self.resume(i, Wake::TimedOut);
        }
    }

    // ---- TLS: per-coroutine slots (the key API is sync::TlsKey) ----

    pub(crate) fn tls_alloc(&self, dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> Option<usize> {
        let used = self.tls_used.get();
        let k = (!used).trailing_zeros() as usize;
        if k >= TLS_KEYS {
            return None;
        }
        self.tls_used.set(used | 1 << k);
        self.tls_dtors[k].set(dtor);
        // A key freed and allocated again starts empty everywhere, not with the old key's values.
        // Only nonzero values are written: the table is in .data, and writing every slot's made
        // all 260 KB of it private to each sandbox at boot, where reading leaves it shared.
        for s in &self.slots {
            if s.tls[k].get() != 0 {
                s.tls[k].set(0);
            }
        }
        Some(k)
    }

    pub(crate) fn tls_free(&self, k: usize) {
        self.tls_used.set(self.tls_used.get() & !(1 << k));
        self.tls_dtors[k].set(None);
    }

    pub(crate) fn tls_get(&self, k: usize) -> usize {
        self.slots[self.current.get() as usize].tls[k].get()
    }

    pub(crate) fn tls_set(&self, k: usize, v: usize) {
        self.slots[self.current.get() as usize].tls[k].set(v);
    }

    fn run_tls_destructors(&self, i: u16) {
        let s = &self.slots[i as usize];
        for _ in 0..TLS_DESTRUCTOR_ROUNDS {
            let mut ran = false;
            for k in 0..TLS_KEYS {
                let v = s.tls[k].get();
                if v == 0 || self.tls_used.get() & (1 << k) == 0 {
                    continue;
                }
                if let Some(d) = self.tls_dtors[k].get() {
                    s.tls[k].set(0);
                    // SAFETY: the key's owner registered it for exactly this.
                    unsafe { d(v as *mut c_void) };
                    ran = true;
                }
            }
            if !ran {
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeClock, RealClock, new_sched};
    use std::cell::RefCell;
    use std::time::Instant;

    #[test]
    fn hundreds_interleave_fifo() {
        struct T {
            s: &'static Sched,
            log: RefCell<Vec<(usize, usize)>>,
        }
        const N: usize = 300;
        const ROUNDS: usize = 5;
        fn body(p: usize) -> usize {
            let (t, id) = unsafe { &*(p as *const (&'static T, usize)) };
            for r in 0..ROUNDS {
                t.log.borrow_mut().push((r, *id));
                t.s.yield_now();
            }
            *id
        }
        let s = new_sched(N + 1, FakeClock::leak());
        let t: &'static T = Box::leak(Box::new(T { s, log: RefCell::new(Vec::new()) }));
        let args: Vec<(&'static T, usize)> = (0..N).map(|i| (t, i)).collect();
        let args = Box::leak(args.into_boxed_slice());
        let tids: Vec<Tid> = args.iter().map(|a| s.spawn(body, a as *const _ as usize).unwrap()).collect();
        for (i, tid) in tids.iter().enumerate() {
            assert_eq!(s.join(*tid), Ok(i));
        }
        let want: Vec<(usize, usize)> = (0..ROUNDS).flat_map(|r| (0..N).map(move |i| (r, i))).collect();
        assert_eq!(*t.log.borrow(), want);
        assert_eq!(s.live_count(), 1);
    }

    #[test]
    fn yield_ping_pong_a_million() {
        fn body(p: usize) -> usize {
            let s = unsafe { &*(p as *const Sched) };
            for _ in 0..500_000 {
                s.yield_now();
            }
            0
        }
        let s = new_sched(2, FakeClock::leak());
        let a = s.spawn(body, s as *const _ as usize).unwrap();
        let b = s.spawn(body, s as *const _ as usize).unwrap();
        let t = Instant::now();
        s.join(a).unwrap();
        s.join(b).unwrap();
        let el = t.elapsed();
        println!("yield (switch + run queue): {:.1} ns", el.as_nanos() as f64 / 1e6);
        assert!(el.as_secs() < 3, "{el:?}");
    }

    #[test]
    fn exit_values_and_join() {
        fn early(p: usize) -> usize {
            let s = unsafe { &*(p as *const Sched) };
            s.yield_now();
            s.exit(7)
        }
        fn returns(_: usize) -> usize {
            9
        }
        let s = new_sched(4, FakeClock::leak());
        let a = s.spawn(early, s as *const _ as usize).unwrap();
        let b = s.spawn(returns, 0).unwrap();
        // b exits before it is joined: a zombie until then.
        s.yield_now();
        s.yield_now();
        assert!(s.is_alive(b));
        assert_eq!(s.join(b), Ok(9));
        assert_eq!(s.join(a), Ok(7));
        assert_eq!(s.join(a), Err(JoinError::Invalid), "joined twice");
        assert_eq!(s.join(s.current()), Err(JoinError::Deadlock));
        assert_eq!(s.live_count(), 1);
    }

    #[test]
    fn churn_beyond_capacity_frees_cleanly() {
        fn quick(v: usize) -> usize {
            v
        }
        fn detach_self(p: usize) -> usize {
            let s = unsafe { &*(p as *const Sched) };
            s.detach(s.current()).unwrap();
            s.yield_now();
            0
        }
        let s = new_sched(CAPACITY, FakeClock::leak());
        let cap = CAPACITY - 1;
        let mut stale = Vec::new();
        for round in 0..3 {
            // Fill the table: joinable and self-detaching coroutines, alternately.
            let tids: Vec<Tid> = (0..cap)
                .map(|i| {
                    if i % 2 == 0 {
                        s.spawn(quick, i).unwrap()
                    } else {
                        s.spawn(detach_self, s as *const _ as usize).unwrap()
                    }
                })
                .collect();
            assert_eq!(s.spawn(quick, 0), Err(SpawnError::Full));
            assert_eq!(s.live_count(), cap + 1);
            for (i, t) in tids.iter().enumerate() {
                if i % 2 == 0 {
                    assert_eq!(s.join(*t), Ok(i), "round {round}");
                }
            }
            // Let the detached ones finish: one more pass, then one to reap the last.
            s.yield_now();
            s.yield_now();
            // Only the root is left; nothing freed is listed.
            let mut listed = Vec::new();
            s.for_each_live(|t| listed.push(t));
            assert_eq!(listed, vec![s.current()], "round {round}");
            assert_eq!(s.live_count(), 1);
            for t in &stale {
                assert!(!s.is_alive(*t), "a stale id names a new coroutine");
            }
            stale = tids;
        }
    }

    #[test]
    fn many_deadlines_fire_in_order() {
        struct T {
            s: &'static Sched,
            order: RefCell<Vec<u64>>,
        }
        fn sleeper(p: usize) -> usize {
            let (t, d) = unsafe { &*(p as *const (&'static T, u64)) };
            assert_eq!(t.s.sleep_until(*d), Wake::TimedOut);
            assert!(t.s.now() >= *d);
            t.order.borrow_mut().push(*d);
            0
        }
        let clock = FakeClock::leak();
        let s = new_sched(300, clock);
        let t: &'static T = Box::leak(Box::new(T { s, order: RefCell::new(Vec::new()) }));
        // Deadlines in a scrambled order, with duplicates (ties fire in arming order).
        let ds: Vec<u64> = (0..256u64).map(|i| 1_000 + (i * 7919) % 200).collect();
        let args: &'static [(&'static T, u64)] = Box::leak(ds.iter().map(|&d| (t, d)).collect());
        let tids: Vec<Tid> = args.iter().map(|a| s.spawn(sleeper, a as *const _ as usize).unwrap()).collect();
        for tid in tids {
            s.join(tid).unwrap();
        }
        let mut sorted = ds.clone();
        sorted.sort();
        assert_eq!(*t.order.borrow(), sorted);
        // The fake clock only moves in idle: one idle per distinct deadline, no spinning.
        assert_eq!(clock.idles(), 200);
    }

    #[test]
    fn real_clock_sleep() {
        let clock = RealClock::leak();
        let s = new_sched(1, clock);
        let t = Instant::now();
        assert_eq!(s.sleep_until(s.now() + 2_000_000), Wake::TimedOut);
        assert!(t.elapsed().as_micros() >= 2000);
    }

    #[test]
    fn wake_beats_deadline() {
        fn sleeper(p: usize) -> usize {
            let s = unsafe { &*(p as *const Sched) };
            match s.sleep_until(1_000_000) {
                Wake::Woken => 1,
                _ => 0,
            }
        }
        let clock = FakeClock::leak();
        let s = new_sched(1, clock);
        let a = s.spawn(sleeper, s as *const _ as usize).unwrap();
        s.yield_now();
        assert!(s.wake(a));
        assert!(!s.wake(a), "not blocked any more");
        assert_eq!(s.join(a), Ok(1));
        assert_eq!(clock.now_ns(), 0, "the clock never had to move");
    }

    #[test]
    fn guard_pages_are_unmapped() {
        let s = crate::testutil::new_sched_guarded(4, FakeClock::leak());
        fn ret(_: usize) -> usize {
            3
        }
        let a = s.spawn(ret, 0).unwrap();
        assert_eq!(s.join(a), Ok(3));
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let lo = s.slots[1].stack_lo.get() - PAGE;
        let line = maps
            .lines()
            .find(|l| usize::from_str_radix(l.split('-').next().unwrap(), 16).unwrap() == lo)
            .expect("the guard page starts a mapping");
        assert!(line.contains("---p"), "{line}");
    }
}
