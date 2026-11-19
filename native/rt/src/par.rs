//! Threaded mode: a host thread per program thread, one guest CPU passed between them.
//!
//! Coroutine mode runs every program and kernel thread as a coroutine on one host thread. Threaded
//! mode keeps the same scheduler ([`Sched`]) and host operations, but program code runs on a host
//! thread of its own, in parallel, and the kernel (LKL, the scheduler, the futexes, the arena) is
//! guarded by a single **CPU token**: only the host thread holding it may touch that shared state.
//!
//! - **Which host thread.** Runtime code finds its host thread's record from the stack pointer
//!   ([`me`]), never from a register: the FS and GS bases are the program's.
//!
//! - **The token.** [`OWNER`] names the slot that holds it (or [`NONE_SLOT`]). A host thread waits
//!   for it by reading its own eventfd (blocking while the count is 0) and is handed it by a write
//!   on that eventfd. The eventfds are made before lockdown at a fixed fd range (the filter pins
//!   `read`/`write` to it). Acquiring and the waiter queue are serialised by a short spinlock.
//!
//! - **Binding.** Each program thread's coroutine is *bound* to its host thread
//!   (`Sched::bind`): it runs only there, because returning to user mode (`rt_sigreturn`) must
//!   happen on the host thread the program trapped on. LKL's kernel threads and the timer
//!   coroutines stay unbound and run on whichever host thread holds the token. When the token
//!   holder has no coroutine it may run but another host thread's bound coroutine is runnable, it
//!   hands the token to that home (a directed hand-off).
//!
//! - **Scheduling.** Each host thread has a *scheduler coroutine* ([`Sched::spawn_sched_loop`])
//!   running [`sched_loop`]: it picks a runnable coroutine the host may run and switches to it;
//!   when none, it gives the token away and waits. A coroutine that blocks switches back to its
//!   host's scheduler coroutine (`Sched::schedule` → [`Threaded::schedule`]).
//!
//! - **Timers and idle.** A dedicated kernel host thread ([`KERNEL`]) is the idler: when it holds
//!   the token with nothing runnable it `ppoll`s to the next timer deadline on its own eventfd
//!   (woken early by a hand-off or a newly-armed timer) and the host fds coroutines wait for
//!   (`host::idle_fds`: a read or write of a host fd, the guest's poll of one, the hooks'), fires
//!   due timers, wakes the fds' waiters, and hands the token to a runnable coroutine's home. A
//!   host thread returning to user mode hands the token to the kernel thread when a timer is
//!   pending or an fd is waited for, so deadlines and fds are always serviced. (It watched only its
//!   eventfd once: a program that polled its full stdout pipe, xz, waited for good.)
//!
//! - **Lazy threads.** A trapped `clone` ([`guest`]) takes a free slot and makes a host thread
//!   through the gate ([`trap::clone_thread`]); the slot frees when the host kernel clears its tid
//!   word (`CLONE_CHILD_CLEARTID`). The thread ends with `exit(0)` through the gate.
//!
//! Memory is high-water, as in every mode (no `madvise`: concurrent `madvise` and page faults is
//! the Dirty-COW race class).
//!
//! - **Fork mode** (`guest`'s `fork`): the same, across host processes. [`PAR`] (the token, every
//!   process's slots) is in the shared section (`share`), the eventfds are inherited by every fork,
//!   and slot ids are the sandbox's, not a process's (each slot records its process,
//!   `HostSlot::proc`). The per-slot alternate and boot stacks are private memory, each process its
//!   own copy at the same address. A fork's child starts on its slot's boot stack ([`host_fork`],
//!   [`child_start`]); a forked process's thread waits for the token watching init's pidfd too
//!   (`wait_token`). Threads and processes end on their boot stack ([`thread_exited`],
//!   [`process_exited`]): the control stacks are shared, and another process may take the slot's
//!   coroutines as soon as it is free.

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::context;
use crate::sched::{Sched, Tid};
use crate::trap::{self, PollFd};
use crate::xabi::Timespec;

/// Program-thread host slots (0 is the main thread; 1.. are made lazily at `clone`).
pub const PROG_SLOTS: usize = 128;
/// The idler/timer host thread's slot.
pub const KERNEL: u16 = PROG_SLOTS as u16;
/// Slots in all (program threads plus the kernel thread).
pub const N_SLOTS: usize = PROG_SLOTS + 1;
/// No slot (the token is free): distinct from every real slot.
pub const NONE_SLOT: u32 = u32::MAX;

/// The eventfds' fixed fd range: slot `i` reads/writes `EFD_BASE + i`. The host (exobox's
/// inventory) makes them there before [`enable`], and again in a fork's child before
/// [`after_fork`]; its security filter pins the token `read`/`write` to the range it made.
pub const EFD_BASE: u32 = 256;
/// A lazy thread's first (boot) stack: `thread_start`'s frame and the `rt_sigreturn` frame, until
/// it jumps to the program. Small; the program then runs on its own stack. Sized so a slot's
/// stacks (alternate + boot) are a power of two: [`me`] finds the slot by a shift.
const BOOT_STACK: usize = SLOT_STACKS - trap::ALTSTACK_SIZE;
/// Each slot's part of the stack region: its alternate signal stack, then its boot stack.
const SLOT_STACKS: usize = 1 << SLOT_SHIFT;
const SLOT_SHIFT: u32 = 17;
const _: () = assert!(trap::ALTSTACK_SIZE < SLOT_STACKS);

const POLLIN: i16 = 1;

/// One host thread's record, found from the stack pointer ([`me`]); its slot index keys the token.
pub struct HostSlot {
    id: u16,
    /// `EFD_BASE + id`.
    efd: u32,
    /// The slot is in use (a live host thread).
    used: AtomicBool,
    /// Made after lockdown (a program thread), vs the main or kernel thread.
    lazy: Cell<bool>,
    /// `CLONE_CHILD_CLEARTID`: the host kernel clears it (to 0) when the thread is off its stacks,
    /// which frees the slot. Set nonzero while the thread is being made.
    tid_word: AtomicU32,
    /// The program coroutine bound here (`Tid::raw`; 0: none, e.g. the kernel thread).
    bound: Cell<u64>,
    /// This host's scheduler coroutine (`Tid::raw`).
    sched_co: Cell<u64>,
    /// The coroutine this host thread is currently running (`Tid::raw`): the context-switch source,
    /// since the shared `Sched::current` is set by whichever host last held the token.
    running: Cell<u64>,
    /// The bound coroutine's control stack `[lo, hi)` (where its traps land); `(0, 0)`: the main
    /// thread's own stack (the root), handled like coroutine mode.
    ctl: Cell<(usize, usize)>,
    /// This slot's alternate signal stack and boot stack (reserved before lockdown).
    alt: Cell<usize>,
    boot: Cell<usize>,
    /// The guest tid `new_thread` made for this program thread, until its first LKL call attaches
    /// it (0: none / already attached). The main thread is init, attached at boot.
    attach: Cell<i32>,
    /// `CLONE_CHILD_CLEARTID` / `set_tid_address`: zeroed and futex-woken at the thread's exit.
    clear_tid: Cell<usize>,
    /// Acquire-waiter queue link (under `SPIN`).
    wnext: Cell<u16>,
    /// Fork mode: the process (`proc_id`) whose host thread this is; 0 is init's.
    proc: AtomicU32,
    /// Handed the token as an invitation ([`hand`]): the token is free, and this thread may take
    /// it when it wakes, unless another took it first.
    invited: AtomicBool,
    /// Its last invitation was lost to another thread (under `spin`): the next hand-off assigns
    /// the token to it outright, so a thread can't be passed over for good.
    lost: Cell<bool>,
}

impl HostSlot {
    const fn new(id: u16) -> Self {
        HostSlot {
            id,
            efd: EFD_BASE + id as u32,
            used: AtomicBool::new(false),
            proc: AtomicU32::new(0),
            lazy: Cell::new(false),
            tid_word: AtomicU32::new(0),
            bound: Cell::new(0),
            sched_co: Cell::new(0),
            running: Cell::new(0),
            ctl: Cell::new((0, 0)),
            alt: Cell::new(0),
            boot: Cell::new(0),
            attach: Cell::new(0),
            clear_tid: Cell::new(0),
            wnext: Cell::new(u16::MAX),
            invited: AtomicBool::new(false),
            lost: Cell::new(false),
        }
    }
    fn set_running(&self, t: Tid) {
        self.running.set(t.raw());
    }
    fn running(&self) -> Tid {
        Tid::from_raw(self.running.get())
    }
    fn sched_co(&self) -> Tid {
        Tid::from_raw(self.sched_co.get())
    }
}

/// Everything threaded mode keeps. One static; only the token holder touches the scheduler fields.
pub struct Threaded {
    sched: Cell<Option<&'static Sched>>,
    slots: [HostSlot; N_SLOTS],
    owner: crate::stats::Owner<{ KERNEL as u32 }>,
    spin: AtomicBool,
    /// Acquire-waiter FIFO (slot ids), under `spin`.
    whead: Cell<u16>,
    wtail: Cell<u16>,
    /// The kernel idler thread has set up its signal stack (before the TSYNC `route` may reach it).
    k_ready: AtomicBool,
    /// Next lazy slot search start.
    next: AtomicU32,
    /// The slots' stack region ([`SLOT_STACKS`] each: alternate, then boot), for [`me`].
    region: AtomicUsize,
    /// Fork mode: processes alive (init's included), the bound on them (0: none), and the last
    /// process number given out.
    live_procs: AtomicU32,
    max_procs: AtomicU32,
    next_proc: AtomicU32,
    /// The deadline the idler sleeps to without the token (under `spin`; u64::MAX: it isn't, so a
    /// release with any deadline pending hands it the token, as before).
    idler_until: AtomicU64,
}

// SAFETY: the scheduler fields are touched only by the token holder (one at a time). The atomics
// and the spinlock-guarded waiter queue are the cross-thread state.
unsafe impl Sync for Threaded {}

/// Shared between fork mode's processes (`share`): the token, the slots of every process.
#[unsafe(link_section = "exobox_shared")]
pub static PAR: Threaded = Threaded {
    sched: Cell::new(None),
    slots: {
        // A const array of slots with their ids.
        let mut a: [HostSlot; N_SLOTS] = [const { HostSlot::new(0) }; N_SLOTS];
        let mut i = 0;
        while i < N_SLOTS {
            a[i] = HostSlot::new(i as u16);
            i += 1;
        }
        a
    },
    owner: crate::stats::Owner::new(NONE_SLOT),
    spin: AtomicBool::new(false),
    whead: Cell::new(u16::MAX),
    wtail: Cell::new(u16::MAX),
    k_ready: AtomicBool::new(false),
    next: AtomicU32::new(1),
    region: AtomicUsize::new(0),
    live_procs: AtomicU32::new(1),
    max_procs: AtomicU32::new(0),
    next_proc: AtomicU32::new(0),
    idler_until: AtomicU64::new(u64::MAX),
};

fn sched() -> &'static Sched {
    PAR.sched.get().expect("par not enabled")
}

/// Fork mode: this host process's own (private: not in the shared section, copied by a fork and
/// then set by the child).
struct Local {
    /// The process's number in the sandbox (0: init's; a fork's child gets the next).
    id: AtomicU32,
    /// A fork's child (not init's process).
    forked: AtomicBool,
    /// Init's process's pidfd (made before lockdown, inherited): readable once it is gone. -1:
    /// not fork mode.
    init_pidfd: core::sync::atomic::AtomicI32,
}

static LOCAL: Local =
    Local { id: AtomicU32::new(0), forked: AtomicBool::new(false), init_pidfd: core::sync::atomic::AtomicI32::new(-1) };

/// This host process's number in the sandbox (fork mode; 0: init's, and in the other modes).
pub fn proc_id() -> u32 {
    LOCAL.id.load(Ordering::Relaxed)
}

/// Whether this is a fork's child process (not init's).
pub fn forked() -> bool {
    LOCAL.forked.load(Ordering::Relaxed)
}

/// Fork mode, before lockdown: init's pidfd, which every forked process watches while it waits
/// for the token (`wait_token`), so that it ends with init's process however that ends.
pub fn set_init_pidfd(fd: i32) {
    LOCAL.init_pidfd.store(fd, Ordering::Relaxed);
}

/// A fork's child process, at its start: its number.
pub fn become_child(id: u32) {
    LOCAL.id.store(id, Ordering::Relaxed);
    LOCAL.forked.store(true, Ordering::Relaxed);
}

/// The calling host thread's record, found from the stack pointer: no register of the thread's is
/// the runtime's. (It was the GS base, but the program may set GS itself: `arch_prctl(ARCH_SET_GS)`,
/// or `wrgsbase` with FSGSBASE, which no filter sees; the runtime now never reads or writes it.)
/// - On a slot's alternate or boot stack (the trap entry and the target hook run on the
///   alternate stack, a lazy thread starts on its boot stack): that slot, by a subtraction and a
///   shift (one region, [`SLOT_STACKS`] per slot).
/// - On a coroutine's stack (the dispatcher on a program thread's control stack, LKL's threads,
///   the scheduler loops): the host thread it is bound to, or was last switched to on
///   (`Sched::par_host_of_stack`).
/// - Anywhere else: the main thread's own stack (slot 0's root: setup code, and the program's
///   main thread's traps), the only host stack runtime code runs on after `enable`.
fn me() -> &'static HostSlot {
    let sp: usize;
    // SAFETY: reads rsp.
    unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack, preserves_flags)) };
    let off = sp.wrapping_sub(PAR.region.load(Ordering::Relaxed));
    if off < SLOT_STACKS * N_SLOTS {
        return &PAR.slots[off >> SLOT_SHIFT];
    }
    match sched().par_host_of_stack(sp) {
        Some(h) => &PAR.slots[h as usize],
        None => &PAR.slots[0],
    }
}

/// This host thread's slot id.
pub fn my_id() -> u16 {
    me().id
}

fn slot(id: u16) -> &'static HostSlot {
    &PAR.slots[id as usize]
}

// ---- the spinlock and the eventfd wakeups ----

fn lock() {
    while PAR.spin.swap(true, Ordering::Acquire) {
        core::hint::spin_loop();
    }
}
fn unlock() {
    PAR.spin.store(false, Ordering::Release);
}

/// Hand `id` the token: a write on its eventfd (its blocking read returns).
fn poke(id: u16) {
    crate::stats::count(crate::stats::K::Poke, 0);
    let _ = trap::eventfd_write(slot(id).efd, 1);
}

/// Block until this host thread holds the token: assigned to it, or offered ([`hand`]) and free
/// when it wakes. An offer another thread took first puts it back at the queue's head, and the
/// next hand-off assigns the token to it.
///
/// In a forked process, the wait also watches init's pidfd: when init's process is gone (its end
/// is the sandbox's, or it crashed on the host), nothing would hand this thread the token again,
/// and the process ends here instead of waiting for good (holding the sandbox's stdout open).
fn wait_token(id: u16) {
    let _w = crate::stats::wait_token(|| PAR.owner.load(Ordering::Relaxed) != id as u32);
    wait_token_inner(id);
    // Held: not in the queue any more (a thread put back in line after a lost offer can be
    // assigned the token by a directed hand-off instead of from the queue).
    if slot(id).lost.get() || PAR.whead.get() != u16::MAX {
        lock();
        unqueue(id);
        slot(id).lost.set(false);
        unlock();
    }
}

/// Take `id` out of the acquire-waiter queue, if it is in it (under the lock).
fn unqueue(id: u16) {
    let mut prev = u16::MAX;
    let mut i = PAR.whead.get();
    while i != u16::MAX {
        let next = slot(i).wnext.get();
        if i == id {
            if prev == u16::MAX {
                PAR.whead.set(next);
            } else {
                slot(prev).wnext.set(next);
            }
            if PAR.wtail.get() == id {
                PAR.wtail.set(prev);
            }
            slot(id).wnext.set(u16::MAX);
            return;
        }
        prev = i;
        i = next;
    }
}

fn wait_token_inner(id: u16) {
    let h = slot(id);
    while PAR.owner.load(Ordering::Acquire) != id as u32 {
        if h.invited.swap(false, Ordering::AcqRel) {
            lock();
            let o = PAR.owner.load(Ordering::Relaxed);
            if o == NONE_SLOT || o == id as u32 {
                PAR.owner.store(id as u32, Ordering::Release);
                unlock();
                return;
            }
            // Taken meanwhile: first in line (out of wherever it was: a thread queued in acquire
            // can be offered the token by a directed hand-off), and the next hand-off is ours
            // outright.
            h.lost.set(true);
            unqueue(id);
            h.wnext.set(PAR.whead.get());
            if PAR.whead.get() == u16::MAX {
                PAR.wtail.set(id);
            }
            PAR.whead.set(id);
            unlock();
            // As acquire does: the holder may be the idler, asleep to its next timer with the
            // token; it hands the token on when poked. (Without this, an offer lost to the idler
            // left the thread waiting until the idler's timer, or for good: guest_fork time::clock.)
            poke(o as u16);
            continue;
        }
        if forked() {
            let mut fds = [
                PollFd { fd: slot(id).efd as i32, events: POLLIN, revents: 0 },
                PollFd { fd: LOCAL.init_pidfd.load(Ordering::Relaxed), events: POLLIN, revents: 0 },
            ];
            if trap::ppoll_fds(&mut fds, None).is_ok() && fds[1].revents != 0 {
                trap::exit_group(0);
            }
            if fds[0].revents == 0 {
                continue;
            }
        }
        let _ = trap::eventfd_read(slot(id).efd);
    }
}

// ---- the token ----

/// Take the CPU token (blocking until held). The caller then owns the scheduler and the kernel.
pub fn acquire(id: u16) {
    lock();
    let o = PAR.owner.load(Ordering::Relaxed);
    if o == id as u32 {
        unlock(); // already held (e.g. the main thread between setup syscalls)
        crate::stats::count(crate::stats::K::AcqHeld, 0);
        return;
    }
    if o == NONE_SLOT {
        crate::stats::count(crate::stats::K::AcqFree, 0);
        PAR.owner.store(id as u32, Ordering::Release);
        unlock();
        return;
    }
    // Queue and wait; poke the current owner so an idling one releases to us.
    let owner = PAR.owner.load(Ordering::Relaxed) as u16;
    slot(id).wnext.set(u16::MAX);
    if PAR.wtail.get() == u16::MAX {
        PAR.whead.set(id);
    } else {
        slot(PAR.wtail.get()).wnext.set(id);
    }
    PAR.wtail.set(id);
    unlock();
    let _c = crate::stats::contended(owner == KERNEL);
    poke(owner);
    wait_token(id);
}

/// Pass the token to `t` (under the lock; the caller pokes `t` after unlocking). An offer: the
/// token is left free and `t` is invited to take it when it wakes, so a thread already running
/// that wants it meanwhile takes it at once, instead of the token sitting with a sleeping thread
/// for the host's wake-up latency (18-66 µs: 4.1 s of the token's 5.6 s held in make -j4, nearly
/// all of rustc's and cargo's, PERF.md). A thread that lost its last offer is assigned it outright.
fn hand(t: u16) {
    let h = slot(t);
    if h.lost.replace(false) {
        PAR.owner.store(t as u32, Ordering::Release);
    } else {
        PAR.owner.store(NONE_SLOT, Ordering::Release);
        h.invited.store(true, Ordering::Release);
    }
}

fn pop_waiter() -> Option<u16> {
    let h = PAR.whead.get();
    if h == u16::MAX {
        return None;
    }
    PAR.whead.set(slot(h).wnext.get());
    if PAR.whead.get() == u16::MAX {
        PAR.wtail.set(u16::MAX);
    }
    slot(h).wnext.set(u16::MAX);
    Some(h)
}

/// Give up the token. A directed hand-off (a runnable coroutine bound to another host) takes
/// priority, then an acquire-waiter; otherwise the kernel thread when a timer is pending or armed,
/// a host fd is waited for (so it is serviced: [`idle_watching`]), or `allow_none` is false, else
/// the token is left free. Returns the slot it went to (or [`NONE_SLOT`]).
///
/// Armed, not only on the heap: arming the kernel's timer (`timer_set_oneshot`) wakes the timer's
/// coroutine to re-read its deadline, and until it runs the deadline is on no heap. A thread
/// that armed it and went back to user mode left the token free, nothing pending, and nobody ran
/// the coroutine: another thread's sleep never ended while that one was busy (busy_sleep,
/// threaded and fork). (Any runnable coroutine bound to no host would do too, but the idle host
/// task is one after nearly every call: that handed the idler the token at every return, a
/// getppid at 3.4 µs instead of 0.8.)
fn give(id: u16, allow_none: bool) -> u32 {
    lock();
    let target = if let Some(home) = sched().par_bound_elsewhere(id) {
        home as u32
    } else if let Some(w) = pop_waiter() {
        w as u32
    } else if !allow_none
        || idle_watching()
        || crate::host::timer_rereading()
        || sched().par_next_deadline().is_some_and(|d| d < PAR.idler_until.load(Ordering::Relaxed))
    {
        KERNEL as u32
    } else {
        NONE_SLOT
    };
    if target == NONE_SLOT || target == id as u32 {
        PAR.owner.store(target, Ordering::Release);
    } else {
        hand(target as u16);
    }
    unlock();
    if target != NONE_SLOT && target != id as u32 {
        poke(target as u16);
    }
    target
}

// ---- the scheduler driver ----

impl crate::sched::Par for Threaded {
    /// A coroutine blocked (or yielded): switch to this host's scheduler coroutine, which decides
    /// what runs next. Returns when the blocking coroutine runs again.
    fn schedule(&self, s: &'static Sched) {
        let h = me();
        let from = h.running();
        let sc = h.sched_co();
        // Switch to the scheduler coroutine; it loops until it switches back to `from`.
        s.par_context_switch(from, sc);
        h.set_running(from);
    }
}

/// A host thread's scheduler coroutine body: run what the host may, else give up the token and
/// wait. `arg` is the slot id. The kernel thread is the idler: it holds the token and `ppoll`s to
/// the next deadline, firing timers; others hand it off and block on their eventfd.
fn sched_loop(arg: usize) -> usize {
    let id = arg as u16;
    let s = sched();
    let h = slot(id);
    h.set_running(h.sched_co());
    loop {
        s.par_expire(true);
        if let Some(n) = s.par_pick(id) {
            h.set_running(n);
            s.par_context_switch(h.sched_co(), n);
            h.set_running(h.sched_co());
            continue;
        }
        if id != KERNEL {
            // A program thread with nothing to run: give the token away, wait for it back.
            crate::stats::count(crate::stats::K::SchedIdle, 0);
            give(id, true);
            wait_token(id);
            continue;
        }
        // The kernel/idler thread. Hand off to a runnable coroutine's home or an acquire-waiter;
        // else idle. The idle wait watches the host fds coroutines wait on and the hooks'
        // executor's ([`host::idle_fds`]); a program busy enough that it never idles has them
        // looked at between hand-offs, at most once a millisecond (as coroutine mode's
        // `executor::busy_poll`).
        let mut fds = [PollFd::default(); crate::trap::PPOLL_FDS as usize];
        if idle_watching() && s.now().saturating_sub(LAST_LOOK.0.get()) >= BUSY_LOOK_NS {
            // (a wake makes a coroutine runnable: the hand-off below runs it)
            LAST_LOOK.0.set(s.now());
            let n = crate::host::idle_fds(&mut fds);
            let zero = Timespec { tv_sec: 0, tv_nsec: 0 };
            if n > 0 && trap::ppoll_fds(&mut fds[..n], Some(&zero)).is_ok_and(|r| r > 0) {
                crate::host::idle_ready(&fds[..n]);
            }
        }
        lock();
        if s.par_runnable_here(id) {
            // Something of ours or no one's became runnable (a timer that just fired, the look
            // above): run it first.
            unlock();
            continue;
        }
        let target = s.par_bound_elsewhere(id).map(|h| h as u32).or_else(|| pop_waiter().map(|w| w as u32));
        let deadline = s.par_next_deadline();
        if let Some(d) = deadline
            && !idle_watching()
        {
            // Sleep to the next deadline without the token (handed on, or left free): a release
            // hands it back only for a deadline earlier than this one (or a timer being set). It
            // kept the token while it slept, so a thread wanting the kernel woke it to be handed
            // it, and every release with a timer pending handed it back: with fix 4's offers,
            // nearly every contended acquire of a parallel rustc's or cargo's found the token
            // asleep in the idler (PERF.md).
            match target {
                Some(t) => hand(t as u16),
                None => PAR.owner.store(NONE_SLOT, Ordering::Release),
            }
            PAR.idler_until.store(d, Ordering::Relaxed);
            unlock();
            if let Some(t) = target {
                poke(t as u16);
            }
            let ns = d.saturating_sub(s.now());
            let ts = Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
            let mut p = PollFd { fd: h.efd as i32, events: POLLIN, revents: 0 };
            if trap::ppoll(Some(&mut p), Some(&ts)).is_ok_and(|n| n > 0) {
                let _ = trap::eventfd_read(h.efd);
            }
            lock();
            PAR.idler_until.store(u64::MAX, Ordering::Relaxed);
            unlock();
            acquire(id);
            continue;
        }
        if let Some(t) = target {
            hand(t as u16);
            unlock();
            poke(t as u16);
            wait_token(id);
            continue;
        }
        if deadline.is_none() && !idle_watching() {
            // Nothing to wait for but a hand-off: leave the token free and sleep until handed it
            // (a new timer or fd wait is made under the token, and handed here on that thread's
            // release).
            PAR.owner.store(NONE_SLOT, Ordering::Release);
            unlock();
            wait_token(id);
            continue;
        }
        // Keep the token and ppoll to the deadline on our eventfd (woken early by an acquirer's
        // poke) and the watched fds. On return, loop: fire due timers, run what an fd woke.
        unlock();
        fds[0] = PollFd { fd: h.efd as i32, events: POLLIN, revents: 0 };
        let n = 1 + crate::host::idle_fds(&mut fds[1..]);
        let ts = deadline.map(|d| {
            let ns = d.saturating_sub(s.now());
            Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 }
        });
        let polled = crate::stats::time(crate::stats::K::KernelPpoll, || trap::ppoll_fds(&mut fds[..n], ts.as_ref()));
        if polled.is_ok_and(|r| r > 0) {
            if fds[0].revents != 0 {
                let _ = trap::eventfd_read(h.efd);
            }
            LAST_LOOK.0.set(s.now());
            crate::host::idle_ready(&fds[1..n]);
        }
    }
}

/// Whether the idler has host fds to watch: a coroutine waits on one (`host::hostfd_rw`), or the
/// hooks' executor does, or the guest polls one (`executor::watching`).
fn idle_watching() -> bool {
    crate::host::fd_waiting() || (crate::executor::installed() && crate::executor::watching())
}

/// How often the idler looks at the watched fds at most while the program keeps it from idling.
const BUSY_LOOK_NS: u64 = 1_000_000;

/// When the idler last looked at the watched fds (the kernel thread's, which only it touches).
static LAST_LOOK: LastLook = LastLook(Cell::new(0));
struct LastLook(Cell<u64>);
// SAFETY: only the kernel thread touches it.
unsafe impl Sync for LastLook {}

/// The kernel/idler host thread. Set up before lockdown, then loops as the scheduler coroutine of
/// slot [`KERNEL`]. Never returns.
pub fn kernel_main() -> ! {
    let id = KERNEL;
    // SAFETY: once per process, before lockdown (sigaltstack is still allowed).
    unsafe {
        setup_host(id, false);
    }
    slot(id).used.store(true, Ordering::Release);
    // Signal that our signal stack is installed, so the main thread may now install the TSYNC
    // routing filter (after which only gate calls are allowed, which is all we make).
    PAR.k_ready.store(true, Ordering::Release);
    // Wait to be handed the token (never enqueue as an acquire-waiter: the kernel thread runs only
    // when a release hands it work, chiefly a pending timer deadline).
    wait_token(id);
    let sc = sched().spawn_sched_loop(sched_loop, id as usize, id, context::read_fs()).expect("kernel sched coroutine");
    slot(id).sched_co.set(sc.raw());
    // Enter the scheduler loop; it never returns (the process ends through exit_group).
    sched().par_switch(sc);
    unreachable!("kernel sched loop returned")
}

/// Spin until the kernel idler thread has installed its signal stack (the main thread calls this
/// after spawning it and before `route`, which would TSYNC a filter onto it).
pub fn wait_kernel_ready() {
    while !PAR.k_ready.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}

// ---- host-thread setup ----

/// Give the calling host thread its slot: its alternate signal stack (`lazy` threads already have
/// theirs installed by `clone_thread`'s frame). [`me`] finds the slot from the stack pointer.
///
/// # Safety
/// Called once per host thread; before lockdown for non-lazy threads (it uses `sigaltstack`).
unsafe fn setup_host(id: u16, lazy: bool) {
    let h = slot(id);
    if !lazy {
        // SAFETY: the alt region is this thread's; before lockdown.
        unsafe { trap::set_altstack(h.alt.get() as *mut u8, trap::ALTSTACK_SIZE).expect("altstack") };
    }
    h.lazy.set(lazy);
}

/// Reserve the per-slot alternate and boot stacks (before lockdown; high-water, `NORESERVE`), make
/// the eventfds at the fixed fds, bind the main thread (the running init coroutine) to slot 0, and
/// install the driver. Returns the token fd range for the filter.
///
/// # Safety
/// Called once, on the main thread, after boot and before `route`.
pub unsafe fn enable(s: &'static Sched, root: Tid) -> Result<(), rustix::io::Errno> {
    PAR.sched.set(Some(s));
    // Reserve alt + boot stacks for every slot in one NORESERVE region (only touched pages cost).
    let each = SLOT_STACKS;
    let total = each * N_SLOTS;
    // SAFETY: a fresh anonymous reservation owned by the runtime from now on.
    let base = unsafe {
        rustix::mm::mmap_anonymous(
            core::ptr::null_mut(),
            total,
            rustix::mm::ProtFlags::READ | rustix::mm::ProtFlags::WRITE,
            rustix::mm::MapFlags::PRIVATE | rustix::mm::MapFlags::NORESERVE,
        )?
    } as usize;
    PAR.region.store(base, Ordering::Relaxed);
    for i in 0..N_SLOTS {
        let h = &PAR.slots[i];
        h.alt.set(base + i * each);
        h.boot.set(base + i * each + trap::ALTSTACK_SIZE + BOOT_STACK); // boot stack top
    }
    // The main thread becomes slot 0, owning the token; its running coroutine (init) is bound here.
    let main = &PAR.slots[0];
    // SAFETY: the main thread, before lockdown.
    unsafe { setup_host(0, false) };
    main.used.store(true, Ordering::Release);
    main.bound.set(root.raw());
    main.set_running(root);
    main.ctl.set((0, 0)); // the root: its stack is the host thread's own (target() handles it)
    s.bind(root, 0);
    PAR.owner.store(0, Ordering::Release);
    s.install_par(&PAR);
    let main_sc = s.spawn_sched_loop(sched_loop, 0, 0, context::read_fs()).map_err(|_| rustix::io::Errno::NOMEM)?;
    main.sched_co.set(main_sc.raw());
    Ok(())
}

// ---- the dispatcher's token, per trapped syscall ----

/// Enter the kernel to serve a trapped syscall on this host thread: take the token and make this
/// host's bound coroutine the current one. Returns the slot id for [`leave`].
pub fn enter() -> u16 {
    let h = me();
    acquire(h.id);
    let bound = Tid::from_raw(h.bound.get());
    h.set_running(bound);
    sched().par_set_current(bound);
    h.id
}

/// Done serving a trapped syscall: give up the token (the kernel thread takes it if a timer is
/// pending) and return to user mode.
pub fn leave(id: u16) {
    give(id, true);
}

/// The guest tid this host thread's first LKL call must `attach_thread` (0: none/already attached).
/// Reads and clears it.
pub fn take_attach() -> i32 {
    me().attach.replace(0)
}

/// Record this host thread's `set_tid_address` / `CLONE_CHILD_CLEARTID` word.
pub fn set_clear_tid(addr: usize) {
    me().clear_tid.set(addr);
}

/// This host thread's clear-tid word (cleared), to zero and futex-wake at its exit.
pub fn take_clear_tid() -> usize {
    me().clear_tid.replace(0)
}

/// The trap's target stack for this host thread (its bound coroutine's control stack), or 0 for
/// the main thread's root (the caller falls back to the root logic).
pub fn target_ctl() -> (usize, usize) {
    me().ctl.get()
}

// ---- lazy program threads ----

/// A free program slot for a new host thread of process `proc`, with its bound coroutine (a
/// control stack for its traps) and its scheduler coroutine; marked taken (`tid_word` nonzero,
/// cleared again when the thread is off its stacks). Called with the token held.
fn take_slot(proc: u32) -> Result<(u16, Tid), rustix::io::Errno> {
    let s = sched();
    // Find a free slot (its old host thread, if any, has cleared its tid word).
    let start = PAR.next.load(Ordering::Relaxed) as usize;
    let mut found = None;
    for k in 0..PROG_SLOTS {
        let i = 1 + ((start + k) % (PROG_SLOTS - 1)); // slots 1..PROG_SLOTS
        let h = &PAR.slots[i];
        if !h.used.load(Ordering::Acquire) && h.tid_word.load(Ordering::Acquire) == 0 {
            found = Some(i as u16);
            break;
        }
    }
    let id = found.ok_or(rustix::io::Errno::AGAIN)?;
    PAR.next.store((id as u32 + 1) % PROG_SLOTS as u32, Ordering::Relaxed);
    let h = slot(id);
    // Free the previous occupant's coroutines (its host thread is long gone: tid_word is 0, nothing
    // runs on their stacks), so the Sched slots are reused rather than leaked.
    let (ob, osc) = (h.bound.get(), h.sched_co.get());
    if ob != 0 {
        s.drop_adopted(Tid::from_raw(ob));
    }
    if osc != 0 {
        s.drop_adopted(Tid::from_raw(osc));
    }
    h.bound.set(0);
    h.sched_co.set(0);
    // The bound coroutine: a "root-like" coroutine whose control stack is a Sched stack; it starts
    // in user mode on its own host thread (not via a Sched switch), so it is parked (off the run
    // queue) and its context is filled when it first blocks.
    let bound = s.adopt_root(id).map_err(|_| rustix::io::Errno::AGAIN)?;
    h.bound.set(bound.raw());
    h.attach.set(0);
    h.clear_tid.set(0);
    h.ctl.set(s.stack_of(bound));
    // Its scheduler coroutine.
    let sc = s.spawn_sched_loop(sched_loop, id as usize, id, context::read_fs()).map_err(|_| {
        s.drop_adopted(bound);
        rustix::io::Errno::AGAIN
    })?;
    h.sched_co.set(sc.raw());
    h.lazy.set(false);
    h.running.set(0);
    h.proc.store(proc, Ordering::Relaxed);
    h.tid_word.store(u32::MAX, Ordering::Release);
    Ok((id, bound))
}

// ---- fork mode: a process's first host thread ----

/// Fork mode: a slot for a fork's child process `proc`, whose first host thread is the host
/// fork's child itself ([`host_fork`]). Returns the slot and its bound coroutine, the child's
/// thread (what `thread_self` says on it). Called with the token held. Undone by [`drop_slot`].
pub fn fork_slot(proc: u32) -> Result<(u16, Tid), rustix::io::Errno> {
    take_slot(proc)
}

/// A slot from [`fork_slot`] whose fork failed.
pub fn drop_slot(id: u16) {
    drop_coroutines(id);
    slot(id).tid_word.store(0, Ordering::Release);
}

/// The top of slot `id`'s boot region (private memory of each process: a fork's child starts
/// there, and a thread's end runs there, off the shared stacks).
pub fn boot_top(id: u16) -> usize {
    slot(id).boot.get()
}

/// Slot `id`'s alternate signal stack, `(base, len)`.
pub fn alt_stack(id: u16) -> (usize, usize) {
    (slot(id).alt.get(), trap::ALTSTACK_SIZE)
}

/// The host fork (`clone(flags)` through the gate, no new stack: what the filter allows), made on
/// `stack_top` (in slot `id`'s boot region, private memory: the calling thread runs on a shared
/// control stack, which the child must not write). Returns the child's host pid in the parent,
/// or `-errno`. In the child the call doesn't return: it makes `rt_sigreturn` (through the gate)
/// on `frame`, an `rt_sigframe` (its return address, then the ucontext) the caller left in that
/// region, which installs the child's own alternate signal stack and enters the child's code.
///
/// # Safety
/// `stack_top` is 16-aligned private memory below `frame`, free; `frame` is a valid frame whose
/// registers start the child.
pub unsafe fn host_fork(stack_top: usize, flags: u64, frame: usize) -> isize {
    let _t = crate::stats::timed(crate::stats::K::Fork, 0); // the parent's: the child doesn't return
    // SAFETY: the caller's.
    unsafe { fork_trampoline(stack_top, flags, frame) }
}

#[unsafe(naked)]
unsafe extern "C" fn fork_trampoline(stack_top: usize, flags: u64, frame: usize) -> isize {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "mov rsp, rdi",
        // The frame's address, for the child (its copy of this stack has it too).
        "push rdx",
        // gate(NR_CLONE, flags, 0, 0, 0, 0, 0): the seventh argument (a5) on the stack.
        "push 0",
        "mov rdi, {nr}",
        "xor edx, edx",
        "xor ecx, ecx",
        "xor r8d, r8d",
        "xor r9d, r9d",
        "call {gate}",
        "test rax, rax",
        "jz 2f",
        "mov rsp, rbp",
        "pop rbp",
        "ret",
        // The child: rt_sigreturn reads the frame's ucontext at rsp (just past its return address).
        "2:",
        "mov rsp, [rsp + 8]",
        "add rsp, 8",
        "mov eax, 15",
        "jmp exobox_rt_gate_syscall",
        nr = const crate::trap::NR_CLONE,
        gate = sym trap::gate,
    )
}

/// Run `f(arg)` on stack `top` (16-aligned), never coming back: a thread's or a process's end,
/// moved off the shared control stack it ran on before its slot is given up.
///
/// # Safety
/// `top` is free private memory, this thread's.
pub unsafe fn on_stack(top: usize, f: extern "C" fn(usize) -> !, arg: usize) -> ! {
    // SAFETY: the caller's.
    unsafe {
        core::arch::asm!(
            "mov rsp, {top}",
            "call {f}",
            "ud2",
            top = in(reg) top & !15,
            f = in(reg) f,
            in("rdi") arg,
            options(noreturn),
        )
    }
}

/// Call `f(arg)` on stack `top` (16-aligned) and come back to this one: a fork's child runs the
/// kernel's bootstrap on its control stack (shared memory), from its boot stack.
///
/// # Safety
/// `top` is the top of free memory only this thread uses meanwhile.
#[unsafe(naked)]
pub unsafe extern "C" fn call_on_stack(top: usize, f: extern "C" fn(usize), arg: usize) {
    core::arch::naked_asm!(
        "push rbp",
        "mov rbp, rsp",
        "and rdi, -16",
        "mov rsp, rdi",
        "mov rdi, rdx",
        "call rsi",
        "mov rsp, rbp",
        "pop rbp",
        "ret",
    )
}

/// Make the calling (fork's child) host thread slot `id`'s, and take the token for it: the
/// child's first steps, on its boot stack. Its bound coroutine is then the current one.
pub fn child_start(id: u16) {
    let h = slot(id);
    // SAFETY: once, on this thread, which `rt_sigreturn` gave its alternate stack.
    unsafe { setup_host(id, true) };
    h.lazy.set(false);
    h.used.store(true, Ordering::Release);
    let bound = Tid::from_raw(h.bound.get());
    h.set_running(bound);
    acquire(id);
    sched().par_set_current(bound);
}

/// The calling thread's slot's bound coroutine's control stack top (where the child's
/// bootstrap runs: shared memory, as every kernel stack must be).
pub fn ctl_top() -> usize {
    me().ctl.get().1
}

/// The bound coroutine of the calling thread's slot.
pub fn bound() -> Tid {
    Tid::from_raw(me().bound.get())
}

/// The calling thread's slot no longer owns its bound coroutine (someone joins it, and frees it).
pub fn disown_bound() {
    me().bound.set(0);
}

/// Fork mode, init's process: its main thread's traps run on a coroutine stack too (shared
/// memory), not the host thread's own stack: kernel code keeps objects on its stack that other
/// processes reach (a wait queue entry while a `wait4` blocks). Called once, after [`enable`].
pub fn root_on_shared_stack() -> Result<(), rustix::io::Errno> {
    let s = sched();
    let holder = s.adopt_root(0).map_err(|_| rustix::io::Errno::NOMEM)?;
    PAR.slots[0].ctl.set(s.stack_of(holder));
    Ok(())
}

/// Make a host thread for a new program thread (a trapped `clone`): a free slot, a bound coroutine
/// resuming the program at `regs`, and a host thread through the gate that starts it in user mode.
/// Returns the guest tid the caller reports, or an errno. Called with the token held.
pub fn spawn_thread(
    regs: &context::Registers,
    fs: usize,
    guest_tid: i32,
    clear_tid: usize,
    tmpl: &trap::Ucontext,
) -> Result<(), rustix::io::Errno> {
    let s = sched();
    let (id, bound) = take_slot(proc_id())?;
    let h = slot(id);
    h.attach.set(guest_tid);
    h.clear_tid.set(clear_tid);
    h.lazy.set(true);
    let child = ChildStart { regs: *regs, fs };
    // The child's start state at the top of its boot region; the rt_sigreturn frame is built below
    // it (thread_start reads it before using that stack for anything else).
    let top = start_slot(id);
    // SAFETY: inside the slot's own boot region.
    unsafe { core::ptr::write(top, child) };
    let r = unsafe {
        trap::clone_thread(
            top as usize - 64,
            h.alt.get(),
            trap::ALTSTACK_SIZE,
            h.tid_word.as_ptr(),
            tmpl,
            thread_start,
            id as usize,
        )
    };
    match r {
        Ok(_) => {
            h.used.store(true, Ordering::Release);
            Ok(())
        }
        Err(e) => {
            h.tid_word.store(0, Ordering::Release);
            s.drop_adopted(bound);
            Err(e)
        }
    }
}

/// The child's start state, left in its boot region for `thread_start`.
struct ChildStart {
    regs: context::Registers,
    fs: usize,
}

/// Where a lazy thread's [`ChildStart`] sits: just below the top of its boot region, 16-aligned.
fn start_slot(id: u16) -> *mut ChildStart {
    ((slot(id).boot.get() - size_of::<ChildStart>()) & !15) as *mut ChildStart
}

/// A lazy host thread's first runtime code (via the `clone_thread` frame, altstack installed).
/// Binds the thread and jumps to the program in user mode; the bound coroutine then exists only
/// for the thread's traps.
extern "C" fn thread_start(arg: usize) -> ! {
    let id = arg as u16;
    // SAFETY: the parent wrote the start state into the slot's boot region.
    let cs = unsafe { core::ptr::read(start_slot(id)) };
    let h = slot(id);
    // SAFETY: the slot is this thread's; lazy (altstack already installed by the frame).
    unsafe { setup_host(id, true) };
    let bound = Tid::from_raw(h.bound.get());
    h.set_running(bound);
    // The child resumes the program with its own FS base (set TLS by clone, or inherited).
    // SAFETY: entering the program as its `clone` left it; no Rust runs between wrfsbase and
    // restore. FS does not matter to the runtime (globals only), so set the program's here.
    unsafe {
        core::arch::asm!("wrfsbase {}", in(reg) cs.fs, options(nomem, nostack));
        context::restore(&cs.regs)
    }
}

/// A program thread's guest task ended (`task_exit` host op, threaded): give up the token and end
/// the host thread. Called with the token held, on the thread's own host. The slot's Sched
/// coroutines are freed when the slot is reused (nothing runs on their stacks after `exit(0)`); the
/// host kernel clears the tid word once this thread is off its stacks, marking the slot free.
///
/// The end runs on the slot's boot stack (private), not the control stack it was called on: in
/// fork mode that is shared, and a fork's first thread (made by the host fork, with no tid word
/// the kernel clears) frees its slot itself, after which another process may reuse the stack.
pub fn thread_exited(id: u16) -> ! {
    // A coroutine bound to no host may be runnable (a timer this thread's last calls armed is woken
    // to re-read its deadline, which is on no heap until it runs): this host can't run it any
    // more, so the kernel thread takes the token rather than leaving it free with that coroutine
    // stranded (a thread's end while main slept on that timer hung the process). The return to
    // user mode (`leave`) doesn't look: it would hand the token off at nearly every call.
    let allow_none = !sched().par_unbound_ready();
    // SAFETY: the boot region is this thread's, unused while it runs the program.
    unsafe { on_stack(boot_top(id), thread_end, id as usize | (allow_none as usize) << 16) }
}

/// Free slot `id`'s coroutines, now that its thread is off their stacks (on its boot stack), with
/// the token held: a slot reused only much later (they're taken in turn) mustn't keep two
/// coroutines and their stacks meanwhile (fork mode's processes ran out of them).
fn drop_coroutines(id: u16) {
    let h = slot(id);
    let s = sched();
    for t in [h.bound.replace(0), h.sched_co.replace(0)] {
        if t != 0 {
            s.drop_adopted(Tid::from_raw(t));
        }
    }
}

extern "C" fn thread_end(arg: usize) -> ! {
    let (id, allow_none) = (arg as u16, arg >> 16 != 0);
    let h = slot(id);
    drop_coroutines(id);
    h.used.store(false, Ordering::Release);
    give(id, allow_none);
    if !h.lazy.get() && forked() {
        // A fork's first thread: no CLONE_CHILD_CLEARTID word. Off the shared stacks already.
        h.tid_word.store(0, Ordering::Release);
    }
    // SAFETY: nothing else needs this thread's stack; the kernel clears the tid word (reuse frees
    // the Sched coroutines).
    unsafe { trap::exit_thread() }
}

/// Fork mode: a forked process's last task ended (`task_exit` with its pid): the host process
/// ends. Called with the token held, on the thread's own host. Its slots come free: its other
/// threads have ended (each gave the token up before this one could take it); their host threads
/// are waited for (briefly) to be off their stacks, then any slot of the process still marked
/// taken (a thread that never attached) is freed with the token held, and the process exits.
pub fn process_exited(id: u16) -> ! {
    PAR.live_procs.fetch_sub(1, Ordering::AcqRel);
    let allow_none = !sched().par_unbound_ready();
    // SAFETY: as thread_exited.
    unsafe { on_stack(boot_top(id), process_end, id as usize | (allow_none as usize) << 16) }
}

extern "C" fn process_end(arg: usize) -> ! {
    let (id, allow_none) = (arg as u16, arg >> 16 != 0);
    let me_proc = proc_id();
    let h = slot(id);
    drop_coroutines(id);
    h.used.store(false, Ordering::Release);
    give(id, allow_none);
    let others = |j: usize| {
        let o = &PAR.slots[j];
        j != id as usize && o.proc.load(Ordering::Relaxed) == me_proc && o.tid_word.load(Ordering::Acquire) != 0
    };
    // Up to 100 ms: the other threads already made their `exit`.
    let ms = Timespec { tv_sec: 0, tv_nsec: 1_000_000 };
    for _ in 0..100 {
        if !(1..PROG_SLOTS).any(others) {
            break;
        }
        let _ = trap::ppoll(None, Some(&ms));
    }
    if (1..PROG_SLOTS).any(others) {
        acquire(id);
        for j in (1..PROG_SLOTS).filter(|&j| others(j)) {
            PAR.slots[j].used.store(false, Ordering::Release);
            PAR.slots[j].tid_word.store(0, Ordering::Release);
        }
        give(id, true);
    }
    h.tid_word.store(0, Ordering::Release);
    trap::exit_group(0)
}

/// Fork mode: the most processes alive at once, init's included (`--max-procs`; 0: no bound but
/// the slots).
pub fn set_max_procs(n: u32) {
    PAR.max_procs.store(n, Ordering::Relaxed);
    PAR.live_procs.store(1, Ordering::Relaxed);
}

/// Fork mode: a new process's number, if the bound allows one more (`None`: the fork fails with
/// EAGAIN). Called with the token held. [`process_exited`] (or [`drop_proc`]) gives it back.
pub fn take_proc() -> Option<u32> {
    let max = PAR.max_procs.load(Ordering::Relaxed);
    if max != 0 && PAR.live_procs.load(Ordering::Acquire) >= max {
        return None;
    }
    PAR.live_procs.fetch_add(1, Ordering::AcqRel);
    Some(PAR.next_proc.fetch_add(1, Ordering::Relaxed) + 1)
}

/// A process number from [`take_proc`] whose fork failed.
pub fn drop_proc() {
    PAR.live_procs.fetch_sub(1, Ordering::AcqRel);
}

/// The main thread's alternate signal stack, installed again (exobox's intercept: host code may
/// have changed it in passthrough). Through the gate.
pub fn rearm_altstack() {
    // SAFETY: slot 0's alternate stack is the main thread's.
    let _ = unsafe { trap::set_altstack(PAR.slots[0].alt.get() as *mut u8, trap::ALTSTACK_SIZE) };
}

/// A host fork's child (a template's instance), before it uses the guest: only the forking
/// (main) thread was copied, and it holds the CPU token (exobox's fork takes it first, so the
/// kernel was copied at rest). What the fork didn't copy, or copied as shared:
/// - the CPU-token eventfds: a fork shares their open files with the parent, so every hand-off
///   here would wake the parent's threads (and theirs ours). The host makes each again, at its
///   fd, before this (exobox's inventory).
/// - the kernel idler thread: gone. Its slot is cleared (its scheduler coroutine freed: nothing
///   runs on it), for a new one (`kernel_main` on a thread the caller spawns, then
///   [`wait_kernel_ready`]).
/// - the token's lock and waiter queue: whatever state the other threads left them in is
///   nobody's now; reset, the main thread the owner.
///
/// Program threads don't exist yet (setup can't make any), so no other slot is in use.
pub fn after_fork(s: &'static Sched) -> Result<(), rustix::io::Errno> {
    PAR.spin.store(false, Ordering::Release);
    PAR.whead.set(u16::MAX);
    PAR.wtail.set(u16::MAX);
    for i in 0..N_SLOTS {
        PAR.slots[i].wnext.set(u16::MAX);
        PAR.slots[i].invited.store(false, Ordering::Relaxed);
        PAR.slots[i].lost.set(false);
    }
    let k = slot(KERNEL);
    let old = k.sched_co.replace(0);
    if old != 0 {
        s.drop_adopted(Tid::from_raw(old));
    }
    k.running.set(0);
    k.used.store(false, Ordering::Release);
    PAR.k_ready.store(false, Ordering::Release);
    PAR.idler_until.store(u64::MAX, Ordering::Relaxed);
    PAR.owner.store(0, Ordering::Release);
    Ok(())
}

/// True in threaded mode after [`enable`] has run (the driver is installed).
pub fn enabled() -> bool {
    PAR.sched.get().is_some()
}
