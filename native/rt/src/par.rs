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
//!   (woken early by a hand-off or a newly-armed timer), fires due timers, and hands the token to
//!   a runnable coroutine's home. A host thread returning to user mode hands the token to the
//!   kernel thread when a timer is pending, so deadlines are always serviced.
//!
//! - **Lazy threads.** A trapped `clone` ([`guest`]) takes a free slot and makes a host thread
//!   through the gate ([`trap::clone_thread`]); the slot frees when the host kernel clears its tid
//!   word (`CLONE_CHILD_CLEARTID`). The thread ends with `exit(0)` through the gate.
//!
//! Memory is high-water (the filter refuses `madvise` here: concurrent `madvise` and page faults
//! is the Dirty-COW race class).

use core::cell::Cell;
use core::mem::size_of;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};

use rustix::fd::AsRawFd;

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

/// The eventfds' fixed fd range: slot `i` reads/writes `EFD_BASE + i`. The filter pins the token
/// `read`/`write` to `[EFD_BASE, EFD_BASE + N_SLOTS)`.
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
}

impl HostSlot {
    const fn new(id: u16) -> Self {
        HostSlot {
            id,
            efd: EFD_BASE + id as u32,
            used: AtomicBool::new(false),
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
    owner: AtomicU32,
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
}

// SAFETY: the scheduler fields are touched only by the token holder (one at a time). The atomics
// and the spinlock-guarded waiter queue are the cross-thread state.
unsafe impl Sync for Threaded {}

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
    owner: AtomicU32::new(NONE_SLOT),
    spin: AtomicBool::new(false),
    whead: Cell::new(u16::MAX),
    wtail: Cell::new(u16::MAX),
    k_ready: AtomicBool::new(false),
    next: AtomicU32::new(1),
    region: AtomicUsize::new(0),
};

fn sched() -> &'static Sched {
    PAR.sched.get().expect("par not enabled")
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
    let _ = trap::eventfd_write(slot(id).efd, 1);
}

/// Block until this host thread holds the token (its eventfd read returns on each hand-off).
fn wait_token(id: u16) {
    while PAR.owner.load(Ordering::Acquire) != id as u32 {
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
        return;
    }
    if o == NONE_SLOT {
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
    poke(owner);
    wait_token(id);
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
/// priority, then an acquire-waiter; otherwise the kernel thread when a timer is pending (so it is
/// serviced) or `allow_none` is false, else the token is left free. Returns the slot it went to
/// (or [`NONE_SLOT`]).
fn give(id: u16, allow_none: bool) -> u32 {
    lock();
    let target = if let Some(home) = sched().par_bound_elsewhere(id) {
        home as u32
    } else if let Some(w) = pop_waiter() {
        w as u32
    } else if !allow_none || sched().par_next_deadline().is_some() {
        KERNEL as u32
    } else {
        NONE_SLOT
    };
    PAR.owner.store(target, Ordering::Release);
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
            give(id, true);
            wait_token(id);
            continue;
        }
        // The kernel/idler thread. Hand off to a runnable coroutine's home or an acquire-waiter;
        // else idle.
        lock();
        let target = s.par_bound_elsewhere(id).map(|h| h as u32).or_else(|| pop_waiter().map(|w| w as u32));
        if let Some(t) = target {
            PAR.owner.store(t, Ordering::Release);
            unlock();
            poke(t as u16);
            wait_token(id);
            continue;
        }
        match s.par_next_deadline() {
            None => {
                // No timers: leave the token free and sleep until handed it (a new timer will be
                // armed under the token and handed here on the arming thread's release).
                PAR.owner.store(NONE_SLOT, Ordering::Release);
                unlock();
                wait_token(id);
            }
            Some(d) => {
                // Keep the token and ppoll to the deadline on our eventfd (woken early by an
                // acquirer's poke). On return, loop: fire due timers.
                unlock();
                let now = s.now();
                let ns = d.saturating_sub(now);
                let ts = Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 };
                let mut p = PollFd { fd: h.efd as i32, events: POLLIN, revents: 0 };
                let _ = trap::ppoll(Some(&mut p), Some(&ts));
                if p.revents != 0 {
                    let _ = trap::eventfd_read(h.efd);
                }
            }
        }
    }
}

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
pub unsafe fn enable(s: &'static Sched, root: Tid) -> Result<(u32, u32), rustix::io::Errno> {
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
        // An eventfd duped onto the fixed fd EFD_BASE + i.
        let efd = rustix::event::eventfd(0, rustix::event::EventfdFlags::empty())?;
        let want = (EFD_BASE + i as u32) as i32;
        // SAFETY: dup2 to a chosen fd; the source is closed with `efd` after.
        let r = unsafe { trap::gate(33, efd.as_raw_fd() as usize, want as usize, 0, 0, 0, 0) };
        if r < 0 {
            return Err(rustix::io::Errno::from_raw_os_error(-r as i32));
        }
        drop(efd);
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
    Ok((EFD_BASE, EFD_BASE + N_SLOTS as u32 - 1))
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
    h.attach.set(guest_tid);
    h.clear_tid.set(clear_tid);
    h.ctl.set(s.stack_of(bound));
    // Its scheduler coroutine.
    let sc = s.spawn_sched_loop(sched_loop, id as usize, id, context::read_fs()).map_err(|_| {
        s.drop_adopted(bound);
        rustix::io::Errno::AGAIN
    })?;
    h.sched_co.set(sc.raw());
    h.lazy.set(true);
    h.running.set(0);
    h.tid_word.store(u32::MAX, Ordering::Release);
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
pub fn thread_exited(id: u16) -> ! {
    let h = slot(id);
    h.used.store(false, Ordering::Release);
    give(id, true);
    // SAFETY: nothing else needs this thread's stack; the kernel clears the tid word (reuse frees
    // the Sched coroutines).
    unsafe { trap::exit_thread() }
}

/// True in threaded mode after [`enable`] has run (the driver is installed).
pub fn enabled() -> bool {
    PAR.sched.get().is_some()
}
