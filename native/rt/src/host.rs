//! LKL's host operations in coroutine mode: the table the kernel calls ([`HOST_OPS`]), wired to
//! the scheduler (`sched`) and its primitives (`sync`), and the production [`Host`] behind the
//! scheduler ([`SysHost`]: clocks, and `ppoll` as the idle wait).
//!
//! Use: [`Sched::init`] a scheduler, [`install`] it with the kernel's memory, then
//! `lkl_init(host::ops())` and `lkl_start_kernel(..)` from a coroutine of that scheduler (not the
//! root: the kernel's threads may `thread_exit`, and the root is the host thread, which can't).
//!
//! Everything is fixed-size and static, per the crate's rules: semaphores, mutexes and timers come
//! from pools ([`SEMAPHORES`], [`MUTEXES`], [`TIMERS`]; `*_alloc` returns NULL when one is full,
//! which LKL checks), the kernel's memory from one region handed to [`install`] before boot (LKL
//! asks for its pool once, at boot: no host `mmap` after setup).
//!
//! The scheduler author's wiring questions, answered against LKL (arch/lkl, `exobox/native`):
//!
//! - **Is a host mutex ever unlocked by another thread than its locker?** No. The kernel's only
//!   host mutex is `cpu.lock` (kernel/cpu.c), and every lock is paired with an unlock in the same
//!   function, on the same thread, with no blocking op in between (`__cpu_try_get_lock` returns
//!   holding it and its caller unlocks it through `__cpu_try_get_unlock` before anything sleeps;
//!   `lkl_cpu_put` drops it around `run_irqs()` and before `thread_sched_jb()`). What *is* taken on
//!   one thread and released on another is the kernel's CPU (`cpu.owner`, handed over in
//!   `__switch_to` by `lkl_cpu_change_owner`), and that goes through semaphores, which have no
//!   owner. So `sync::Mutex`'s owner check holds.
//! - **Is a jmp_buf always longjmp'd from the coroutine that set it?** Yes. The two setters are
//!   `thread_sched_jb()` (asm/sched.h: a host task calls `jmp_buf_set(&ti->sched_jb, schedule)`)
//!   and `del_host_task()` (kernel/syscalls.c: `jmp_buf_set(&ti->sched_jb, exit_task)`, in the TLS
//!   destructor of the exiting thread). Both mark the task `TIF_SCHED_JB`, and the only longjmp is
//!   in `__switch_to(prev, next)` for `prev`'s buffer, which runs on `prev`'s own thread, inside
//!   that `schedule()`/`do_exit()` — below the `jmp_buf_set` on the same stack. `__switch_to`
//!   longjmps from a *copy* of the buffer on its stack (taken before `sem_up(next)`, after which
//!   the buffer may be reused): fine here, because a `context::JmpBuf` is only a stack pointer
//!   into the setter's frame, which doesn't move.
//! - **`void (*f)(void)` vs our `fn(usize)`.** `jmp_buf_set`'s and `timer_alloc`'s callbacks take
//!   no argument; `sync::jmp_buf_set` and `Timer` pass one. Calling a `void (void)` function with
//!   an extra argument in rdi happens to work on x86-64 SysV, but transmuting between function
//!   pointer types of different signatures is undefined behaviour in Rust, so each goes through a
//!   shim that receives the C function as its argument and calls it with none
//!   ([`call_void`], [`timer_fired`]). `thread_create`'s `void (*)(void *)` and the TLS
//!   destructor's are exactly `Sched::spawn_c`'s and `TlsKey`'s types: no shim.
//!
//! A kernel spin a cooperative host can't serve (not hit by the boot test; for the kernel series):
//! at halt, `lkl_cpu_cleanup()` (kernel/cpu.c) busy-waits until `cpu.shutdown_gate` drops to
//! `MAX_THREADS`. A thread parked in `lkl_cpu_get()` waiting for the CPU (`sem_down(cpu.sem)`)
//! still counts in the gate until it runs again; `arch_cpu_idle()` posts `cpu.sem` for it, then
//! spins in `lkl_cpu_cleanup()` without blocking, so here the woken coroutine never runs and the
//! halt hangs. It takes a second thread inside `lkl_syscall`/`lkl_cpu_get` at halt (a program
//! thread in a syscall).

use core::cell::{Cell, UnsafeCell};
use core::ffi::{c_char, c_int, c_uint, c_ulong, c_ulonglong, c_void};
use core::ptr;

use lkl_sys::{lkl_host_operations, lkl_jmp_buf, lkl_mutex, lkl_sem, lkl_thread_t, lkl_tls_key};

use crate::context::JmpBuf;
use crate::sched::{Host, Sched, Tid};
use crate::sync::{self, Mutex, Semaphore, Timer, TlsKey};

/// Semaphores: LKL takes one per task (every kernel thread and every host task has a
/// `sched_sem`), plus four of its own (`cpu.c`, `setup.c`). As many as there can be coroutines;
/// host tasks (program threads) also have one each.
pub const SEMAPHORES: usize = crate::sched::CAPACITY;
/// Mutexes: LKL allocates one (`cpu.lock`).
pub const MUTEXES: usize = 8;
/// Timers: LKL allocates one, for its clockevent (kernel/time.c; again after each shutdown of it).
/// Each takes a coroutine while allocated.
pub const TIMERS: usize = 4;

const PAGE: usize = 4096;
/// mem_alloc's alignment: malloc's on x86-64.
const ALIGN: usize = 16;

/// One pooled object and whether it is handed out. LKL's handle is the slot's address.
struct Slot<T> {
    used: Cell<bool>,
    v: UnsafeCell<T>,
}

impl<T> Slot<T> {
    const fn new(v: T) -> Self {
        Slot { used: Cell::new(false), v: UnsafeCell::new(v) }
    }
    fn get(&self) -> &T {
        // SAFETY: only replaced (`Pool::alloc`) while not handed out, so no reference is live.
        unsafe { &*self.v.get() }
    }
}

struct Pool<T, const N: usize> {
    slots: [Slot<T>; N],
    /// Where the next search starts (after the last slot handed out), so allocation doesn't scan
    /// the busy front every time.
    next: Cell<usize>,
}

impl<T, const N: usize> Pool<T, N> {
    /// A free slot, its value replaced by `v` (dropping the old one: a freed semaphore or mutex
    /// has no waiters, which their queues' Drop checks). `None` when all are taken.
    fn alloc(&'static self, v: T) -> Option<&'static Slot<T>> {
        let start = self.next.get();
        for k in 0..N {
            let i = (start + k) % N;
            let s = &self.slots[i];
            if !s.used.get() {
                // SAFETY: not handed out, so nothing refers to the value.
                unsafe { *s.v.get() = v };
                s.used.set(true);
                self.next.set((i + 1) % N);
                return Some(s);
            }
        }
        None
    }

    /// The slot behind a handle from `alloc`.
    ///
    /// # Safety
    /// `p` came from this pool's `alloc` (and wasn't freed).
    unsafe fn slot(&self, p: *const c_void) -> &Slot<T> {
        debug_assert!(self.slots.as_ptr_range().contains(&(p as *const Slot<T>)), "not a pool handle");
        // SAFETY: the caller's contract.
        unsafe { &*(p as *const Slot<T>) }
    }

    #[cfg(test)]
    fn in_use(&self) -> usize {
        self.slots.iter().filter(|s| s.used.get()).count()
    }
}

// SAFETY: one host thread runs the scheduler and the kernel's host ops (see `Sched`'s impl).
unsafe impl<T, const N: usize> Sync for Pool<T, N> {}

// The pools and the kernel's heap are the kernel's: shared between fork mode's processes (`share`).
#[unsafe(link_section = "exobox_shared")]
static SEMS: Pool<Semaphore, SEMAPHORES> =
    Pool { slots: [const { Slot::new(Semaphore::new(0)) }; SEMAPHORES], next: Cell::new(0) };
#[unsafe(link_section = "exobox_shared")]
static MUTEX_POOL: Pool<Mutex, MUTEXES> =
    Pool { slots: [const { Slot::new(Mutex::new(false)) }; MUTEXES], next: Cell::new(0) };
#[unsafe(link_section = "exobox_shared")]
static TIMER_POOL: Pool<TimerSlot, TIMERS> =
    Pool { slots: [const { Slot::new(TimerSlot::new()) }; TIMERS], next: Cell::new(0) };

/// A timer and LKL's function for it.
struct TimerSlot {
    timer: Timer,
    f: Cell<Option<unsafe extern "C" fn()>>,
    /// The timer's coroutine while it runs `f` (it may free its own timer from there).
    runner: Cell<Option<Tid>>,
    /// Freed from inside `f`: the slot is released when `f` returns, not before (the coroutine
    /// still reads the Timer until then).
    release_on_return: Cell<bool>,
}

impl TimerSlot {
    const fn new() -> Self {
        TimerSlot {
            timer: Timer::new(),
            f: Cell::new(None),
            runner: Cell::new(None),
            release_on_return: Cell::new(false),
        }
    }
}

/// The kernel's memory: one region handed in before boot, allocated from by bumping. LKL asks
/// for its whole pool once at boot (`page_alloc(mem=)`, mm/bootmem.c) and gives it back at halt
/// (`page_free`); nothing else in the kernel calls these ops (stock LKL's other callers are
/// tools/lkl/lib's virtio and disk helpers, which exobox doesn't link). So a bump allocator is
/// enough: a free of the latest block rolls the top back, and the region starts over when
/// everything is freed (a halt and a new boot reuse it). Other frees are leaked, which a fixed
/// region can afford for what never happens.
struct Heap {
    base: Cell<usize>,
    end: Cell<usize>,
    top: Cell<usize>,
    live: Cell<usize>,
    /// The latest block (its start) and the top before it, for the roll-back.
    last: Cell<(usize, usize)>,
}

impl Heap {
    const fn new() -> Self {
        Heap { base: Cell::new(0), end: Cell::new(0), top: Cell::new(0), live: Cell::new(0), last: Cell::new((0, 0)) }
    }

    fn alloc(&self, size: usize, align: usize) -> *mut c_void {
        let top = self.top.get();
        let Some(start) = top.checked_next_multiple_of(align) else { return ptr::null_mut() };
        // A zero-size block still gets its own address, so it can be freed like any other.
        let Some(new_top) = start.checked_add(size.max(1)) else { return ptr::null_mut() };
        if new_top > self.end.get() {
            return ptr::null_mut();
        }
        self.top.set(new_top);
        self.last.set((start, top));
        self.live.set(self.live.get() + 1);
        start as *mut c_void
    }

    fn free(&self, p: *mut c_void) {
        if p.is_null() {
            return;
        }
        let p = p as usize;
        debug_assert!(p >= self.base.get() && p < self.top.get(), "not a kernel heap block");
        let live = self.live.get() - 1;
        self.live.set(live);
        let (start, prev_top) = self.last.get();
        if live == 0 {
            self.top.set(self.base.get());
        } else if p == start {
            self.top.set(prev_top);
        }
        // Only one roll-back: the block before the latest one isn't known.
        self.last.set((0, 0));
    }
}

struct Global {
    sched: Cell<Option<&'static Sched>>,
    heap: Heap,
}

// SAFETY: as the pools'.
unsafe impl Sync for Global {}

#[unsafe(link_section = "exobox_shared")]
static G: Global = Global { sched: Cell::new(None), heap: Heap::new() };

fn sched() -> &'static Sched {
    G.sched.get().expect("host ops used before host::install")
}

/// Make `sched` the scheduler the host ops run on, and `heap[..heap_len]` the kernel's memory
/// (`page_alloc`/`mem_alloc`): at least `mem=` of the command line, plus a page for alignment if
/// `heap` isn't page-aligned. Returns the table for `lkl_init`.
///
/// # Safety
/// The region is readable and writable and belongs to the kernel from now on. `sched` is
/// initialized ([`Sched::init`]) on this host thread. Called once per process (the table is
/// static, as LKL keeps a pointer to it).
pub unsafe fn install(sched: &'static Sched, heap: *mut u8, heap_len: usize) -> *mut lkl_host_operations {
    assert!(G.sched.get().is_none(), "host::install twice");
    G.sched.set(Some(sched));
    let base = heap as usize;
    G.heap.base.set(base);
    G.heap.end.set(base + heap_len);
    G.heap.top.set(base);
    ops()
}

/// The table installed by [`install`], for `lkl_init`.
pub fn ops() -> *mut lkl_host_operations {
    HOST_OPS.0.get()
}

/// LKL's host-operations table. Writable (an `UnsafeCell`): `lkl_init` takes a mutable pointer,
/// and LKL's PCI self-tests store into `pci_ops` (not built here, but the table must not be in
/// read-only memory if they ever are).
pub struct HostOps(UnsafeCell<lkl_host_operations>);

// SAFETY: as the pools'; the table is only written before boot, if at all.
unsafe impl Sync for HostOps {}

/// The table. Unsupported optional ops are NULL, which LKL checks before calling: `virtio_devices`
/// (no virtio), `ioremap`/`iomem_access` (no MMIO devices), `mmap`/`munmap`/`shmem_*` (only with
/// `CONFIG_MMU` or KASAN, both off), `pci_ops` (no PCI).
pub static HOST_OPS: HostOps = HostOps(UnsafeCell::new(lkl_host_operations {
    virtio_devices: ptr::null(),
    print: Some(print),
    panic: Some(panic),
    sem_alloc: Some(sem_alloc),
    sem_free: Some(sem_free),
    sem_up: Some(sem_up),
    sem_down: Some(sem_down),
    mutex_alloc: Some(mutex_alloc),
    mutex_free: Some(mutex_free),
    mutex_lock: Some(mutex_lock),
    mutex_unlock: Some(mutex_unlock),
    thread_create: Some(thread_create),
    thread_detach: Some(thread_detach),
    thread_exit: Some(thread_exit),
    thread_join: Some(thread_join),
    thread_self: Some(thread_self),
    thread_equal: Some(thread_equal),
    thread_stack: Some(thread_stack),
    tls_alloc: Some(tls_alloc),
    tls_free: Some(tls_free),
    tls_set: Some(tls_set),
    tls_get: Some(tls_get),
    mem_alloc: Some(mem_alloc),
    mem_free: Some(mem_free),
    page_alloc: Some(page_alloc),
    page_free: Some(page_free),
    time: Some(time),
    timer_alloc: Some(timer_alloc),
    timer_set_oneshot: Some(timer_set_oneshot),
    timer_free: Some(timer_free),
    ioremap: None,
    iomem_access: None,
    jmp_buf_set: Some(jmp_buf_set),
    jmp_buf_longjmp: Some(jmp_buf_longjmp),
    memcpy: Some(memcpy),
    memset: Some(memset),
    memmove: Some(memmove),
    mmap: None,
    munmap: None,
    shmem_init: None,
    shmem_mmap: None,
    pci_ops: ptr::null_mut(),
    // The kernel series' item 6 (a task's exit): the sandbox's dispatcher provides it
    // (`exobox_rt::guest`), as what a task's end means is the sandbox's; without it, a task's
    // end ends its coroutine (thread_exit).
    task_exit: None,
    hostfd_rw: Some(hostfd_rw),
    // Items 8 (signals at a syscall's return) and 9 (fork as a host fork): the dispatcher's, in
    // the modes that use them.
    signal_handler: None,
    fork: None,
    // The kernel's socket impersonation and passed fds' readiness: `tsi`.
    net_connect: Some(crate::tsi::net_connect),
    net_listen: Some(crate::tsi::net_listen),
    net_sendto: Some(crate::tsi::net_sendto),
    net_ready: Some(crate::tsi::net_ready),
    hostfd_poll: Some(crate::tsi::hostfd_poll),
}));

// ---- print and panic ----

/// All of `buf` to the host's stderr, a `write` on fd 2 through the gate (allowed by every
/// filter). Not rustix's: once the routing filter is in, a syscall not from the gate traps and
/// would be served by the guest (as the program's write to its fd 2), from inside the kernel.
/// Errors are dropped: there is nowhere else to report them.
fn write_stderr(mut buf: &[u8]) {
    while !buf.is_empty() {
        match crate::trap::write(2, buf) {
            Ok(0) => return,
            Ok(n) => buf = &buf[n..],
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return,
        }
    }
}

unsafe extern "C" fn print(s: *const c_char, len: c_int) {
    if s.is_null() || len <= 0 {
        return;
    }
    // SAFETY: LKL passes its console buffer and its length.
    write_stderr(unsafe { core::slice::from_raw_parts(s as *const u8, len as usize) });
}

/// The kernel panicked (its message is already out, through `print`). A panic here: the sandbox
/// ends (the crate's rule: built `panic=abort`).
unsafe extern "C" fn panic() {
    panic!("the kernel panicked (LKL's panic host op)");
}

/// lkl-sys's shim.c: what `lkl_printf` formatted.
#[unsafe(no_mangle)]
pub extern "C" fn exobox_lkl_print(s: *const c_char, len: c_ulong) {
    if s.is_null() {
        return;
    }
    // SAFETY: shim.c passes its stack buffer and the formatted length.
    write_stderr(unsafe { core::slice::from_raw_parts(s as *const u8, len as usize) });
}

/// lkl-sys's shim.c: `lkl_bug`, after printing its message. The kernel can't go on.
#[unsafe(no_mangle)]
pub extern "C" fn exobox_lkl_panic() -> ! {
    panic!("the kernel hit lkl_bug");
}

// ---- semaphores and mutexes ----

unsafe extern "C" fn sem_alloc(count: c_int) -> *mut lkl_sem {
    match SEMS.alloc(Semaphore::new(count.max(0) as u64)) {
        Some(s) => s as *const Slot<Semaphore> as *mut lkl_sem,
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn sem_free(sem: *mut lkl_sem) {
    // SAFETY: LKL frees what sem_alloc gave it.
    unsafe { SEMS.slot(sem as *const c_void) }.used.set(false);
}

unsafe extern "C" fn sem_up(sem: *mut lkl_sem) {
    // SAFETY: as sem_free.
    unsafe { SEMS.slot(sem as *const c_void) }.get().up(sched());
}

unsafe extern "C" fn sem_down(sem: *mut lkl_sem) {
    // SAFETY: as sem_free.
    unsafe { SEMS.slot(sem as *const c_void) }.get().down(sched());
}

unsafe extern "C" fn mutex_alloc(recursive: c_int) -> *mut lkl_mutex {
    match MUTEX_POOL.alloc(Mutex::new(recursive != 0)) {
        Some(m) => m as *const Slot<Mutex> as *mut lkl_mutex,
        None => ptr::null_mut(),
    }
}

unsafe extern "C" fn mutex_free(m: *mut lkl_mutex) {
    // SAFETY: LKL frees what mutex_alloc gave it.
    unsafe { MUTEX_POOL.slot(m as *const c_void) }.used.set(false);
}

unsafe extern "C" fn mutex_lock(m: *mut lkl_mutex) {
    // SAFETY: as mutex_free.
    unsafe { MUTEX_POOL.slot(m as *const c_void) }.get().lock(sched());
}

unsafe extern "C" fn mutex_unlock(m: *mut lkl_mutex) {
    // SAFETY: as mutex_free. Always the locker (the module comment).
    unsafe { MUTEX_POOL.slot(m as *const c_void) }.get().unlock(sched());
}

// ---- threads: coroutines ----

/// A coroutine running `f(arg)`; 0 (LKL's failure) when the table is full. A `Tid` is never 0.
unsafe extern "C" fn thread_create(f: Option<unsafe extern "C" fn(*mut c_void)>, arg: *mut c_void) -> lkl_thread_t {
    let Some(f) = f else { return 0 };
    // SAFETY: LKL's thread functions run on a fresh thread of their own, which this is.
    match unsafe { sched().spawn_c(f, arg) } {
        Ok(t) => t.raw() as lkl_thread_t,
        Err(_) => 0,
    }
}

/// Never called by the kernel (stock LKL has no caller); the current coroutine, as pthreads'.
unsafe extern "C" fn thread_detach() {
    let s = sched();
    let _ = s.detach(s.current());
}

unsafe extern "C" fn thread_exit() {
    // Fork mode: a fork's child thread whose clone failed (its process ends there).
    crate::guest::fork_thread_exit();
    sched().exit(0)
}

/// 0, or -1 for an id that can't be joined (unknown, detached, already joined, itself).
unsafe extern "C" fn thread_join(tid: lkl_thread_t) -> c_int {
    match sched().join(Tid::from_raw(tid)) {
        Ok(_) => 0,
        Err(_) => -1,
    }
}

unsafe extern "C" fn thread_self() -> lkl_thread_t {
    sched().current().raw() as lkl_thread_t
}

unsafe extern "C" fn thread_equal(a: lkl_thread_t, b: lkl_thread_t) -> c_int {
    (a == b) as c_int
}

/// The current coroutine's stack (lowest address, size), for `object_is_on_stack`. NULL for the
/// root, whose stack the scheduler doesn't know: LKL then answers "not on the stack".
unsafe extern "C" fn thread_stack(size: *mut c_ulong) -> *mut c_void {
    let (lo, len) = sched().stack();
    if !size.is_null() {
        // SAFETY: LKL passes its local.
        unsafe { *size = len as c_ulong };
    }
    lo as *mut c_void
}

// ---- TLS keys; the handle is the key's index + 1 (never NULL) ----

unsafe extern "C" fn tls_alloc(dtor: Option<unsafe extern "C" fn(*mut c_void)>) -> *mut lkl_tls_key {
    match TlsKey::alloc(sched(), dtor) {
        Some(k) => (k.0 + 1) as *mut lkl_tls_key,
        None => ptr::null_mut(),
    }
}

fn key(k: *mut lkl_tls_key) -> TlsKey {
    TlsKey(k as usize - 1)
}

unsafe extern "C" fn tls_free(k: *mut lkl_tls_key) {
    key(k).free(sched())
}

unsafe extern "C" fn tls_set(k: *mut lkl_tls_key, v: *mut c_void) -> c_int {
    key(k).set(sched(), v as usize);
    0
}

unsafe extern "C" fn tls_get(k: *mut lkl_tls_key) -> *mut c_void {
    key(k).get(sched()) as *mut c_void
}

// ---- memory ----

unsafe extern "C" fn mem_alloc(size: c_ulong) -> *mut c_void {
    G.heap.alloc(size as usize, ALIGN)
}

unsafe extern "C" fn mem_free(p: *mut c_void) {
    G.heap.free(p)
}

unsafe extern "C" fn page_alloc(size: c_ulong) -> *mut c_void {
    G.heap.alloc(size as usize, PAGE)
}

unsafe extern "C" fn page_free(p: *mut c_void, _size: c_ulong) {
    G.heap.free(p)
}

// ---- time and timers ----

/// CLOCK_MONOTONIC ns: the scheduler's clock, the one its timers run on.
unsafe extern "C" fn time() -> c_ulonglong {
    sched().now()
}

/// The shim between `Timer`'s `fn(*mut c_void)` and LKL's `void (*)(void)`: `arg` is the slot.
unsafe extern "C" fn timer_fired(arg: *mut c_void) {
    // SAFETY: timer_alloc passed its slot, which stays allocated while its coroutine runs.
    let t = unsafe { TIMER_POOL.slot(arg) };
    let ts = t.get();
    let f = ts.f.get().expect("timer without a function");
    ts.runner.set(Some(sched().current()));
    // SAFETY: LKL's timer function (`timer_fn`: triggers the timer IRQ) runs on any thread.
    unsafe { f() };
    ts.runner.set(None);
    // The timer may have sent a signal (an itimer's SIGALRM, a POSIX timer's): a program thread
    // parked in one of the runtime's own waits learns of it only at its next call into the kernel,
    // so cut those waits short (they go back to waiting if there was nothing for them).
    sched().interrupt_waits();
    if ts.release_on_return.replace(false) {
        // Freed by `f` itself. The coroutine returns to `timer_main`, which sees the timer freed
        // and ends without yielding first, so the slot can't be handed out under it.
        t.used.set(false);
    }
}

unsafe extern "C" fn timer_alloc(f: Option<unsafe extern "C" fn()>) -> *mut c_void {
    let Some(f) = f else { return ptr::null_mut() };
    let Some(t) = TIMER_POOL.alloc(TimerSlot::new()) else { return ptr::null_mut() };
    t.get().f.set(Some(f));
    let p = t as *const Slot<TimerSlot> as *mut c_void;
    // SAFETY: timer_fired is the shim for this slot.
    match unsafe { t.get().timer.start(sched(), timer_fired, p) } {
        Ok(()) => p,
        Err(_) => {
            t.used.set(false);
            ptr::null_mut()
        }
    }
}

/// Fire once, `delta` ns from now. Saturating (`Timer::set_oneshot`): LKL's clockevent allows
/// ULONG_MAX, "no event".
unsafe extern "C" fn timer_set_oneshot(timer: *mut c_void, delta: c_ulong) -> c_int {
    // SAFETY: LKL passes what timer_alloc gave it.
    unsafe { TIMER_POOL.slot(timer) }.get().timer.set_oneshot(delta);
    0
}

unsafe extern "C" fn timer_free(timer: *mut c_void) {
    // SAFETY: as timer_set_oneshot.
    let t = unsafe { TIMER_POOL.slot(timer) };
    let ts = t.get();
    let own = ts.runner.get() == Some(sched().current());
    // From another coroutine this waits for the timer's coroutine to end; from its own function
    // it only marks it, and the coroutine ends when the function returns (timer_fired).
    ts.timer.free();
    if own {
        ts.release_on_return.set(true);
    } else {
        t.used.set(false);
    }
}

// ---- jmp_buf ----

const _: () = assert!(size_of::<JmpBuf>() <= size_of::<lkl_jmp_buf>());
const _: () = assert!(align_of::<JmpBuf>() <= align_of::<lkl_jmp_buf>());

/// The shim between `sync::jmp_buf_set`'s `fn(usize)` and LKL's `void (*)(void)`: `f` is the C
/// function (module comment).
unsafe extern "C" fn call_void(f: usize) {
    // SAFETY: jmp_buf_set passed a `unsafe extern "C" fn()` as usize: same size, never null.
    let f: unsafe extern "C" fn() = unsafe { core::mem::transmute::<usize, unsafe extern "C" fn()>(f) };
    // SAFETY: LKL's function, called as it declares it.
    unsafe { f() }
}

unsafe extern "C" fn jmp_buf_set(jb: *mut lkl_jmp_buf, f: Option<unsafe extern "C" fn()>) {
    let Some(f) = f else { return };
    // SAFETY: the jump-back point is in LKL's buffer (big enough: asserted above); the frames a
    // longjmp skips are LKL's C frames and call_void's, nothing to drop; LKL longjmps only from
    // this coroutine (module comment).
    unsafe { sync::jmp_buf_set(jb as *mut JmpBuf, call_void, f as usize) };
}

unsafe extern "C" fn jmp_buf_longjmp(jb: *mut lkl_jmp_buf, val: c_int) {
    // SAFETY: as jmp_buf_set. `val` is only ever 1 (and jmp_buf_set's result unused by LKL).
    unsafe { sync::jmp_buf_longjmp(jb as *const JmpBuf, val as c_uint as usize) }
}

// ---- memory primitives: core's (they compile to the binary's memcpy/memset/memmove) ----

unsafe extern "C" fn memcpy(d: *mut c_void, s: *const c_void, n: c_ulong) -> *mut c_void {
    // SAFETY: the kernel's memcpy contract: valid, non-overlapping.
    unsafe { ptr::copy_nonoverlapping(s as *const u8, d as *mut u8, n as usize) };
    d
}

unsafe extern "C" fn memset(d: *mut c_void, c: c_int, n: c_ulong) -> *mut c_void {
    // SAFETY: the kernel's memset contract.
    unsafe { ptr::write_bytes(d as *mut u8, c as u8, n as usize) };
    d
}

unsafe extern "C" fn memmove(d: *mut c_void, s: *const c_void, n: c_ulong) -> *mut c_void {
    // SAFETY: the kernel's memmove contract: valid, may overlap.
    unsafe { ptr::copy(s as *const u8, d as *mut u8, n as usize) };
    d
}

// ---- host fds as guest files (the kernel series' item 11) ----

/// The one host fd a coroutine waits on, polled by the idle wait (the filter allows `ppoll` on one
/// fd): (fd, events, the waiter).
#[unsafe(link_section = "exobox_shared")]
static FD_WAIT: FdWait = FdWait(Cell::new(None));
struct FdWait(Cell<Option<(i32, i16, Tid)>>);
// SAFETY: as the pools'.
unsafe impl Sync for FdWait {}

const POLLIN: i16 = 1;
const POLLOUT: i16 = 4;
/// How long a waiting coroutine sleeps between polls when the idle wait isn't watching its fd (it
/// watches one; or the program keeps the CPU busy, and idle never runs).
const FD_REPOLL_NS: u64 = 5_000_000;

/// The kernel's "restart this call if no handler says otherwise" (include/linux/errno.h).
const ERESTARTSYS: core::ffi::c_long = 512;

/// `hostfd_rw`: a read or write on the host's fd for a guest file made by `host_fd`, called with
/// the CPU free and the task asleep. The host thread is every coroutine's, so it must not block in
/// the host: poll the fd (through the gate), and until it is ready block the coroutine, the idle
/// wait watching the fd; then the one read or write, which won't block. Through the gate, so the
/// filter decides: reads of 0 and writes of 1 and 2 (the program's stdio) and nothing else.
///
/// **Ends and signals.** The kernel's wait for this is uninterruptible (hostfd.c: the task asleep
/// outside the CPU, as in a disk read), so neither a group exit nor a signal reaches a thread
/// blocked here: its process never ended while a reader waited on a silent stdin (capnix's
/// channel at fd 1000). So the wait is short: one poll interval (or less: it is marked
/// interruptible, `Sched::interrupt_waits`, which a group exit, an exec, a `kill` or a timer
/// wakes), and then, if the fd still isn't ready, `-ERESTARTSYS` with nothing done. The call's
/// return to the program (`syscall_return`, the kernel series' item 8) then sees what is pending:
/// a fatal signal ends the task, a caught one runs its handler and the call restarts under
/// `SA_RESTART` or is `EINTR`, as a pipe's read; with nothing pending the kernel runs the call
/// again, back here. (The kernel-side fix would be hostfd.c waiting interruptibly and the host
/// op being told to give up: see the item-8 notes in `guest`.)
unsafe extern "C" fn hostfd_rw(fd: c_int, buf: *mut c_void, len: c_ulong, write: c_int) -> core::ffi::c_long {
    let events = if write != 0 { POLLOUT } else { POLLIN };
    let zero = crate::xabi::Timespec { tv_sec: 0, tv_nsec: 0 };
    let ready = || {
        let mut p = crate::trap::PollFd { fd, events, revents: 0 };
        crate::trap::ppoll(Some(&mut p), Some(&zero)).map(|n| n > 0)
    };
    match ready() {
        Ok(true) => {}
        Ok(false) => {
            let s = sched();
            let deadline = s.now().saturating_add(FD_REPOLL_NS);
            s.set_interruptible(true);
            if FD_WAIT.0.get().is_none() {
                FD_WAIT.0.set(Some((fd, events, s.current())));
                s.block(Some(deadline));
                FD_WAIT.0.set(None);
            } else {
                s.sleep_until(deadline);
            }
            s.set_interruptible(false);
            match ready() {
                Ok(true) => {}
                Ok(false) => return -ERESTARTSYS,
                Err(e) => return -(e.raw_os_error() as core::ffi::c_long),
            }
        }
        Err(e) => return -(e.raw_os_error() as core::ffi::c_long),
    }
    let r = if write != 0 {
        // SAFETY: the kernel's buffer of len bytes.
        crate::trap::write(fd as u32, unsafe { core::slice::from_raw_parts(buf as *const u8, len as usize) })
    } else {
        // SAFETY: as above, writable.
        crate::trap::read(fd as u32, unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, len as usize) })
    };
    match r {
        Ok(n) => n as core::ffi::c_long,
        Err(e) => -(e.raw_os_error() as core::ffi::c_long),
    }
}

// ---- the production Host: clocks and the idle wait ----

/// The scheduler's [`Host`] in the sandbox: the host's clocks (rustix's vDSO calls: no syscall,
/// so nothing the filter must allow) and, with nothing runnable, a `ppoll` with no fds through the
/// gate (the filter's one wait: at most one pollfd, no signal mask).
#[derive(Debug, Default)]
pub struct SysHost;

fn ns(t: rustix::time::Timespec) -> u64 {
    (t.tv_sec as u64).wrapping_mul(1_000_000_000).wrapping_add(t.tv_nsec as u64)
}

/// A relative timeout of `ns` as a timespec. Can't overflow (u64 ns is under 600 years of
/// seconds), but a deadline far off ("never", saturated to u64::MAX) still becomes a valid,
/// very long wait rather than a negative one.
pub fn timespec(ns: u64) -> rustix::time::Timespec {
    rustix::time::Timespec { tv_sec: (ns / 1_000_000_000) as i64, tv_nsec: (ns % 1_000_000_000) as i64 }
}

impl Host for SysHost {
    fn monotonic(&self) -> u64 {
        ns(rustix::time::clock_gettime(rustix::time::ClockId::Monotonic))
    }

    fn realtime(&self) -> u64 {
        ns(rustix::time::clock_gettime(rustix::time::ClockId::Realtime))
    }

    /// Sleep in `ppoll` until `deadline` or a signal; with no deadline, until a signal. Returning
    /// early is fine: the scheduler checks again.
    fn idle(&self, deadline: Option<u64>) {
        let timeout = match deadline {
            None => None,
            Some(d) => {
                let now = self.monotonic();
                if d <= now {
                    return;
                }
                Some(timespec(d - now))
            }
        };
        let ts = timeout.map(|t| crate::xabi::Timespec { tv_sec: t.tv_sec, tv_nsec: t.tv_nsec });
        // Through the gate (the filter's one wait; rustix's poll would trap once the routing
        // filter is in), watching the host fd a coroutine waits for, if any, and the fds the
        // hooks' executor waits on (`executor::idle_fds`). EINTR (a signal) is a wake-up like any
        // other.
        let mut fds = [crate::trap::PollFd::default(); crate::filter::PPOLL_FDS as usize];
        let own = FD_WAIT.0.get();
        let first = usize::from(own.is_some());
        if let Some((fd, events, _)) = own {
            fds[0] = crate::trap::PollFd { fd, events, revents: 0 };
        }
        let n = first + crate::executor::idle_fds(&mut fds[first..]);
        if let Ok(ready) = crate::trap::ppoll_fds(&mut fds[..n], ts.as_ref())
            && ready > 0
        {
            if let Some((_, _, tid)) = own
                && fds[0].revents != 0
            {
                sched().wake(tid);
            }
            crate::executor::idle_ready(&fds[first..n]);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::{FakeClock, RealClock, new_sched};
    use std::cell::RefCell;

    // The host ops reach their scheduler through a global: one test at a time per process
    // (nextest runs each in its own; under `cargo test` this serializes them), each installing
    // its own scheduler.
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn setup(host: &'static dyn Host, heap_len: usize) -> (std::sync::MutexGuard<'static, ()>, &'static Sched, &'static lkl_host_operations) {
        let guard = LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let s = new_sched(32, host);
        let heap: &'static mut [u8] = Box::leak(vec![0u8; heap_len].into_boxed_slice());
        G.sched.set(None);
        G.heap.live.set(0);
        let ops = unsafe { &*install(s, heap.as_mut_ptr(), heap.len()) };
        (guard, s, ops)
    }

    fn teardown() {
        assert_eq!(SEMS.in_use(), 0, "semaphores leaked");
        assert_eq!(MUTEX_POOL.in_use(), 0, "mutexes leaked");
        assert_eq!(TIMER_POOL.in_use(), 0, "timers leaked");
        G.sched.set(None);
    }

    #[test]
    fn sems_and_mutex_through_the_table() {
        let (_g, s, ops) = setup(FakeClock::leak(), 0);
        unsafe {
            // A coroutine blocks on a semaphore made through the table; up through it releases it.
            let sem = ops.sem_alloc.unwrap()(0);
            let m = ops.mutex_alloc.unwrap()(0);
            assert!(!sem.is_null() && !m.is_null());
            struct A {
                ops: &'static lkl_host_operations,
                sem: *mut lkl_sem,
                m: *mut lkl_mutex,
                log: RefCell<Vec<&'static str>>,
            }
            unsafe extern "C" fn waiter(p: *mut c_void) {
                let a = unsafe { &*(p as *const A) };
                unsafe { a.ops.sem_down.unwrap()(a.sem) };
                a.log.borrow_mut().push("down");
                unsafe { a.ops.mutex_lock.unwrap()(a.m) };
                a.log.borrow_mut().push("locked");
                unsafe { a.ops.mutex_unlock.unwrap()(a.m) };
            }
            let a: &'static A = Box::leak(Box::new(A { ops, sem, m, log: RefCell::new(vec![]) }));
            ops.mutex_lock.unwrap()(m);
            let t = ops.thread_create.unwrap()(Some(waiter), a as *const A as *mut c_void);
            assert_ne!(t, 0);
            s.yield_now();
            assert!(a.log.borrow().is_empty());
            ops.sem_up.unwrap()(sem);
            s.yield_now();
            assert_eq!(*a.log.borrow(), ["down"], "waits for the mutex");
            ops.mutex_unlock.unwrap()(m);
            assert_eq!(ops.thread_join.unwrap()(t), 0);
            assert_eq!(*a.log.borrow(), ["down", "locked"]);
            assert_eq!(ops.thread_join.unwrap()(t), -1, "joined twice");
            ops.sem_free.unwrap()(sem);
            ops.mutex_free.unwrap()(m);
        }
        teardown();
    }

    #[test]
    fn pools_run_out_and_come_back() {
        let (_g, _s, ops) = setup(FakeClock::leak(), 0);
        unsafe {
            let all: Vec<*mut lkl_sem> = (0..SEMAPHORES).map(|_| ops.sem_alloc.unwrap()(1)).collect();
            assert!(all.iter().all(|p| !p.is_null()));
            assert!(ops.sem_alloc.unwrap()(0).is_null(), "full: NULL");
            ops.sem_free.unwrap()(all[7]);
            // The freed one comes back, with its new count (a down doesn't block).
            let again = ops.sem_alloc.unwrap()(1);
            assert_eq!(again, all[7]);
            ops.sem_down.unwrap()(again);
            for p in all {
                ops.sem_free.unwrap()(p);
            }
            let ms: Vec<*mut lkl_mutex> = (0..MUTEXES).map(|_| ops.mutex_alloc.unwrap()(1)).collect();
            assert!(ops.mutex_alloc.unwrap()(0).is_null());
            // Recursive, as asked.
            ops.mutex_lock.unwrap()(ms[0]);
            ops.mutex_lock.unwrap()(ms[0]);
            ops.mutex_unlock.unwrap()(ms[0]);
            ops.mutex_unlock.unwrap()(ms[0]);
            for m in ms {
                ops.mutex_free.unwrap()(m);
            }
        }
        teardown();
    }

    #[test]
    fn heap_bumps_rolls_back_and_resets() {
        let (_g, _s, ops) = setup(FakeClock::leak(), 64 * 1024);
        unsafe {
            let base = G.heap.base.get();
            let pa = ops.page_alloc.unwrap();
            let ma = ops.mem_alloc.unwrap();
            let a = ma(10);
            assert_eq!(a as usize % ALIGN, 0);
            let p = pa(3 * PAGE as c_ulong);
            assert_eq!(p as usize % PAGE, 0);
            assert!(p as usize >= a as usize + 10);
            ptr::write_bytes(p as *mut u8, 0xaa, 3 * PAGE);
            // Too big: NULL, nothing taken.
            let top = G.heap.top.get();
            assert!(pa(1 << 20).is_null());
            assert_eq!(G.heap.top.get(), top);
            // The latest block's free rolls back.
            ops.page_free.unwrap()(p, 3 * PAGE as c_ulong);
            assert_eq!(G.heap.top.get(), a as usize + 10);
            let b = ma(1);
            assert!(!b.is_null());
            // Everything freed: the region starts over (a second boot gets the same pool).
            ops.mem_free.unwrap()(a);
            ops.mem_free.unwrap()(b);
            assert_eq!(G.heap.top.get(), base);
            assert_eq!(pa(16 * 1024) as usize, base.next_multiple_of(PAGE));
            ops.mem_free.unwrap()(ptr::null_mut());
        }
        teardown();
    }

    #[test]
    fn threads_tls_and_stack() {
        let (_g, s, ops) = setup(FakeClock::leak(), 0);
        thread_local! { static DTORS: RefCell<Vec<usize>> = const { RefCell::new(vec![]) }; }
        unsafe extern "C" fn dtor(v: *mut c_void) {
            DTORS.with(|d| d.borrow_mut().push(v as usize));
        }
        struct A {
            ops: &'static lkl_host_operations,
            key: *mut lkl_tls_key,
            stack: Cell<(usize, c_ulong)>,
            me: Cell<lkl_thread_t>,
        }
        unsafe extern "C" fn body(p: *mut c_void) {
            let a = unsafe { &*(p as *const A) };
            let o = a.ops;
            unsafe {
                assert!(o.tls_get.unwrap()(a.key).is_null());
                assert_eq!(o.tls_set.unwrap()(a.key, 42 as *mut c_void), 0);
                assert_eq!(o.tls_get.unwrap()(a.key) as usize, 42);
                let mut size = 0;
                let lo = o.thread_stack.unwrap()(&mut size);
                a.stack.set((lo as usize, size));
                a.me.set(o.thread_self.unwrap()());
                // thread_exit: no return from here.
                o.thread_exit.unwrap()();
            }
            unreachable!()
        }
        unsafe {
            let key = ops.tls_alloc.unwrap()(Some(dtor));
            assert!(!key.is_null());
            let a: &'static A =
                Box::leak(Box::new(A { ops, key, stack: Cell::new((0, 0)), me: Cell::new(0) }));
            let t = ops.thread_create.unwrap()(Some(body), a as *const A as *mut c_void);
            assert_eq!(ops.thread_join.unwrap()(t), 0);
            assert_eq!(a.me.get(), t);
            assert_eq!(ops.thread_equal.unwrap()(t, a.me.get()), 1);
            assert_eq!(ops.thread_equal.unwrap()(t, ops.thread_self.unwrap()()), 0);
            let (lo, size) = a.stack.get();
            assert!(lo != 0 && size as usize >= crate::testutil::STACK - PAGE, "{lo:#x} {size}");
            // The exit ran the destructor with the coroutine's value.
            assert_eq!(DTORS.with(|d| d.borrow().clone()), [42]);
            // The root's stack is unknown: NULL.
            let mut size = 1;
            assert!(ops.thread_stack.unwrap()(&mut size).is_null());
            assert_eq!(size, 0);
            ops.tls_free.unwrap()(key);
            // Detach: reclaimed at its exit without a join.
            unsafe extern "C" fn detaching(p: *mut c_void) {
                let o = unsafe { &*(p as *const lkl_host_operations) };
                unsafe { o.thread_detach.unwrap()() };
            }
            let live = s.live_count();
            let d = ops.thread_create.unwrap()(Some(detaching), ops as *const _ as *mut c_void);
            s.yield_now();
            s.yield_now();
            assert_eq!(s.live_count(), live);
            assert_eq!(ops.thread_join.unwrap()(d), -1);
        }
        teardown();
    }

    thread_local! { static FIRED: RefCell<Vec<u64>> = const { RefCell::new(vec![]) }; }
    thread_local! { static SELF_FREE: Cell<*mut c_void> = const { Cell::new(ptr::null_mut()) }; }

    unsafe extern "C" fn on_timer() {
        FIRED.with(|f| f.borrow_mut().push(sched().now()));
    }
    // Frees its own timer from its function, as the clockevent's shutdown could.
    unsafe extern "C" fn on_timer_free_self() {
        FIRED.with(|f| f.borrow_mut().push(sched().now()));
        let t = SELF_FREE.with(|t| t.get());
        unsafe { (*HOST_OPS.0.get()).timer_free.unwrap()(t) };
    }

    #[test]
    fn timers_fire_saturate_and_free() {
        let clock = FakeClock::leak();
        let (_g, s, ops) = setup(clock, 0);
        unsafe {
            assert_eq!(ops.time.unwrap()(), 0);
            let t = ops.timer_alloc.unwrap()(Some(on_timer));
            assert!(!t.is_null());
            ops.timer_set_oneshot.unwrap()(t, 100);
            s.sleep_until(1_000);
            assert_eq!(FIRED.with(|f| f.borrow().clone()), [100]);
            assert_eq!(ops.time.unwrap()(), 1_000);
            // ULONG_MAX, the clockevent's "no event": never fires, and the idle isn't a spin.
            let idles = clock.idles();
            ops.timer_set_oneshot.unwrap()(t, c_ulong::MAX);
            s.sleep_until(5_000);
            assert_eq!(FIRED.with(|f| f.borrow().len()), 1);
            assert_eq!(clock.idles() - idles, 1);
            let live = s.live_count();
            ops.timer_free.unwrap()(t);
            assert_eq!(s.live_count(), live - 1, "its coroutine ended");

            // Full pool: NULL.
            let ts: Vec<*mut c_void> = (0..TIMERS).map(|_| ops.timer_alloc.unwrap()(Some(on_timer))).collect();
            assert!(ts.iter().all(|t| !t.is_null()));
            assert!(ops.timer_alloc.unwrap()(Some(on_timer)).is_null());
            for t in ts {
                ops.timer_free.unwrap()(t);
            }

            // Freed from its own function: the slot comes back once the function returned.
            let t = ops.timer_alloc.unwrap()(Some(on_timer_free_self));
            SELF_FREE.with(|c| c.set(t));
            ops.timer_set_oneshot.unwrap()(t, 10);
            s.sleep_until(6_000);
            assert_eq!(FIRED.with(|f| f.borrow().len()), 2);
            s.yield_now(); // let the timer's coroutine be reaped
            assert_eq!(TIMER_POOL.in_use(), 0);
            assert_eq!(s.live_count(), live - 1);
        }
        teardown();
    }

    struct J {
        ops: &'static lkl_host_operations,
        jb: UnsafeCell<lkl_jmp_buf>,
        hits: Cell<usize>,
    }
    thread_local! { static JB: Cell<*const J> = const { Cell::new(ptr::null()) }; }
    // LKL's shape: a `void (void)` function that longjmps (here, from a copy of the buffer on its
    // own stack, as __switch_to does) after yielding to the others.
    unsafe extern "C" fn jumps_from_a_copy() {
        let j = unsafe { &*JB.with(|c| c.get()) };
        j.hits.set(j.hits.get() + 1);
        sched().yield_now();
        let mut copy = unsafe { ptr::read(j.jb.get()) };
        unsafe { j.ops.jmp_buf_longjmp.unwrap()(&mut copy, 1) };
        unreachable!()
    }
    unsafe extern "C" fn returns() {
        let j = unsafe { &*JB.with(|c| c.get()) };
        j.hits.set(j.hits.get() + 100);
    }

    #[test]
    fn jmp_buf_through_the_shim() {
        let (_g, _s, ops) = setup(RealClock::leak(), 0);
        let j: &'static J = Box::leak(Box::new(J { ops, jb: UnsafeCell::new(lkl_jmp_buf { buf: [0; 128] }), hits: Cell::new(0) }));
        JB.with(|c| c.set(j));
        unsafe {
            for _ in 0..3 {
                ops.jmp_buf_set.unwrap()(j.jb.get(), Some(jumps_from_a_copy));
            }
            ops.jmp_buf_set.unwrap()(j.jb.get(), Some(returns));
        }
        assert_eq!(j.hits.get(), 103);
        teardown();
    }

    #[test]
    fn print_and_memory_ops() {
        let (_g, _s, ops) = setup(FakeClock::leak(), 0);
        unsafe {
            ops.print.unwrap()(c"host::tests: print reaches stderr\n".as_ptr(), 34);
            ops.print.unwrap()(ptr::null(), 5);
            let mut a = *b"0123456789";
            ops.memmove.unwrap()(a.as_mut_ptr().add(2) as *mut c_void, a.as_ptr() as *const c_void, 5);
            assert_eq!(&a, b"0101234789");
            let src = *b"abc";
            ops.memcpy.unwrap()(a.as_mut_ptr() as *mut c_void, src.as_ptr() as *const c_void, 3);
            ops.memset.unwrap()(a.as_mut_ptr().add(8) as *mut c_void, b'z' as c_int, 2);
            assert_eq!(&a, b"abc12347zz");
        }
        teardown();
    }

    #[test]
    fn sys_host_idles_without_spinning() {
        let h = SysHost;
        let t0 = h.monotonic();
        assert!(h.realtime() > 1_600_000_000 * 1_000_000_000);
        let cpu0 = cpu_ns();
        h.idle(Some(t0 + 20_000_000));
        let el = h.monotonic() - t0;
        assert!(el >= 20_000_000, "{el}");
        assert!(cpu_ns() - cpu0 < 5_000_000, "idle used CPU");
        // A deadline in the past returns at once.
        h.idle(Some(0));
        assert_eq!(timespec(u64::MAX).tv_sec, (u64::MAX / 1_000_000_000) as i64);
        assert_eq!(timespec(1_500_000_001).tv_nsec, 500_000_001);
    }

    fn cpu_ns() -> u64 {
        let mut ru: libc::rusage = unsafe { core::mem::zeroed() };
        unsafe { libc::getrusage(libc::RUSAGE_THREAD, &mut ru) };
        let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
        (us(ru.ru_utime) + us(ru.ru_stime)) * 1000
    }
}
