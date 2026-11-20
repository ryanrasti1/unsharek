//! A small `core::task` executor over the runtime's coroutines, for the networking hooks
//! (`tsi`): their futures, a provider's long-lived sessions among them, run here with real
//! [`Waker`]s, after lockdown.
//!
//! - **One coroutine** runs every task ([`spawn`]): it polls the ready ones in FIFO order (a task
//!   that wakes itself runs again after those already ready), then blocks on the scheduler until
//!   a waker, its next timer or an fd wakes it. Its stack is a coroutine's (unsharek: 128 KiB): a
//!   task's poll runs there.
//! - **Timers** ([`Cx::sleep_until`]) are deadlines on the scheduler's clock (CLOCK_MONOTONIC).
//! - **Host fds** ([`Cx::readable`], [`poll_fd`]): fds the hooks hold (unsharek's `HeldFd`), checked
//!   with a `ppoll` of timeout 0 through the gate; one that isn't ready is watched by the
//!   scheduler's idle wait (`host::SysHost::idle`, threaded mode's idler in `par`: one `ppoll`
//!   over up to eight fds, which the filter allows), and, while the program keeps the CPU busy
//!   and idle never runs, by [`busy_poll`] from the dispatcher's turn-taking (threaded mode: the
//!   idler between hand-offs). Passed fds the guest polls (`tsi`'s `hostfd_poll`) or reads or
//!   writes nonblocking (`host::hostfd_rw`'s EAGAIN) are watched the same way ([`HOSTFDS`], shared
//!   by fork mode's processes); when one is ready the executor tells the kernel
//!   (`lkl_hostfd_ready`).
//!
//! **Modes.** Coroutine mode: one host thread, so the queues are plain cells. The ready queue
//! sits behind a spin lock so a waker may be called from any thread (threaded mode's guest
//! threads call `net_ready` on their own host threads); what threaded mode still needs is the
//! scheduler's `wake` of the executor from another thread, and the CPU token around the
//! executor's calls into the kernel (`tsi::kernel`). Fork mode: the hooks run in init's process
//! only; another process's host ops must forward to it.
//!
//! Allocation: tasks are boxed, queues are `Vec`s: the binary's global allocator, which unsharek
//! serves after lockdown from a region reserved before it.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use core::time::Duration;

use crate::sched::{Sched, Tid};
use crate::trap::{self, PollFd};

pub const POLLIN: i16 = 1;
pub const POLLOUT: i16 = 4;
const POLLERR: i16 = 8;
const POLLHUP: i16 = 16;
/// The busy program's check of the watched fds, at most this often ([`busy_poll`]).
const BUSY_POLL_NS: u64 = 1_000_000;

type Task = Pin<Box<dyn Future<Output = ()>>>;

struct Slot {
    generation: u32,
    fut: Option<Task>,
    /// On the ready queue (or being polled with a wake pending).
    queued: bool,
}

/// One fd a task waits on, until it is ready (then the entry goes: the task looks again).
struct Watch {
    fd: i32,
    events: i16,
    waker: Waker,
}

struct Timer {
    id: u64,
    deadline: u64,
    waker: Waker,
}

struct Exec {
    sched: Cell<Option<&'static Sched>>,
    /// The executor's coroutine, once started.
    tid: Cell<Option<Tid>>,
    /// It waits for work (in `run`'s block), not inside a call (the kernel's CPU, say): only
    /// then does a waker wake it, so no wait of the kernel's is interrupted.
    parked: Cell<bool>,
    slots: RefCell<Vec<Slot>>,
    free: RefCell<Vec<usize>>,
    ready: SpinCell<VecDeque<(u32, u32)>>,
    timers: RefCell<Vec<Timer>>,
    next_timer: Cell<u64>,
    watches: RefCell<Vec<Watch>>,
    /// Of the passed fds watched ([`HOSTFDS`]), the ones found ready: the kernel is told by the
    /// executor's coroutine.
    hostfds_ready: RefCell<Vec<i32>>,
    last_busy_poll: Cell<u64>,
    /// The host-thread slot the executor's coroutine is bound to (`u16::MAX`: none, it runs
    /// wherever the CPU is). Fork mode: init's kernel thread, since the executor's state is init's
    /// process's own memory.
    home: Cell<u16>,
    /// The sandbox's end, waiting for the executor to settle ([`settled`]): woken when it parks.
    drainer: Cell<Option<Tid>>,
}

/// A cell behind a spin lock: the ready queue, pushed to by wakers from wherever they run.
struct SpinCell<T> {
    locked: AtomicBool,
    v: core::cell::UnsafeCell<T>,
}

impl<T> SpinCell<T> {
    const fn new(v: T) -> Self {
        SpinCell { locked: AtomicBool::new(false), v: core::cell::UnsafeCell::new(v) }
    }
    fn with<R>(&self, f: impl FnOnce(&mut T) -> R) -> R {
        while self.locked.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            core::hint::spin_loop();
        }
        // SAFETY: the lock is held; `f` can't re-enter (it only touches the queue).
        let r = f(unsafe { &mut *self.v.get() });
        self.locked.store(false, Ordering::Release);
        r
    }
}

// SAFETY: one host thread runs the executor (see the module comment); the ready queue, which
// wakers reach from anywhere, is behind its lock.
unsafe impl Sync for Exec {}

static E: Exec = Exec {
    sched: Cell::new(None),
    tid: Cell::new(None),
    parked: Cell::new(false),
    slots: RefCell::new(Vec::new()),
    free: RefCell::new(Vec::new()),
    ready: SpinCell::new(VecDeque::new()),
    timers: RefCell::new(Vec::new()),
    next_timer: Cell::new(0),
    watches: RefCell::new(Vec::new()),
    hostfds_ready: RefCell::new(Vec::new()),
    last_busy_poll: Cell::new(0),
    home: Cell::new(u16::MAX),
    drainer: Cell::new(None),
};

/// Passed fds the guest polls (or reads or writes nonblocking) and the host fd isn't ready for:
/// (fd, events; events 0: a free entry), one entry per fd. In the shared section, not the
/// executor's own memory: in fork mode a forked process's guest files are watched too, by init's
/// process, whose idle wait (threaded mode's idler) polls them and whose executor tells the
/// kernel. Touched only with the CPU token held. Entries go when they fire; a watch past the
/// table's end is dropped (one per host fd: there are as many as the sandbox was given).
#[unsafe(link_section = "unsharek_shared")]
static HOSTFDS: HostFds = HostFds([const { Cell::new((0, 0)) }; 16]);
struct HostFds([Cell<(i32, i16)>; 16]);
// SAFETY: touched with the CPU token held (one host thread at a time).
unsafe impl Sync for HostFds {}

impl HostFds {
    fn each(&self) -> impl Iterator<Item = (i32, i16)> + '_ {
        self.0.iter().map(Cell::get).filter(|x| x.1 != 0)
    }
    fn is_empty(&self) -> bool {
        self.each().next().is_none()
    }
}

/// Bind the executor's coroutine to host-thread slot `home` (fork mode: init's kernel thread).
/// Before it starts.
pub fn set_home(home: u16) {
    E.home.set(home);
}

/// Run the executor on `sched` (the guest's, at boot). Its coroutine starts with the first task.
pub fn install(sched: &'static Sched) {
    E.sched.set(Some(sched));
}

fn sched() -> &'static Sched {
    E.sched.get().expect("executor::install not called")
}

/// Whether the executor runs (the guest booted).
pub fn installed() -> bool {
    E.sched.get().is_some()
}

/// Whether the calling coroutine is the executor's. Its syscalls (a hook's library's: capnweb-rs's
/// stacker reads /proc/self/maps) are the host's own, made as the kernel's tsi task
/// (`tsi::host_syscall`), never as a thread of the program's.
pub fn on_executor() -> bool {
    installed() && E.tid.get().is_some_and(|t| t == sched().current())
}

/// Whether the executor has nothing left to do but wait for the outside: parked (or never
/// started), nothing ready, and no task waiting to write to a held fd (a provider's session still
/// flushing). Waits for reads (a session's reader, forever) and timers don't count.
pub fn settled() -> bool {
    let writing = E.watches.try_borrow().map_or(true, |w| w.iter().any(|x| x.events & POLLOUT != 0));
    (E.tid.get().is_none() || E.parked.get()) && E.ready.with(|q| q.is_empty()) && !writing
}

/// Block the calling coroutine (not the executor's) until the executor parks, or `deadline`.
pub fn wait_parked(deadline: u64) {
    let s = sched();
    E.drainer.set(Some(s.current()));
    s.block(Some(deadline));
    E.drainer.set(None);
}

// ---- tasks and wakers ----

/// Run `f` to completion on the executor, in the background.
pub fn spawn(f: impl Future<Output = ()> + 'static) {
    let fut: Task = Box::pin(f);
    let i = match E.free.borrow_mut().pop() {
        Some(i) => i,
        None => {
            let mut slots = E.slots.borrow_mut();
            slots.push(Slot { generation: 0, fut: None, queued: false });
            slots.len() - 1
        }
    };
    let generation = {
        let mut slots = E.slots.borrow_mut();
        let s = &mut slots[i];
        s.fut = Some(fut);
        s.queued = true;
        s.generation
    };
    E.ready.with(|q| q.push_back((i as u32, generation)));
    start();
}

/// The executor's coroutine, made if it isn't yet, and woken if it waits.
fn start() {
    let s = sched();
    match E.tid.get() {
        Some(t) => {
            if E.parked.get() {
                s.wake(t);
            }
        }
        None => {
            let t = s.spawn(run, 0).expect("no coroutine for the hooks' executor");
            let _ = s.detach(t);
            if E.home.get() != u16::MAX {
                s.bind(t, E.home.get());
            }
            E.tid.set(Some(t));
        }
    }
}

fn waker_of(i: u32, generation: u32) -> Waker {
    let data = ((generation as usize) << 32) | i as usize;
    // SAFETY: the vtable's functions treat the data as a number, never a pointer.
    unsafe { Waker::from_raw(RawWaker::new(data as *const (), &VTABLE)) }
}

static VTABLE: RawWakerVTable = RawWakerVTable::new(w_clone, w_wake, w_wake, w_drop);

fn w_clone(d: *const ()) -> RawWaker {
    RawWaker::new(d, &VTABLE)
}

fn w_wake(d: *const ()) {
    let d = d as usize;
    let (i, generation) = (d as u32, (d >> 32) as u32);
    // A task's slot is only read under the ready queue's lock here: queued is set with it held.
    let push = E.ready.with(|q| {
        // SAFETY: slots is only resized by spawn on the executor's thread; a stale index (a slot
        // freed and reused) is caught by the generation.
        let slots = unsafe { &mut *E.slots.as_ptr() };
        match slots.get_mut(i as usize) {
            // (a task being polled has no future in its slot, and may wake itself)
            Some(s) if s.generation == generation && !s.queued => {
                s.queued = true;
                q.push_back((i, generation));
                true
            }
            _ => false,
        }
    });
    if push
        && E.parked.get()
        && let Some(t) = E.tid.get()
    {
        sched().wake(t);
    }
}

fn w_drop(_: *const ()) {}

/// Poll every task that was ready when this began.
fn run_ready() {
    let n = E.ready.with(|q| q.len());
    for _ in 0..n {
        let Some((i, generation)) = E.ready.with(|q| q.pop_front()) else { break };
        let fut = {
            let mut slots = E.slots.borrow_mut();
            let s = &mut slots[i as usize];
            if s.generation != generation {
                continue;
            }
            E.ready.with(|_| s.queued = false);
            s.fut.take()
        };
        let Some(mut fut) = fut else { continue };
        let waker = waker_of(i, generation);
        let mut cx = Context::from_waker(&waker);
        let done = fut.as_mut().poll(&mut cx).is_ready();
        if done {
            // Dropped with no borrow held: its drop may spawn or wake.
            drop(fut);
            let mut slots = E.slots.borrow_mut();
            let s = &mut slots[i as usize];
            // Its wakers are stale from now on.
            E.ready.with(|_| {
                s.generation = s.generation.wrapping_add(1);
                s.queued = false;
            });
            drop(slots);
            E.free.borrow_mut().push(i as usize);
        } else {
            E.slots.borrow_mut()[i as usize].fut = Some(fut);
        }
    }
}

/// The executor's coroutine.
fn run(_: usize) -> usize {
    let s = sched();
    loop {
        run_ready();
        let now = s.now();
        fire_timers(now);
        poll_watches();
        tell_hostfds();
        if !E.ready.with(|q| q.is_empty()) {
            // The others get a turn between rounds: tasks that keep waking each other must not
            // keep the program from running.
            s.yield_now();
            continue;
        }
        let deadline = E.timers.borrow().iter().map(|t| t.deadline).min();
        // Woken by a waker (`sched.wake`), its timer, or the idle wait's fds (their wakers).
        E.parked.set(true);
        if let Some(d) = E.drainer.get() {
            s.wake(d);
        }
        s.block(deadline);
        E.parked.set(false);
    }
}

// ---- time ----

/// The executor's clock: CLOCK_MONOTONIC ns, the scheduler's.
pub fn now() -> u64 {
    sched().now()
}

fn fire_timers(now: u64) {
    let due: Vec<Waker> = {
        let mut t = E.timers.borrow_mut();
        let mut due = Vec::new();
        t.retain(|x| {
            if x.deadline <= now {
                due.push(x.waker.clone());
                false
            } else {
                true
            }
        });
        due
    };
    for w in due {
        w.wake();
    }
}

/// A future ready at `deadline` (CLOCK_MONOTONIC ns): [`Cx::sleep_until`].
#[derive(Debug)]
pub struct Sleep {
    deadline: u64,
    id: u64,
}

impl Future for Sleep {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if now() >= self.deadline {
            return Poll::Ready(());
        }
        let mut timers = E.timers.borrow_mut();
        if let Some(t) = timers.iter_mut().find(|t| t.id == self.id && self.id != 0) {
            t.waker.clone_from(cx.waker());
        } else {
            let id = E.next_timer.get() + 1;
            E.next_timer.set(id);
            self.id = id;
            timers.push(Timer { id, deadline: self.deadline, waker: cx.waker().clone() });
        }
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if self.id != 0 {
            E.timers.borrow_mut().retain(|t| t.id != self.id);
        }
    }
}

// ---- host fds ----

/// `fd`'s `events` (POLLIN, POLLOUT) ready now (or POLLERR/POLLHUP), by a `ppoll` with timeout 0.
pub fn fd_ready(fd: i32, events: i16) -> i16 {
    let zero = crate::xabi::Timespec { tv_sec: 0, tv_nsec: 0 };
    let mut p = PollFd { fd, events, revents: 0 };
    match trap::ppoll(Some(&mut p), Some(&zero)) {
        Ok(n) if n > 0 => p.revents,
        _ => 0,
    }
}

/// Ready if host fd `fd` has `events` (or an error or hangup) now; else `cx`'s waker is woken
/// when it may have. For the fds the hooks hold (the filter allows `ppoll` on any fd; reads and
/// writes only on held ones).
pub fn poll_fd(fd: i32, events: i16, cx: &mut Context<'_>) -> Poll<()> {
    if fd_ready(fd, events) != 0 {
        return Poll::Ready(());
    }
    let mut w = E.watches.borrow_mut();
    if !w.iter().any(|x| x.fd == fd && x.events == events && x.waker.will_wake(cx.waker())) {
        w.push(Watch { fd, events, waker: cx.waker().clone() });
    }
    Poll::Pending
}

/// A future ready once `fd` has `events`: [`Cx::readable`], [`Cx::writable`].
#[derive(Debug)]
pub struct FdReady {
    fd: i32,
    events: i16,
}

impl Future for FdReady {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        poll_fd(self.fd, self.events, cx)
    }
}

/// A passed fd the guest polls whose host fd isn't ready: watched until it is, then the kernel
/// is told (`tsi`'s `hostfd_poll`).
pub fn watch_hostfd(fd: i32, events: i16) {
    let h = &HOSTFDS.0;
    match h.iter().find(|x| x.get().1 != 0 && x.get().0 == fd).or_else(|| h.iter().find(|x| x.get().1 == 0)) {
        Some(x) => x.set((fd, x.get().1 | events)),
        None => return,
    }
    // A forked process's watch is init's process's to poll and tell (its idle wait, its
    // executor): this process's copy of the executor is no executor.
    if !crate::par::forked() {
        start();
    }
}

/// Whether the idle wait has fds of the executor's to watch (threaded mode's idler is then handed
/// the CPU token, `par`'s `give`). In a forked process the tasks' watches are a stale copy of
/// init's: at worst the idler is handed the token for nothing.
pub fn watching() -> bool {
    !HOSTFDS.is_empty() || E.watches.try_borrow().map_or(true, |w| !w.is_empty())
}

/// The fds the idle wait should watch, after the ones it watches itself: up to `out.len()`,
/// the tasks' and then the guest's passed fds (any beyond are seen by the executor's own polls).
pub fn idle_fds(out: &mut [PollFd]) -> usize {
    let mut n = 0;
    let mut add = |fd: i32, events: i16| {
        if let Some(p) = out[..n].iter_mut().find(|p| p.fd == fd) {
            p.events |= events;
        } else if n < out.len() {
            out[n] = PollFd { fd, events, revents: 0 };
            n += 1;
        }
    };
    if let Ok(w) = E.watches.try_borrow() {
        for x in w.iter() {
            add(x.fd, x.events);
        }
    }
    for (fd, events) in HOSTFDS.each() {
        add(fd, events);
    }
    n
}

/// The idle wait's results for the fds [`idle_fds`] gave: whoever waits on a ready one is woken.
pub fn idle_ready(fds: &[PollFd]) {
    for p in fds.iter().filter(|p| p.revents != 0) {
        fd_fired(p.fd, p.revents);
    }
}

fn fd_fired(fd: i32, revents: i16) {
    let any = revents | if revents & (POLLERR | POLLHUP) != 0 { POLLIN | POLLOUT } else { 0 };
    let wake: Vec<Waker> = {
        let Ok(mut w) = E.watches.try_borrow_mut() else { return };
        let mut wake = Vec::new();
        w.retain(|x| {
            if x.fd == fd && x.events & any != 0 {
                wake.push(x.waker.clone());
                false
            } else {
                true
            }
        });
        wake
    };
    for w in wake {
        w.wake();
    }
    let mut fired = false;
    if let Ok(mut r) = E.hostfds_ready.try_borrow_mut() {
        for x in &HOSTFDS.0 {
            let (xfd, events) = x.get();
            if events != 0 && xfd == fd && events & any != 0 {
                x.set((0, 0));
                r.push(fd);
                fired = true;
            }
        }
    }
    // Woken if it waits, made if it never ran (a forked process's watch is the first).
    if fired {
        start();
    }
}

/// Every watched fd, polled without waiting (the executor's turn, and [`busy_poll`]).
fn poll_watches() {
    let mut fds = [PollFd::default(); crate::trap::PPOLL_FDS as usize];
    loop {
        // In batches: more fds than one ppoll takes are polled in several.
        let all: Vec<(i32, i16)> = {
            let w = E.watches.borrow();
            let mut all: Vec<(i32, i16)> = Vec::new();
            for (fd, ev) in w.iter().map(|x| (x.fd, x.events)).chain(HOSTFDS.each()) {
                match all.iter_mut().find(|a| a.0 == fd) {
                    Some(a) => a.1 |= ev,
                    None => all.push((fd, ev)),
                }
            }
            all
        };
        if all.is_empty() {
            return;
        }
        let zero = crate::xabi::Timespec { tv_sec: 0, tv_nsec: 0 };
        let mut any = false;
        for chunk in all.chunks(fds.len()) {
            for (p, &(fd, events)) in fds.iter_mut().zip(chunk) {
                *p = PollFd { fd, events, revents: 0 };
            }
            if let Ok(n) = trap::ppoll_fds(&mut fds[..chunk.len()], Some(&zero))
                && n > 0
            {
                any = true;
                for p in &fds[..chunk.len()] {
                    if p.revents != 0 {
                        fd_fired(p.fd, p.revents);
                    }
                }
            }
        }
        if !any {
            return;
        }
        // Fired entries are gone; another round only if more were watched than one ppoll takes.
        if all.len() <= fds.len() {
            return;
        }
    }
}

/// From the dispatcher's turn-taking (a program busy enough that the idle wait doesn't run): the
/// watched fds polled, at most once a millisecond.
pub fn busy_poll() {
    if !installed() || E.tid.get().is_none() {
        return;
    }
    let now = sched().now();
    if now.saturating_sub(E.last_busy_poll.get()) < BUSY_POLL_NS {
        return;
    }
    E.last_busy_poll.set(now);
    if E.watches.try_borrow().is_ok_and(|w| w.is_empty()) && HOSTFDS.is_empty() {
        return;
    }
    poll_watches();
}

/// The passed fds found ready: the kernel wakes the guest's pollers (from the executor's own
/// coroutine, never from a host op or the idle wait).
fn tell_hostfds() {
    let ready: Vec<i32> = core::mem::take(&mut *E.hostfds_ready.borrow_mut());
    for fd in ready {
        crate::tsi::kernel(|| {
            // SAFETY: the kernel runs; called from the executor's coroutine.
            unsafe { lkl_sys::lkl_hostfd_ready(fd) }
        });
    }
}

// ---- the hooks' handle ----

/// The hooks' handle on the executor: spawn tasks, the clock, timers, held fds. A plain token
/// (`Copy`, `Send`, `Sync`): there is one executor per sandbox. It is what a no_std async
/// protocol core's runtime needs (capnweb's `Runtime { spawn, now, sleep_until }`).
#[derive(Clone, Copy, Debug, Default)]
pub struct Cx;

impl Cx {
    /// Run `f` in the background, to completion (a provider's session, say).
    pub fn spawn(&self, f: impl Future<Output = ()> + 'static) {
        spawn(f)
    }

    /// Monotonic time since an arbitrary origin (CLOCK_MONOTONIC).
    pub fn now(&self) -> Duration {
        Duration::from_nanos(now())
    }

    /// Ready once [`Cx::now`] reaches `deadline`.
    pub fn sleep_until(&self, deadline: Duration) -> Sleep {
        Sleep { deadline: u64::try_from(deadline.as_nanos()).unwrap_or(u64::MAX), id: 0 }
    }

    /// Ready once host fd `fd` (one the hooks hold) is readable, or has an error or hangup.
    pub fn readable(&self, fd: i32) -> FdReady {
        FdReady { fd, events: POLLIN }
    }

    /// Ready once host fd `fd` is writable, or has an error or hangup.
    pub fn writable(&self, fd: i32) -> FdReady {
        FdReady { fd, events: POLLOUT }
    }
}
