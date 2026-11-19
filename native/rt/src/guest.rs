//! The guest in coroutine mode: boot on the scheduler, the dispatcher every trapped syscall goes
//! through, and the program's exec. The pieces (`sched`, `host`, `trap`, `sysmap`, `xabi`,
//! `arena`, `futex`, `exec`) joined.
//!
//! **Threads.** One host thread. Its root coroutine (the thread's own stack) boots the kernel, so
//! its guest task is init (PID 1, the kernel series' item 4): the setup closure run before exec
//! and then the program's main thread are init. Each program thread made by `clone` is a
//! coroutine of its own whose control stack (the coroutine's stack) holds its trap frames and the
//! dispatcher's calls; the program runs on its own stack, in the arena.
//!
//! **Phases.** [`Phase::Setup`]: after the routing filter (`route`), the host code that runs as
//! init before exec (`exobox::Guest::run`'s closure): its syscalls trap and are served here, by
//! the guest; its memory (host `mmap` and friends, made by the host's libc) stays the host's, so
//! the memory calls are passed through the gate to the host, until [`host_memory`]`(false)` says
//! the mode's filter (which allows none of them) is about to go in. [`Phase::Program`]: after
//! [`exec`], the program's memory is the arena's.
//!
//! **What the dispatcher does with each route** (`sysmap`): `Lkl` is `lkl_syscall` on the current
//! coroutine's guest task (a new thread's first call is `attach_thread`, item 5); `Rewrite` as
//! `sysmap` describes, with `xabi`'s translations; `Emulate`: memory in the arena, threads as
//! coroutines, futexes on the scheduler (`futex`), the thread pointer in the trap frame; `Errno`
//! its errno. Pointers the emulations dereference are checked against the arena first (EFAULT);
//! those passed to LKL are LKL's to read (it has no MMU: a bad one is a fault in the sandbox),
//! except where programs pass bad ones on purpose (`statx`: Rust's probe, `Rewrite::Statx`).
//!
//! **Ends.** A task's end comes back from the kernel as the `task_exit` host op (item 6), on the
//! task's own coroutine: init's (pid 1, after its exit ran in the guest) ends the sandbox with
//! its status; another thread's ends its coroutine.
//!
//! **Signals** are the kernel's (item 8): actions, masks, `kill`, default actions. At a call's
//! return to the program the kernel takes a pending caught signal and calls the
//! `signal_handler` host op ([`signal_handler`]), which runs the program's handler as Linux
//! would on that trap: a frame on the program's stack (see "Signal delivery" below), the
//! handler entered as the program, its own calls trapped as any, and its `rt_sigreturn` (which
//! traps: the filter allows it only from the gate) handing the registers, mask and alternate
//! stack back to the kernel's half of sigreturn. A default action that ends the process comes
//! back as `task_exit` with the signal, and the sandbox dies of the same signal ([`die`]).

use core::cell::{Cell, UnsafeCell};
use core::ffi::{CStr, c_long};
use core::mem::size_of;

use lkl_sys as l;
use rustix::io::Errno;

use crate::arena::{self, Arena, Backing, Extent, FileMap};
use crate::context::{self, JmpBuf, ProgramCall, Registers};
use crate::exec::{self, Files, Scratch, StackParams};
use crate::filter::{self, Deny, Params, Policy, Program as Filter};
use crate::futex::{self, Futexes};
use crate::host::{self, SysHost};
use crate::memblk;
use crate::par;
use crate::sched::{Config, Sched, Stacks, Tid};
use crate::sync::TlsKey;
use crate::sysmap::{self, Emulate, Rewrite, Route, StatForm, k, lkl};
use crate::trap::{self, StackT, Ucontext};
use crate::xabi::{self, Itimerval, LklSigaction, LklStat, Timespec, Timeval, X86Sigaction, X86Stat};

mod fork;
pub use fork::enable_fork;

/// The `thread_exit` host op's fork-mode case (`fork::bootstrap_exit`): a fork's child whose clone
/// failed ends its process. Returns otherwise.
pub(crate) fn fork_thread_exit() {
    fork::bootstrap_exit()
}

/// A static only this host thread touches (coroutine mode: one host thread, cooperative).
struct Local<T>(UnsafeCell<T>);
// SAFETY: one host thread uses the guest's state (see the module comment).
unsafe impl<T> Sync for Local<T> {}
impl<T> Local<T> {
    const fn new(v: T) -> Self {
        Local(UnsafeCell::new(v))
    }
    #[allow(clippy::mut_from_ref)]
    /// # Safety
    /// No other reference to the value is live (cooperative: nothing switches while it's used,
    /// or the user guards it, as the arena does).
    unsafe fn get(&self) -> &mut T {
        // SAFETY: the caller's.
        unsafe { &mut *self.0.get() }
    }
}

// The scheduler and the futex table: fork mode's processes share them (`share`).
#[unsafe(link_section = "exobox_shared")]
static SCHED: Sched = Sched::new();
static SYS: SysHost = SysHost;
#[unsafe(link_section = "exobox_shared")]
static FUTEXES: Local<Futexes> = Local::new(Futexes::new());

/// The program's futexes (shared references only: its methods take `&self`).
fn futexes() -> &'static Futexes {
    // SAFETY: only ever borrowed shared.
    unsafe { &*FUTEXES.0.get() }
}
static ARENA_TABLE: Local<[Extent; arena::CAPACITY]> = Local::new([Extent::EMPTY; arena::CAPACITY]);
static ARENA: Local<Option<Arena<'static>>> = Local::new(None);
static SCRATCH: Local<Scratch> = Local::new(Scratch::new());
static FILTER: Local<Filter> = Local::new(Filter::new());
/// The root's alternate signal stack, where SIGSYS lands before the entry moves the frame.
static ALTSTACK: Local<[u8; trap::ALTSTACK_SIZE]> = Local::new([0; trap::ALTSTACK_SIZE]);

/// Where the guest is: what its trapped syscalls are served as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Booted, no filter: nothing traps yet.
    Booted,
    /// The routing filter is in; host code runs as init (see the module comment), on the thread
    /// that began it ([`intercept_begin`]): other threads' calls pass through.
    Setup,
    /// The routing filter is in, no setup runs: every trapped call is re-issued on the host
    /// (`passthrough`), until the next [`intercept_begin`] or the exec.
    Passthrough,
    /// The program runs.
    Program,
}

/// Program threads (and the root) at once.
const THREADS: usize = 512;
/// The program's main stack, mapped in the arena at exec (Linux's default `RLIMIT_STACK`).
const STACK: usize = 8 << 20;

/// A program thread's runtime state; slot 0 is the root's.
struct Thread {
    used: Cell<bool>,
    /// Its coroutine (`Tid::raw`).
    co: Cell<u64>,
    /// The guest tid `new_thread` made for it, until its first LKL call attaches it (0: none).
    attach: Cell<i32>,
    /// `CLONE_CHILD_CLEARTID` / `set_tid_address`: zeroed and futex-woken at its exit.
    clear_tid: Cell<usize>,
    // Signal delivery's per-thread state, for both modes ([`cur`]: threaded mode's by host slot).
    /// The trap being served (its ucontext), innermost first: the registers a handler interrupts.
    uc: Cell<usize>,
    /// The innermost handler the runtime is running for this thread (a [`SigRec`] in
    /// [`signal_handler`]'s frame), 0: none.
    sig_top: Cell<usize>,
    /// The program's mask while the runtime's own calls in this dispatch run with every signal
    /// blocked ([`lkl_quiet`]); restored at the dispatch's end ([`unquiet`]).
    quiet: Cell<Option<u64>>,
    /// Handlers run, and whether the last was `SA_RESTART`: a woken futex wait learns from them
    /// whether its probe ran one ([`futex_call`]).
    handled: Cell<u32>,
    handled_restart: Cell<bool>,
    /// Fork mode, during a clone that makes a process: the child's stack (0: the parent's) and FS
    /// base, for the `fork` host op inside the call (`fork::fork_op`).
    fork_sp: Cell<usize>,
    fork_fs: Cell<usize>,
}

impl Thread {
    /// A slot taken by a new thread, or freed: no trap, no handler.
    fn reset_signals(&self) {
        self.uc.set(0);
        self.sig_top.set(0);
        self.quiet.set(None);
    }
}

struct State {
    phase: Cell<Phase>,
    host_memory: Cell<bool>,
    /// The arena, `[lo, hi)`: what program pointers must lie in.
    arena_lo: Cell<usize>,
    arena_hi: Cell<usize>,
    /// An arena operation is in progress (it may suspend in a `Backing` call to LKL).
    arena_busy: Cell<bool>,
    /// The root's stack pointer when it started the program: its trap frames go below this.
    root_top: Cell<usize>,
    /// The scheduler TLS key holding each coroutine's `Thread` index + 1.
    key: Cell<Option<TlsKey>>,
    threads: [Thread; THREADS],
    /// Each signal's restorer (`rt_sigaction`'s `sa_restorer`, which LKL has no field for).
    restorers: [Cell<usize>; 65],
    /// Calls served, for the dispatcher's turn-taking.
    served: Cell<u32>,
    /// The sandbox's host pid ([`die`]: the one `kill` the filter allows). A host fork's child
    /// finds it isn't its own ([`forked`]).
    host_pid: Cell<u32>,
    /// The host thread whose calls the setup phase routes to the guest ([`intercept_begin`]).
    setup_tid: Cell<u32>,
    /// Whether the routing filter is in ([`route`]).
    routed: Cell<bool>,
    /// The host's auxiliary vector values, for every exec.
    aux: Cell<Aux>,
    /// The running program's absolute path (STOPGAP(item 10): `/proc/self/exe`).
    exe_len: Cell<usize>,
}

static S: State = State {
    phase: Cell::new(Phase::Booted),
    host_memory: Cell::new(true),
    arena_lo: Cell::new(0),
    arena_hi: Cell::new(0),
    arena_busy: Cell::new(false),
    root_top: Cell::new(0),
    key: Cell::new(None),
    threads: [const {
        Thread {
            used: Cell::new(false),
            co: Cell::new(0),
            attach: Cell::new(0),
            clear_tid: Cell::new(0),
            uc: Cell::new(0),
            sig_top: Cell::new(0),
            quiet: Cell::new(None),
            handled: Cell::new(0),
            handled_restart: Cell::new(false),
            fork_sp: Cell::new(0),
            fork_fs: Cell::new(0),
        }
    }; THREADS],
    restorers: [const { Cell::new(0) }; 65],
    served: Cell::new(0),
    host_pid: Cell::new(0),
    setup_tid: Cell::new(0),
    routed: Cell::new(false),
    aux: Cell::new(Aux { hwcap: 0, hwcap2: 0, sysinfo_ehdr: 0, minsigstksz: 0 }),
    exe_len: Cell::new(0),
};

// SAFETY: one host thread (see `Local`).
unsafe impl Sync for State {}

// ------------------------------------------------------------------------------------------------
// Boot.

/// What [`boot`] needs: memory the caller reserved before (host `mmap`, `MAP_NORESERVE`).
pub struct Boot<'a> {
    /// The program's arena, `(base, len)`: page-aligned, read/write/execute, zero, with
    /// `filter::MADV_CHUNK` bytes of the reservation past `len` (the filter's `madvise` bound).
    pub arena: (usize, usize),
    /// How much of the arena, at its end, is the image zone (`arena::Arena::set_image_zone`,
    /// `memblk`): where the caller maps images to be mapped in place from. 0 for none.
    pub image_zone: usize,
    /// The kernel's memory: `mem=` of `cmdline` plus a page.
    pub heap: (*mut u8, usize),
    /// The coroutines' stacks (kernel threads and program threads' control stacks).
    pub stacks: Stacks,
    /// The kernel's command line (`mem=` among it).
    pub cmdline: &'a CStr,
}

/// An error of the guest's setup: what failed, and the errno.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Error {
    pub what: &'static str,
    pub errno: Errno,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.what, self.errno)
    }
}

fn err(what: &'static str) -> impl Fn(Errno) -> Error {
    move |errno| Error { what, errno }
}

/// Boot the guest on the calling host thread, which becomes the scheduler's root coroutine and
/// init's thread. Once per process. Nothing traps until [`route`].
///
/// # Safety
/// The regions in `b` are this guest's from now on, as `Boot` describes them; the calling thread
/// is the only one that will use the guest.
pub unsafe fn boot(b: Boot) -> Result<(), Error> {
    // SAFETY: the caller's regions and thread.
    unsafe {
        SCHED.init(Config { stacks: b.stacks, switch_fs: true, host: &SYS }).map_err(err("coroutine stacks"))?;
        host::install(&SCHED, b.heap.0, b.heap.1);
        crate::executor::install(&SCHED);
        let table: &'static mut [Extent] = &mut ARENA_TABLE.get()[..];
        let mut a = Arena::new(b.arena.0, b.arena.1, arena::Mode::Release, table).map_err(err("arena"))?;
        if b.image_zone != 0 {
            a.set_image_zone(b.arena.0 + b.arena.1 - b.image_zone).map_err(err("the image zone"))?;
        }
        *ARENA.get() = Some(a);
    }
    S.arena_lo.set(b.arena.0);
    S.arena_hi.set(b.arena.0 + b.arena.1);
    let key = TlsKey::alloc(&SCHED, None).ok_or(Error { what: "a TLS key", errno: Errno::NOMEM })?;
    S.key.set(Some(key));
    // SAFETY: getpid, before lockdown.
    S.host_pid.set(unsafe { trap::gate(39, 0, 0, 0, 0, 0, 0) } as u32);
    let root = &S.threads[0];
    root.used.set(true);
    root.co.set(SCHED.current().raw());
    key.set(&SCHED, 1);
    // SAFETY: the static alternate stack is this (the only) host thread's.
    unsafe {
        trap::set_altstack(ALTSTACK.get().as_mut_ptr(), trap::ALTSTACK_SIZE).map_err(err("sigaltstack"))?;
        trap::install(dispatch, target).map_err(err("the SIGSYS handler"))?;
    }
    // SAFETY: the table and its scheduler are installed; one kernel per process. The table is
    // written only here, before the kernel reads it.
    let r = unsafe {
        (*host::ops()).task_exit = Some(task_exit);
        (*host::ops()).signal_handler = Some(signal_handler);
        l::lkl_init(host::ops())
    };
    if r < 0 {
        return Err(Error { what: "lkl_init", errno: Errno::from_raw_os_error(-r) });
    }
    // SAFETY: as above. From the root: its task becomes init (the kernel series' item 4).
    let r = unsafe { l::lkl_start_kernel(b.cmdline.as_ptr()) };
    if r < 0 {
        return Err(Error { what: "lkl_start_kernel", errno: Errno::from_raw_os_error(-r) });
    }
    Ok(())
}

/// Install the routing-only filter (`filter::Policy::RouteOnly`) on the calling thread (and the
/// threads it makes from now on): from now on every syscall of its not from the gate traps, and
/// is served by the guest in the setup phase ([`intercept_begin`]) or re-issued on the host
/// otherwise (`passthrough`). Once; the phase becomes [`Phase::Passthrough`].
pub fn route() -> Result<(), Error> {
    if S.routed.get() {
        return Ok(());
    }
    let p = Params { policy: Policy::RouteOnly, deny: Deny::Kill, gate_ip: trap::gate_ip(), arena: &[], token_fds: (0, 0), pid: 0, extra: &[] };
    // SAFETY: the static program, used only here and in `lock`, one at a time.
    let prog = unsafe { FILTER.get() };
    filter::compile(&p, prog).map_err(|_| Error { what: "the routing filter", errno: Errno::INVAL })?;
    // The calling thread only, in every mode: other host threads of the process stay unrouted
    // until the mode's filter is synced to them at lockdown (the kernel idler makes only gate
    // calls). Routed with TSYNC, another thread's calls would have trapped during setup.
    filter::install(prog, 0).map_err(err("installing the routing filter"))?;
    S.routed.set(true);
    S.phase.set(Phase::Passthrough);
    Ok(())
}

/// The host thread's id (gettid, through the gate).
fn host_tid() -> u32 {
    // SAFETY: gettid.
    unsafe { trap::gate(186, 0, 0, 0, 0, 0, 0) as u32 }
}

/// Begin a setup phase: from now on the calling thread's trapped calls are the guest's, as init
/// (the routing filter must be in: [`route`]). The thread is the boot thread (the root
/// coroutine's); its alternate signal stack is the runtime's again, in case host code changed it
/// in passthrough.
pub fn intercept_begin() -> Result<(), Error> {
    if !S.routed.get() {
        return Err(Error { what: "intercept before the routing filter", errno: Errno::INVAL });
    }
    if par::enabled() {
        par::rearm_altstack();
    } else {
        // SAFETY: the root's static alternate stack, this (the boot) thread's.
        unsafe { trap::set_altstack(ALTSTACK.get().as_mut_ptr(), trap::ALTSTACK_SIZE) }.map_err(err("sigaltstack"))?;
    }
    S.setup_tid.set(host_tid());
    S.phase.set(Phase::Setup);
    Ok(())
}

/// End a setup phase: trapped calls pass through to the host again ([`Phase::Passthrough`]).
pub fn intercept_end() {
    if S.phase.get() == Phase::Setup {
        S.phase.set(Phase::Passthrough);
    }
}

/// Whether this process is a host fork's child that hasn't taken the guest over yet
/// ([`fork_child`]): its pid isn't the one the guest was booted (or last taken over) in.
pub fn forked() -> bool {
    // SAFETY: getpid.
    let pid = unsafe { trap::gate(39, 0, 0, 0, 0, 0, 0) } as u32;
    S.host_pid.get() != 0 && pid != S.host_pid.get()
}

/// Before a host fork of the sandbox's process (a template's): in threaded mode the CPU token
/// is taken, so the fork copies the kernel at rest (not mid-timer on the idler thread). Returns
/// what [`fork_parent`] needs. Host code, outside a setup phase.
pub fn fork_prepare() -> Option<u16> {
    par::enabled().then(par::enter)
}

/// The parent's side after the fork: the token given back.
pub fn fork_parent(token: Option<u16>) {
    if let Some(id) = token {
        par::leave(id);
    }
}

/// A host fork's child takes the guest over: the guest's pid is this process's (the filter's
/// `kill` and [`die`]), and in threaded mode the host-thread state the fork didn't copy is made
/// again (`par::after_fork`: the CPU-token eventfds, which a fork shares with the parent, and
/// the kernel idler thread, which it doesn't copy; `spawn_idler` starts it). Then
/// `token`, if [`fork_prepare`] took it, is given back. The guest's RNG is the caller's to reseed
/// (its state is the parent's copy).
pub fn fork_child(token: Option<u16>, spawn_idler: impl FnOnce()) -> Result<(), Error> {
    // SAFETY: getpid.
    S.host_pid.set(unsafe { trap::gate(39, 0, 0, 0, 0, 0, 0) } as u32);
    if par::enabled() {
        par::after_fork(&SCHED).map_err(err("threaded mode after a fork"))?;
        spawn_idler();
        par::wait_kernel_ready();
        par::leave(token.unwrap_or(0));
    }
    Ok(())
}

/// Switch the runtime to threaded mode (a host thread per program thread): bind the main thread,
/// make the CPU-token eventfds (before lockdown), set memory high-water (the mode filter refuses
/// `madvise`), and install the scheduler driver. Returns the token eventfds' inclusive fd range,
/// for the mode filter. Call once, after [`boot`] and before [`route`], on the main thread. The
/// caller must also start the kernel idler host thread on [`threaded_kernel_main`].
pub fn enable_threaded() -> Result<(u32, u32), Error> {
    with_arena(|a, _| a.set_mode(arena::Mode::HighWater));
    // SAFETY: once, on the main (boot) thread, before lockdown.
    unsafe { par::enable(&SCHED, SCHED.current()) }.map_err(err("enabling threaded mode"))
}

/// The body of threaded mode's kernel idler host thread (the caller spawns it before [`route`]).
/// Never returns.
pub fn threaded_kernel_main() -> ! {
    par::kernel_main()
}

/// Wait until the kernel idler host thread has installed its signal stack: the main thread calls
/// this after spawning it and before [`route`] (whose filter is synced to every thread).
pub fn threaded_wait_ready() {
    par::wait_kernel_ready()
}

/// The arena as the mode filter's `madvise` range (inclusive): `filter::Params::arena`.
pub fn arena_range() -> (u64, u64) {
    (S.arena_lo.get() as u64, S.arena_hi.get() as u64 - 1)
}

/// Whether setup-phase memory calls may still go to the host (false just before the mode's
/// filter goes in: it allows none of them; afterwards `mmap` fails with ENOMEM and the rest do
/// nothing).
pub fn host_memory(allowed: bool) {
    S.host_memory.set(allowed);
}

/// The current phase.
pub fn phase() -> Phase {
    S.phase.get()
}

/// A guest syscall from runtime code (generic number), as the current coroutine's task. In
/// threaded mode with the CPU token held for it, as a trap's dispatch holds it: setup code calls
/// this directly, not through a trap (without the token, the kernel ran on two host threads at
/// once: the kernel idler's timer and setup's call, and LKL's CPU owner came out wrong).
pub fn syscall(nr: c_long, a: [usize; 6]) -> isize {
    with_token(|| lkl_call(nr, a))
}

/// `f` holding threaded mode's CPU token, for runtime code that isn't a trap's dispatch (which
/// takes it itself). Nothing extra in coroutine mode.
fn with_token<R>(f: impl FnOnce() -> R) -> R {
    if !par::enabled() {
        return f();
    }
    let id = par::enter();
    let r = f();
    par::leave(id);
    r
}

// ------------------------------------------------------------------------------------------------
// Exec: the program, from the guest's files, into the arena.

/// The values of the initial auxiliary vector that come from the host.
#[derive(Clone, Copy, Debug, Default)]
pub struct Aux {
    pub hwcap: u64,
    pub hwcap2: u64,
    /// The host's vDSO (`AT_SYSINFO_EHDR`): the program's clocks without a syscall.
    pub sysinfo_ehdr: u64,
    pub minsigstksz: u64,
}

/// Load `path` from the guest's files into the arena, build its stack and start it on this
/// (the root) coroutine, as init. Returns only if the program can't be loaded, with the errno an
/// `execve` would give. From the setup phase (after [`route`]), on the root.
pub fn exec(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], aux: Aux) -> Errno {
    S.aux.set(aux);
    // The loader's calls are the kernel's: in threaded mode with the CPU token (not a trap's
    // dispatch, which takes it itself), given up as the program starts.
    let loaded = with_token(|| {
        let r = load(path, argv, envp, false);
        // The loader's calls ran with signals blocked: the program starts with init's mask.
        unquiet(cur());
        r
    });
    match loaded {
        Ok(regs) => {
            // Everything this function's callers have on the root's stack is dead from here: the
            // root's trap frames go below this point (`target`).
            let sp: usize;
            // SAFETY: reads rsp.
            unsafe { core::arch::asm!("mov {}, rsp", out(reg) sp, options(nomem, nostack)) };
            S.root_top.set(sp - 256);
            S.phase.set(Phase::Program);
            // SAFETY: the program's state as Linux's exec leaves it; FS unset (0), as a new
            // process's: its ld.so sets it with arch_prctl. No Rust code runs between the two.
            unsafe {
                core::arch::asm!("wrfsbase {}", in(reg) 0usize, options(nomem, nostack));
                context::restore(&regs)
            }
        }
        Err(e) => e,
    }
}

/// Open, check and map a program, and build its stack. With `replace`, the old image (the whole
/// arena) is dropped first, once nothing can fail any more short of memory: the guest's execve.
fn load(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], replace: bool) -> Result<Registers, Errno> {
    let aux = S.aux.get();
    let mut g = Guest;
    // SAFETY: the loader's scratch is used only here, once.
    let scratch = unsafe { SCRATCH.get() };
    let mut random = [0u8; 16];
    let r = lkl_quiet(l::__lkl__NR_getrandom, [random.as_mut_ptr() as usize, 16, 0, 0, 0, 0]);
    if r != 16 {
        return Err(Errno::IO);
    }
    // The program's credentials are init's as they are now (setup may have changed them:
    // setresuid in a guard), as Linux's exec takes the task's.
    let id = |nr| lkl_quiet(nr, [0; 6]) as u32;
    let p = StackParams {
        execfn: path,
        argv,
        envp,
        uid: id(l::__lkl__NR_getuid),
        euid: id(l::__lkl__NR_geteuid),
        gid: id(l::__lkl__NR_getgid),
        egid: id(l::__lkl__NR_getegid),
        random,
        hwcap: aux.hwcap,
        hwcap2: aux.hwcap2,
        sysinfo_ehdr: aux.sysinfo_ehdr,
        minsigstksz: aux.minsigstksz,
        // The gate function itself (what the escape tests call), not the address past its syscall.
        gate: trap::gate as *const () as u64,
    };
    let prog = exec::Program::open(&mut g, scratch, path)?;
    if let Err(e) = prog.stack_bytes(&p, STACK) {
        prog.close(&mut g);
        return Err(e);
    }
    // The point of no return: the new image is checked, the old one still mapped (the kernel
    // walks its robust futex list). The kernel's half of the exec (item 10): the other threads
    // end, close-on-exec files close, caught signals' actions reset, the alternate stack goes,
    // the task is named after the file. Its other threads die at their next call into the kernel:
    // those parked in the runtime's own waits are woken to make one (the kill is sent before
    // they run: they need the CPU, or in threaded mode the token, which this thread keeps until
    // new_exec waits for them).
    SCHED.interrupt_waits();
    if replace {
        // The old image's shared file mappings written back while the arena's fds for them are
        // open: new_exec closes them (close-on-exec), and the unmap below only finds them closed.
        writeback();
    }
    if let Err(e) = new_exec(path) {
        prog.close(&mut g);
        return Err(e);
    }
    cur().sig_top.set(0);
    set_exe(path);
    with_arena(|a, b| {
        if replace {
            // The point of no return. Shared file mappings are written back as they go.
            let (lo, hi) = (S.arena_lo.get(), S.arena_hi.get());
            let _ = a.munmap(b, lo, hi - lo);
        }
        let r = (|| {
            let img = prog.map(a, b)?;
            let lo = a.mmap(b, 0, STACK, arena::PROT_READ | arena::PROT_WRITE, arena::MAP_PRIVATE | arena::MAP_ANONYMOUS, None)?;
            // SAFETY: just mapped, read/write, the program's from now on.
            let start = unsafe { img.build_stack(lo, lo + STACK, &p) }?;
            Ok(start.registers())
        })();
        if replace && r.is_err() {
            // The old image is gone: Linux kills a process that fails here (SIGSEGV).
            finish(128 + 11);
        }
        r
    })
}

// ------------------------------------------------------------------------------------------------
// The guest's files and memory, as the loader and the arena see them: guest fds through LKL.

struct Guest;

fn res(r: isize) -> Result<usize, Errno> {
    if r < 0 { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

/// The NUL-terminated copy of a path for LKL (the loader's paths have none).
static PATH: Local<[u8; exec::PATH_MAX + 1]> = Local::new([0; exec::PATH_MAX + 1]);

/// `path` NUL-terminated in [`PATH`], for one LKL call.
fn c_path(path: &[u8]) -> Result<usize, Errno> {
    if path.len() >= exec::PATH_MAX || path.contains(&0) {
        return Err(Errno::NAMETOOLONG);
    }
    // SAFETY: used only for the duration of the caller's calls, which don't touch it again.
    let buf = unsafe { PATH.get() };
    buf[..path.len()].copy_from_slice(path);
    buf[path.len()] = 0;
    Ok(buf.as_ptr() as usize)
}

/// The kernel's half of an exec (`new_exec`, item 10), as the exec-ing thread.
fn new_exec(path: &[u8]) -> Result<(), Errno> {
    let p = c_path(path)?;
    res(lkl_quiet(l::__lkl__NR_new_exec, [p, 0, 0, 0, 0, 0])).map(|_| ())
}

impl Files for Guest {
    fn open(&mut self, path: &[u8]) -> arena::Result<u64> {
        let p = c_path(path)?;
        // Not close-on-exec: the exec's kernel half (`new_exec`) runs between this open and the
        // mapping, which closes the file (`exec::Program::map`).
        const O_RDONLY: usize = 0;
        // execve's checks: a regular file this user may execute.
        const X_OK: usize = 1;
        res(lkl_quiet(lkl::FACCESSAT as c_long, [k::AT_FDCWD as isize as usize, p, X_OK, 0, 0, 0]))?;
        let fd = res(lkl_quiet(lkl::OPENAT as c_long, [k::AT_FDCWD as isize as usize, p, O_RDONLY, 0, 0, 0]))?;
        let mut st = LklStat::default();
        let r = res(lkl_quiet(lkl::FSTAT as c_long, [fd, &mut st as *mut _ as usize, 0, 0, 0, 0]));
        if r.is_err() || st.st_mode & 0o170000 != 0o100000 {
            lkl_quiet(l::__lkl__NR_close, [fd, 0, 0, 0, 0, 0]);
            return Err(r.err().unwrap_or(Errno::ACCESS));
        }
        Ok(fd as u64)
    }

    fn size(&mut self, file: u64) -> arena::Result<u64> {
        let mut st = LklStat::default();
        res(lkl_quiet(lkl::FSTAT as c_long, [file as usize, &mut st as *mut _ as usize, 0, 0, 0, 0]))?;
        Ok(st.st_size as u64)
    }

    fn pread(&mut self, file: u64, offset: u64, buf: &mut [u8]) -> arena::Result<usize> {
        res(lkl_quiet(l::__lkl__NR_pread64, [file as usize, buf.as_mut_ptr() as usize, buf.len(), offset as usize, 0, 0]))
    }

    fn close_file(&mut self, file: u64) {
        lkl_quiet(l::__lkl__NR_close, [file as usize, 0, 0, 0, 0, 0]);
    }
}

impl Backing for Guest {
    fn read(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> arena::Result<usize> {
        // An image's file from its host mapping, not through the kernel's page cache (`memblk`).
        // SAFETY: the arena's range being filled, nothing else's.
        if let Some(n) = unsafe { memblk::pread(lkl_quiet, file as usize, offset, addr, len) } {
            return Ok(n);
        }
        res(lkl_quiet(l::__lkl__NR_pread64, [file as usize, addr, len, offset as usize, 0, 0]))
    }

    fn write(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> arena::Result<usize> {
        res(lkl_quiet(l::__lkl__NR_pwrite64, [file as usize, addr, len, offset as usize, 0, 0]))
    }

    fn retain(&mut self, file: u64) -> arena::Result<u64> {
        const F_GETFL: usize = 3;
        const F_DUPFD_CLOEXEC: usize = 1030;
        const O_ACCMODE: usize = 3;
        const O_RDWR: usize = 2;
        let fl = res(lkl_quiet(lkl::FCNTL as c_long, [file as usize, F_GETFL, 0, 0, 0, 0]))?;
        if fl & O_ACCMODE != O_RDWR {
            return Err(Errno::ACCESS);
        }
        // A high fd, out of the way of the program's own numbering (it is in its table).
        res(lkl_quiet(lkl::FCNTL as c_long, [file as usize, F_DUPFD_CLOEXEC, 512, 0, 0, 0])).map(|f| f as u64)
    }

    fn close(&mut self, file: u64) {
        lkl_quiet(l::__lkl__NR_close, [file as usize, 0, 0, 0, 0, 0]);
    }

    fn release(&mut self, addr: usize, len: usize) -> arena::Result<()> {
        // SAFETY: the arena gives back only pages nothing relies on.
        unsafe { trap::madvise_dontneed(addr, len) }
    }

    fn locate(&mut self, file: u64, offset: u64) -> Option<(usize, u64)> {
        memblk::locate(lkl_quiet, file as usize, offset)
    }
}

/// Run `f` with the arena. An arena call can suspend (its `Backing` calls LKL); another coroutine
/// wanting the arena meanwhile waits its turn.
fn with_arena<R>(f: impl FnOnce(&mut Arena<'static>, &mut Guest) -> R) -> R {
    while S.arena_busy.get() {
        SCHED.yield_now();
    }
    S.arena_busy.set(true);
    // SAFETY: arena_busy keeps every other user out until we're done.
    let a = unsafe { ARENA.get() }.as_mut().expect("guest not booted");
    let r = f(a, &mut Guest);
    S.arena_busy.set(false);
    r
}

/// `[p, p + len)` is program memory the runtime may read or write: in the arena (in the setup
/// phase, host code's memory: anything not NULL).
fn user(p: usize, len: usize) -> bool {
    if S.phase.get() != Phase::Program {
        return p != 0;
    }
    match p.checked_add(len) {
        Some(end) => p >= S.arena_lo.get() && end <= S.arena_hi.get(),
        None => false,
    }
}

/// Read a `T` the program passed, or EFAULT.
fn read_user<T: Copy>(p: usize) -> Result<T, Errno> {
    if !user(p, size_of::<T>()) {
        return Err(Errno::FAULT);
    }
    // SAFETY: checked to be program memory; unaligned reads are fine for these plain structs.
    Ok(unsafe { (p as *const T).read_unaligned() })
}

/// Write a `T` to where the program asked, or EFAULT.
fn write_user<T: Copy>(p: usize, v: T) -> Result<(), Errno> {
    if !user(p, size_of::<T>()) {
        return Err(Errno::FAULT);
    }
    // SAFETY: as read_user.
    unsafe { (p as *mut T).write_unaligned(v) };
    Ok(())
}

// ------------------------------------------------------------------------------------------------
// Threads.

fn key() -> TlsKey {
    S.key.get().expect("guest not booted")
}

/// The current coroutine's `Thread`, bound on its first call (a new thread's slot was filled by
/// its parent's `clone`, which can't set the child's TLS).
fn me() -> &'static Thread {
    let v = key().get(&SCHED);
    if v != 0 {
        return &S.threads[v - 1];
    }
    let co = SCHED.current().raw();
    let i = S.threads.iter().position(|t| t.used.get() && t.co.get() == co).unwrap_or_else(|| {
        // A coroutine that wasn't made by clone (none should trap): a slot of its own.
        let i = S.threads.iter().position(|t| !t.used.get()).expect("thread table full");
        let t = &S.threads[i];
        t.used.set(true);
        t.co.set(co);
        i
    });
    key().set(&SCHED, i + 1);
    &S.threads[i]
}

/// `lkl_syscall` as the current coroutine's task (attaching a new thread's first).
fn lkl_call(nr: c_long, a: [usize; 6]) -> isize {
    if crate::executor::on_executor() {
        // The hooks' own calls (a library's) are the host's, never a thread of init's.
        return crate::tsi::host_syscall(nr, a);
    }
    // Threaded mode keeps the per-thread attach word in the host-thread record (the bound
    // coroutine is reached by a trap, not the per-coroutine TLS `me()`).
    let tid = if par::enabled() { par::take_attach() } else { me().attach.replace(0) };
    if tid != 0 {
        let mut p = [tid as c_long, 0, 0, 0, 0, 0];
        // SAFETY: the kernel runs; attach_thread takes the thread new_thread made for us.
        let r = unsafe { l::lkl_syscall(l::__lkl__NR_attach_thread, p.as_mut_ptr()) };
        debug_assert_eq!(r, 0, "attach_thread({tid})");
    }
    let mut p = a.map(|v| v as c_long);
    // SAFETY: the kernel runs; the arguments are the program's (LKL reads its pointers) or ours.
    unsafe { l::lkl_syscall(nr, p.as_mut_ptr()) as isize }
}

/// The current program thread's runtime state: coroutine mode's by coroutine ([`me`]), threaded
/// mode's by host thread (`par`'s slot, the same index into the table).
fn cur() -> &'static Thread {
    if par::enabled() { &S.threads[par::my_id() as usize] } else { me() }
}

/// `lkl_call` for the runtime's own calls in a dispatch (the loader's, the arena's file I/O, a
/// clone's `new_thread`): a call's return is where the kernel delivers signals, and a handler must
/// not run in the middle of the runtime's work (the arena held, an exec half done, a clone's
/// child not made yet). So the first such call of a dispatch blocks every signal, and the
/// dispatch's end restores the program's mask ([`unquiet`]), whose return delivers what came
/// meanwhile, as at the program's call's return. Two more calls, only for dispatches that make
/// calls of their own (file mappings, exec), not the forwarded ones.
fn lkl_quiet(nr: c_long, a: [usize; 6]) -> isize {
    let t = cur();
    if t.quiet.get().is_none() {
        const SIG_SETMASK: usize = 2;
        let (all, mut old) = (!0u64, 0u64);
        let r = lkl_call(
            l::__lkl__NR_rt_sigprocmask,
            [SIG_SETMASK, &all as *const u64 as usize, &mut old as *mut u64 as usize, 8, 0, 0],
        );
        if r == 0 {
            t.quiet.set(Some(old));
        }
    }
    lkl_call(nr, a)
}

/// The end of a dispatch's quiet calls ([`lkl_quiet`]): the program's mask back.
fn unquiet(t: &Thread) {
    if let Some(old) = t.quiet.take() {
        const SIG_SETMASK: usize = 2;
        lkl_call(l::__lkl__NR_rt_sigprocmask, [SIG_SETMASK, &old as *const u64 as usize, 0, 8, 0, 0]);
    }
}

const CLONE_VM: usize = 0x100;
const CLONE_VFORK: usize = 0x4000;
const CLONE_THREAD: usize = 0x1_0000;
const CLONE_SETTLS: usize = 0x8_0000;
const CLONE_PARENT_SETTID: usize = 0x10_0000;
const CLONE_CHILD_CLEARTID: usize = 0x20_0000;
const CLONE_CHILD_SETTID: usize = 0x100_0000;

/// `clone(flags, newsp, ptid, ctid, tls)` for a thread: a guest thread of the caller's process
/// (`new_thread`) and a coroutine that resumes the program after the `syscall` with rax = 0 on
/// `newsp`, its first LKL call `attach_thread`. Processes (fork, vfork): coroutine mode has none.
fn clone(uc: &Ucontext, a: [usize; 6]) -> Result<usize, Errno> {
    let (flags, newsp, ptid, ctid, tls) = (a[0], a[1], a[2], a[3], a[4]);
    if flags & CLONE_THREAD == 0 && fork::enabled() {
        // A process: a host fork (fork mode).
        return fork::clone_process(uc, a);
    }
    if flags & (CLONE_VM | CLONE_THREAD) != CLONE_VM | CLONE_THREAD || flags & CLONE_VFORK != 0 {
        // Processes: only fork mode has them.
        return Err(Errno::NOSYS);
    }
    if newsp == 0 {
        return Err(Errno::INVAL);
    }
    if (flags & CLONE_PARENT_SETTID != 0 && !user(ptid, 4))
        || (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 && !user(ctid, 4))
    {
        return Err(Errno::FAULT);
    }
    let coroutine_slot = if par::enabled() { 0 } else { S.threads.iter().position(|t| !t.used.get()).ok_or(Errno::AGAIN)? };
    let tid = res(lkl_quiet(l::__lkl__NR_new_thread, [0; 6]))?;
    #[cfg(debug_assertions)]
    if TEST_PANIC_CLONE.swap(false, core::sync::atomic::Ordering::Relaxed) {
        panic!("runtime_panic.c's test hook, in a clone");
    }
    let m = &uc.mcontext;
    let regs = Registers {
        rax: 0,
        rbx: m.rbx,
        rcx: m.rcx,
        rdx: m.rdx,
        rsi: m.rsi,
        rdi: m.rdi,
        rbp: m.rbp,
        rsp: newsp as u64,
        r8: m.r8,
        r9: m.r9,
        r10: m.r10,
        r11: m.r11,
        r12: m.r12,
        r13: m.r13,
        r14: m.r14,
        r15: m.r15,
        rip: m.rip,
    };
    let fs = if flags & CLONE_SETTLS != 0 { tls } else { m.fs_base as usize };
    let clear_tid = if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 };
    if par::enabled() {
        // Threaded mode: a host thread of its own for the new program thread, which starts in user
        // mode. If it can't be made, the guest thread new_thread made is left (ended later).
        par::spawn_thread(&regs, fs, tid as i32, clear_tid, uc).map_err(|_| Errno::AGAIN)?;
    } else {
        // SAFETY: the program's own state after its `clone`, as Linux starts the child.
        // TODO: on failure the guest thread new_thread made stays, never run (item 6 will end it).
        let co: Tid = unsafe { SCHED.spawn_registers(&regs, fs) }.map_err(|_| Errno::AGAIN)?;
        let _ = SCHED.detach(co);
        let t = &S.threads[coroutine_slot];
        t.used.set(true);
        t.co.set(co.raw());
        t.attach.set(tid as i32);
        t.clear_tid.set(clear_tid);
        t.reset_signals();
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        write_user(ptid, tid as u32)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        write_user(ctid, tid as u32)?;
    }
    Ok(tid)
}

/// The sandbox ends with `code`: the host's exit. In a fork's child process, only that process
/// ends, and as the guest's: its exit_group, whose status its parent waits for (`task_exit` then
/// ends the host process).
fn finish(code: i32) -> ! {
    if par::forked() {
        lkl_call(l::__lkl__NR_exit_group, [code as usize, 0, 0, 0, 0, 0]);
    }
    trap::exit_group(code)
}

/// The process is about to end: its writable shared file mappings written back while the files
/// the arena holds for them are still open (init's exit closes them).
fn writeback() {
    if S.phase.get() == Phase::Program {
        let _ = with_arena(|a, b| a.writeback_all(b));
    }
}

/// `exit_group`: the guest ends the process's threads; the calling one's end comes back as
/// `task_exit`, init's last (pid 1) with the status.
fn exit_group(code: usize) -> ! {
    writeback();
    if par::enabled() && !par::forked() {
        // Threaded mode: end the whole sandbox at once (the gate's `exit_group` ends every host
        // thread), the status the program's own. Through the kernel, a thread running user code
        // would hold the end up until its next call (threads in the runtime's own waits are
        // woken, as in coroutine mode: `task_exit`), and only this process is in the sandbox.
        // Fork mode's init too: its end is the sandbox's (the other processes see its pidfd).
        // A fork's child goes through the kernel: its parent waits for the status.
        finish(code as i32 & 0xff);
    }
    lkl_call(l::__lkl__NR_exit_group, [code, 0, 0, 0, 0, 0]);
    // Only if the kernel refused (it doesn't): end anyway.
    finish(code as i32 & 0xff)
}

/// A thread's `exit`: its tid word cleared and woken, then the guest's exit, which comes back as
/// `task_exit`.
fn exit_thread(code: usize) -> ! {
    let ct = if par::enabled() { par::take_clear_tid() } else { me().clear_tid.replace(0) };
    if ct != 0 && write_user(ct, 0u32).is_ok() {
        futexes().wake_in(&SCHED, par::proc_id(), ct, 1, futex::FUTEX_BITSET_MATCH_ANY);
    }
    if !par::enabled() && S.threads.iter().filter(|t| t.used.get()).count() == 1 {
        // The process's last thread: its exit is the process's. (Threaded mode writes back when
        // the process ends, through the kernel's init-ending; a lone `exit` is rare there.)
        writeback();
    }
    lkl_call(l::__lkl__NR_exit, [code, 0, 0, 0, 0, 0]);
    finish(code as i32 & 0xff)
}

/// The `task_exit` host op (item 6): the calling coroutine's task ended in its syscall, the CPU
/// released and LKL's TLS for it cleared. pid 1: init's end, the sandbox's, with its wait status:
/// an exit code, or a signal the sandbox then dies of ([`die`]). Otherwise a thread: its
/// coroutine ends.
///
/// A thread's end may be its process's (exit_group, a fatal signal: the kernel has sent every
/// other thread its kill before this one ends): the threads parked in the runtime's own waits (an
/// emulated futex, a host fd) aren't in the kernel to be ended, so they are woken to make a call,
/// at which the kernel ends them (`futex_call`, `host::hostfd_rw`). Without it a process whose
/// other thread waited in a futex, or read a silent stdin, never ended.
unsafe extern "C" fn task_exit(pid: core::ffi::c_int, status: core::ffi::c_int) {
    if pid == 1 {
        // The program's sockets were closed by its exit: what they still hold reaches the hooks
        // first (bounded).
        crate::tsi::drain();
        if status & 0x7f == 0 {
            finish((status >> 8) & 0xff);
        }
        die(status & 0x7f);
    }
    SCHED.interrupt_waits();
    cur().reset_signals();
    if par::enabled() {
        if pid != 0 && par::forked() {
            // A fork's child process's last task: the host process ends (fork mode).
            par::process_exited(par::my_id());
        }
        // A program thread's guest task ended: end its host thread (its Sched coroutine is freed
        // when the slot is reused). Never returns.
        par::thread_exited(par::my_id());
    }
    let t = me();
    if core::ptr::eq(t, &S.threads[0]) {
        // The root is the host thread and can't end: init's main thread ended before its other
        // threads (pthread_exit from main). It has nothing left to run.
        loop {
            SCHED.block(None);
        }
    }
    t.co.set(0);
    t.used.set(false);
    SCHED.exit(0)
}

// ------------------------------------------------------------------------------------------------
// Numbers the dispatcher looks at before routing.

const NR_READLINK: usize = 89;
const NR_READLINKAT: usize = 267;
const NR_RT_SIGRETURN: u64 = 15;
/// The test hook's call ([`serve`]; debug builds): out of the x86-64 table, so ENOSYS natively.
#[cfg(debug_assertions)]
const TEST_PANIC: usize = 0x4558;
#[cfg(debug_assertions)]
static TEST_PANIC_CLONE: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// Calls that send a signal: after one, the threads parked in the runtime's own waits are woken
/// to take it (`SCHED.interrupt_waits`). kill, tkill, tgkill, rt_sigqueueinfo,
/// rt_tgsigqueueinfo, pidfd_send_signal.
fn sends_signal(nr: usize) -> bool {
    matches!(nr, 62 | 200 | 234 | 129 | 297 | 424)
}

// ------------------------------------------------------------------------------------------------
// Signal delivery (the kernel series' item 8): the program's handlers, run by the runtime.
//
// The kernel decides everything but running the handler: which signal, when (a call's return to
// the program), the handler's mask, `SA_RESETHAND`, restart or `EINTR`, the default actions. It
// calls `signal_handler` inside the call's `lkl_syscall`, with the CPU released, on the trapped
// thread's coroutine (in threaded mode its host thread), deep in the dispatch of the trap. From
// there, as Linux's `setup_rt_frame` (arch/x86/kernel/signal_64.c) would:
//
// - **The frame.** Below the trapped sp and its red zone, or at the top of the alternate stack
//   (`SA_ONSTACK`, a stack set, not already on it): the FPU state (the trap's xsave area, copied,
//   64-aligned), then `struct rt_sigframe`: the return address (the program's restorer, kept from
//   its `rt_sigaction`: LKL's sigaction has none), a kernel `ucontext` (the trap's registers,
//   `uc_sigmask` the mask the kernel will restore, `uc_stack` the thread's alternate stack) and
//   the siginfo. sp % 16 == 8 at the handler, as if called.
// - **The call.** `context::call_program` saves the runtime's place (a [`SigRec`] in this frame,
//   linked from the thread's `sig_top`) and jumps to `handler(sig, &info, &uc)` on that stack, as
//   the program: its FS, a fresh FPU control state; in threaded mode without the CPU token. The
//   handler's own calls trap as any: their frames go below the saved place ([`handler_top`], the
//   target hook's answer while a handler runs), and they may block, nest other handlers, exec.
// - **The return.** The program's restorer makes `rt_sigreturn`, which traps (the filter allows
//   it only from the gate). [`sigreturn`] finds the record whose frame it names, copies the
//   frame's registers (the handler may have changed them: Go's preemption, musl's cancellation)
//   and FPU state into the trap the handler interrupted, its `uc_sigmask` and `uc_stack` to where
//   the kernel reads them back, and jumps back into `signal_handler`, which returns to the kernel
//   1 (the call restarts if it would) or 0 if the program counter moved (`EINTR`).
// - **A handler that never returns** (`siglongjmp`): its record and the dispatch frames above it
//   are dead. The target hook drops records whose handler the program has left (its sp above the
//   frame, or off the alternate stack it ran on) before placing the next trap's frame, so 50
//   `siglongjmp`s don't stack 50 dispatches. The kernel holds nothing across the op.
// - **Not at a program call.** A handler must not run in the middle of the runtime's own work: its
//   own calls in a dispatch run with signals blocked (`lkl_quiet`). A signal for a thread parked
//   in a wait of the runtime's (an emulated futex, a host fd) is taken when it is woken
//   (`Sched::interrupt_waits`: after a `kill`, a timer, a thread's end) and makes a call.
//
// Known limits: a signal for a thread running user code waits for its next call into the kernel
// (the series leaves out interrupting user code); faults (SIGSEGV, SIGFPE) are the host's and end
// the sandbox, not the program's handlers'.

const SA_ONSTACK: u64 = 0x0800_0000;
const SA_RESTART: u64 = 0x1000_0000;
const SS_DISABLE: i32 = 2;
const SIGABRT: i32 = 6;
const SIGSEGV: i32 = 11;
const SIGPIPE: i32 = 13;
const SIGSYS: i32 = 31;
/// How far below its frame a handler on the program's own stack is still taken to be running.
const HANDLER_REACH: usize = 16 << 20;

/// A handler the runtime is running for a thread, in [`signal_handler`]'s frame.
struct SigRec {
    /// The next outer one (0: none).
    prev: usize,
    /// The `rt_sigframe`'s start (its return address): the handler's `rt_sigreturn` traps with sp
    /// just above it.
    frame: usize,
    /// The alternate stack it runs on, `[lo, hi)`, if it was switched to.
    alt: Option<(usize, usize)>,
    /// The runtime's place: the handler's traps go below it.
    jmp: JmpBuf,
    /// The trap the handler interrupted (its ucontext), and its program counter then.
    uc: usize,
    rip: u64,
    /// Its FPU state's size (the copy in the frame).
    fp_len: usize,
    /// Where the kernel reads back the mask and alternate stack sigreturn restores.
    mask: *mut u64,
    stack: *mut StackT,
}

impl SigRec {
    /// Whether the program, trapping at `sp`, is still inside this handler.
    fn live(&self, sp: usize) -> bool {
        match self.alt {
            Some((lo, _)) => sp >= lo && sp < self.frame,
            None => sp < self.frame && self.frame - sp < HANDLER_REACH,
        }
    }
}

/// # Safety
/// `r` is a live record of the current thread's (`sig_top`'s chain).
unsafe fn rec<'a>(r: usize) -> &'a SigRec {
    // SAFETY: the caller's.
    unsafe { &*(r as *const SigRec) }
}

/// The target hook's answer for a program trap while handlers run: below the innermost one's
/// saved place, after dropping those the program has left (a `siglongjmp`). An `rt_sigreturn`
/// names its own handler (sp is its frame + 8). `None`: no handler runs.
fn handler_top(uc: &Ucontext) -> Option<usize> {
    let t = cur();
    let sp = uc.mcontext.rsp as usize;
    let mut r = t.sig_top.get();
    if uc.mcontext.rax == NR_RT_SIGRETURN {
        while r != 0 {
            // SAFETY: the chain's records are live until popped here.
            let x = unsafe { rec(r) };
            if x.frame.wrapping_add(8) == sp {
                t.sig_top.set(r);
                return Some(x.jmp.sp());
            }
            r = x.prev;
        }
        r = t.sig_top.get();
    }
    // SAFETY: as above.
    while r != 0 && !unsafe { rec(r) }.live(sp) {
        r = unsafe { rec(r) }.prev;
    }
    t.sig_top.set(r);
    // SAFETY: as above.
    (r != 0).then(|| unsafe { rec(r) }.jmp.sp())
}

/// The size of the FPU state at `fp` (a frame's xsave area): `fpstate`'s `sw_reserved` says, when
/// its magic is there (`FP_XSTATE_MAGIC1`), else the legacy 512 bytes.
///
/// # Safety
/// `fp` is 0 or a frame's FPU state.
unsafe fn fpstate_len(fp: usize) -> usize {
    if fp == 0 {
        return 0;
    }
    const FP_XSTATE_MAGIC1: u32 = 0x4650_5853;
    // SAFETY: the caller's; sw_reserved is at 464 of the 512-byte legacy area.
    let (magic, size) = unsafe { (((fp + 464) as *const u32).read(), ((fp + 468) as *const u32).read()) };
    if magic == FP_XSTATE_MAGIC1 && (512..=64 * 1024).contains(&(size as usize)) { size as usize } else { 512 }
}

/// The `signal_handler` host op (see the section comment).
unsafe extern "C" fn signal_handler(sig: *mut l::lkl_signal) -> core::ffi::c_int {
    // SAFETY: the kernel's, for the call.
    let s = unsafe { &*sig };
    let t = cur();
    let ucp = t.uc.get();
    if ucp == 0 || S.phase.get() != Phase::Program {
        // Not at a program trap (the runtime's own calls outside a dispatch, setup code): there is
        // nothing to interrupt. As if the handler returned at once.
        return 1;
    }
    debug_assert!(t.quiet.get().is_none(), "a handler at a quiet call");
    // SAFETY: the dispatch's trap frame, live below us.
    let uc = unsafe { &mut *(ucp as *mut Ucontext) };
    let signo = s.sig as usize;
    let restorer = S.restorers.get(signo).map_or(0, Cell::get);
    // SAFETY: the kernel's stack_t and sigset_t, for the call.
    let (stack, mask) = unsafe { (*(s.stack as *const StackT), *(s.mask as *const u64)) };
    let sp = uc.mcontext.rsp as usize;
    let on_alt = stack.size != 0 && (stack.sp..stack.sp.wrapping_add(stack.size)).contains(&sp);
    let alt = (s.flags & SA_ONSTACK != 0 && stack.flags & SS_DISABLE == 0 && stack.size != 0 && !on_alt)
        .then(|| (stack.sp, stack.sp + stack.size));
    let mut top = match alt {
        Some((_, hi)) => hi,
        None => sp.wrapping_sub(128),
    };
    let fp = uc.mcontext.fpregs;
    // SAFETY: the trap's own FPU state.
    let fp_len = unsafe { fpstate_len(fp) };
    top = top.wrapping_sub(fp_len) & !63;
    let fp_at = top;
    let frame = (top.wrapping_sub(8 + size_of::<Ucontext>() + 128) & !15).wrapping_sub(8);
    if restorer == 0 || frame > top || !user(frame, top - frame + fp_len) {
        // No way to return (x86-64 requires SA_RESTORER), or no room: Linux's force_sigsegv.
        writeback();
        die(SIGSEGV);
    }
    let fuc = frame + 8;
    let info = fuc + size_of::<Ucontext>();
    let mut u = *uc;
    u.link = 0;
    u.stack = stack;
    u.sigmask = mask;
    u.mcontext.fpregs = if fp != 0 { fp_at } else { 0 };
    // SAFETY: checked to be program memory, room for all of it; the trap's FPU state, the
    // kernel's 128-byte siginfo.
    unsafe {
        if fp != 0 {
            core::ptr::copy_nonoverlapping(fp as *const u8, fp_at as *mut u8, fp_len);
        }
        (frame as *mut usize).write(restorer);
        (fuc as *mut Ucontext).write_unaligned(u);
        core::ptr::copy_nonoverlapping(s.info as *const u8, info as *mut u8, 128);
    }
    let mut r = SigRec {
        prev: t.sig_top.get(),
        frame,
        alt,
        jmp: JmpBuf::new(),
        uc: ucp,
        rip: uc.mcontext.rip,
        fp_len,
        mask: s.mask as *mut u64,
        stack: s.stack as *mut StackT,
    };
    let rp: *mut SigRec = &raw mut r;
    t.sig_top.set(rp as usize);
    t.handled.set(t.handled.get().wrapping_add(1));
    t.handled_restart.set(s.flags & SA_RESTART != 0);
    // handler(sig) or, under SA_SIGINFO, handler(sig, info, uc): the same registers either way,
    // as Linux sets them.
    let call = ProgramCall {
        rip: s.handler as usize,
        rsp: frame,
        rdi: signo,
        rsi: info,
        rdx: fuc,
        fs: uc.mcontext.fs_base as usize,
    };
    if par::enabled() {
        // The program runs without the token; the handler's rt_sigreturn takes it back.
        par::leave(par::my_id());
    }
    // SAFETY: the frame is built; below the saved place the control stack is free for the
    // handler's traps (`handler_top`). Only `sigreturn` comes back, through the record.
    let restart = unsafe { context::call_program(&raw mut (*rp).jmp, &call) };
    t.sig_top.set(r.prev);
    t.uc.set(ucp);
    restart as core::ffi::c_int
}

/// The program's `rt_sigreturn`, trapped (`uc` is that trap's): the end of a handler the runtime
/// ran (see the section comment), which never returns here; or, if no handler of ours has this
/// frame (the program built it, or its handler's record was dropped), a sigreturn of its own,
/// done here: the frame's registers become this trap's, its mask and alternate stack the
/// kernel's.
fn sigreturn(uc: &mut Ucontext) -> isize {
    let t = cur();
    let fuc_at = uc.mcontext.rsp as usize;
    let Ok(f) = read_user::<Ucontext>(fuc_at) else {
        writeback();
        die(SIGSEGV)
    };
    let frame = fuc_at.wrapping_sub(8);
    let mut r = t.sig_top.get();
    // SAFETY: the chain's records are live (`handler_top` dropped the dead ones).
    while r != 0 && unsafe { rec(r) }.frame != frame {
        r = unsafe { rec(r) }.prev;
    }
    let fs = uc.mcontext.fs_base;
    if r == 0 {
        let fp_len = if f.mcontext.fpregs != 0 && user(f.mcontext.fpregs, 512) {
            // SAFETY: checked (the legacy part; the copy is bounded by the trap's own size).
            unsafe { fpstate_len(f.mcontext.fpregs) }
        } else {
            0
        };
        let fp_len = if user(f.mcontext.fpregs, fp_len) { fp_len } else { 0 };
        restore_registers(uc, &f, fp_len);
        uc.mcontext.fs_base = fs;
        const SIG_SETMASK: usize = 2;
        lkl_call(l::__lkl__NR_rt_sigprocmask, [SIG_SETMASK, &f.sigmask as *const u64 as usize, 0, 8, 0, 0]);
        lkl_call(l::__lkl__NR_sigaltstack, [&f.stack as *const StackT as usize, 0, 0, 0, 0, 0]);
        return f.mcontext.rax as isize;
    }
    // SAFETY: found in the chain: live, its trap below it on this stack.
    let x = unsafe { rec(r) };
    // SAFETY: the interrupted trap's frame, live under `signal_handler`.
    let orig = unsafe { &mut *(x.uc as *mut Ucontext) };
    let fp_len = if user(f.mcontext.fpregs, x.fp_len) { x.fp_len } else { 0 };
    restore_registers(orig, &f, fp_len);
    // The FS base isn't in a signal frame: it stays as the handler left it.
    orig.mcontext.fs_base = fs;
    // SAFETY: the kernel's, for the op's duration (which this is inside of).
    unsafe {
        *x.mask = f.sigmask;
        *x.stack = f.stack;
    }
    t.sig_top.set(r);
    let moved = orig.mcontext.rip != x.rip;
    // SAFETY: the record's call is active below this frame, on this stack.
    unsafe { context::jump(&x.jmp, if moved { 0 } else { 1 }) }
}

/// A signal frame's registers into the trap `to` will resume (`restore_sigcontext`): the general
/// ones, rip and the flags a program may set; and `fp_len` bytes of FPU state over the trap's
/// own, if both have one. Not the segment selectors, nor the FS base (not in a frame).
fn restore_registers(to: &mut Ucontext, f: &Ucontext, fp_len: usize) {
    let (d, m) = (&mut to.mcontext, &f.mcontext);
    (d.r8, d.r9, d.r10, d.r11, d.r12, d.r13, d.r14, d.r15) = (m.r8, m.r9, m.r10, m.r11, m.r12, m.r13, m.r14, m.r15);
    (d.rdi, d.rsi, d.rbp, d.rbx, d.rdx, d.rax, d.rcx, d.rsp, d.rip) =
        (m.rdi, m.rsi, m.rbp, m.rbx, m.rdx, m.rax, m.rcx, m.rsp, m.rip);
    // Linux's FIX_EFLAGS: AC, OF, DF, TF, SF, ZF, AF, PF, CF, RF.
    const FIX_EFLAGS: u64 = 0x4_0000 | 0x800 | 0x400 | 0x100 | 0x80 | 0x40 | 0x10 | 0x4 | 0x1 | 0x1_0000;
    d.eflags = (d.eflags & !FIX_EFLAGS) | (m.eflags & FIX_EFLAGS);
    if fp_len != 0 && d.fpregs != 0 && m.fpregs != 0 {
        // SAFETY: the trap's xsave area is as large as it says (the kernel's frame); the
        // program's was checked by the caller.
        unsafe {
            let room = fpstate_len(d.fpregs);
            core::ptr::copy_nonoverlapping(m.fpregs as *const u8, d.fpregs as *mut u8, fp_len.min(room));
        }
    }
}

/// The guest's process died of `sig` (its default action): so does the sandbox, as the program
/// would natively (a shell sees `abort`'s SIGABRT). The filter allows `kill` of this process
/// only, with a signal; the host's dispositions are the defaults but for SIGSYS (the trap's) and
/// SIGPIPE (ignored, so a closed stdout is EPIPE): SIGSYS comes from the filter itself (a call
/// it kills: any number with the x32 bit), SIGPIPE can't, and ends as 128 + 13, a shell's
/// number for it. The same if a death by signal fails (the filter's `--deny=errno`, or before
/// any filter).
fn die(sig: i32) -> ! {
    if par::forked() {
        // A fork's child process: only it dies, as the guest's (its parent sees the signal in
        // wait). The default action, unblocked, sent to itself: the call's return ends the task.
        const SIG_UNBLOCK: usize = 1;
        let dfl = LklSigaction::default();
        let set = 1u64 << (sig - 1);
        lkl_call(lkl::RT_SIGACTION as c_long, [sig as usize, &dfl as *const _ as usize, 0, 8, 0, 0]);
        lkl_call(l::__lkl__NR_rt_sigprocmask, [SIG_UNBLOCK, &set as *const u64 as usize, 0, 8, 0, 0]);
        let pid = lkl_call(l::__lkl__NR_getpid, [0; 6]);
        lkl_call(l::__lkl__NR_kill, [pid as usize, sig as usize, 0, 0, 0, 0]);
        finish(128 + sig)
    }
    match sig {
        SIGSYS => {
            // SAFETY: the filter kills the process for it.
            unsafe { trap::gate(0x4000_0000 | 39, 0, 0, 0, 0, 0, 0) };
        }
        SIGPIPE => {}
        _ => {
            // SAFETY: a signal to this process, whose default action ends it: in coroutine mode at
            // this call's return; in threaded mode on the thread the kernel picks, which ends the
            // rest (the wait below, until then).
            unsafe { trap::gate(filter::NR_KILL as usize, S.host_pid.get() as usize, sig as usize, 0, 0, 0, 0) };
            let _ = trap::ppoll(None, Some(&xabi::Timespec { tv_sec: 1, tv_nsec: 0 }));
        }
    }
    finish(128 + sig)
}

/// Whether the program runs: a panic now is the runtime's (the program is a foreign binary, so
/// the only Rust code running is the runtime's), and [`runtime_panic`] is how it ends.
pub fn program_runs() -> bool {
    S.phase.get() == Phase::Program
}

/// A panic in the runtime while the program runs (the binary's panic hook, `exobox`'s
/// `launch`): the sandbox dies of SIGABRT now, through the host alone, the message on the host's
/// stderr. std's own way out went through the guest: its message a guest `write`, its `abort`
/// a guest `tgkill`, served by the very runtime that had panicked, mid-call (in threaded mode
/// holding the CPU token). A panic that left the guest mid-change (in a clone, after the new
/// thread's guest task was made) hung every mode: the guest's SIGABRT ended the panicking
/// thread's task but never its process, whose new task would never run to end, and the sandbox
/// waited for good (runtime_panic.c's `clone`; exec_thread_main.c's panic found it).
pub fn runtime_panic(info: &dyn core::fmt::Display) -> ! {
    struct Buf {
        b: [u8; 1024],
        n: usize,
    }
    impl core::fmt::Write for Buf {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            let k = s.len().min(self.b.len() - self.n);
            self.b[self.n..self.n + k].copy_from_slice(&s.as_bytes()[..k]);
            self.n += k;
            Ok(())
        }
    }
    let mut m = Buf { b: [0; 1024], n: 0 };
    let _ = core::fmt::write(&mut m, format_args!("exobox: the runtime panicked: {info}\n"));
    let _ = trap::write(2, &m.b[..m.n]);
    // Init's process (fork mode: a fork's child kills it, whose end is the sandbox's: the other
    // processes see its pidfd), with the default action (as `die`). Then the exit, if the signal
    // didn't end it (every thread blocking it, or the filter's `--deny=errno`).
    // SAFETY: a signal to the sandbox's process; nothing after it needs the runtime's state.
    unsafe { trap::gate(filter::NR_KILL as usize, S.host_pid.get() as usize, SIGABRT as usize, 0, 0, 0, 0) };
    if !par::forked() {
        let _ = trap::ppoll(None, Some(&xabi::Timespec { tv_sec: 1, tv_nsec: 0 }));
    }
    trap::exit_group(128 + SIGABRT)
}

// ------------------------------------------------------------------------------------------------
// The guest's own execve.

/// The program's path and arguments, copied out of the old image before it goes.
static EXEC_STRINGS: Local<[u8; 1 << 20]> = Local::new([0; 1 << 20]);
static EXEC_ARGS: Local<[&'static [u8]; 8192]> = Local::new([&[]; 8192]);
/// The path `/proc/self/exe` names (STOPGAP(item 10)).
static EXE: Local<[u8; exec::PATH_MAX]> = Local::new([0; exec::PATH_MAX]);

/// A NUL-terminated string of the program's, without its NUL (EFAULT outside its memory,
/// ENAMETOOLONG past `max`).
fn user_cstr(p: usize, max: usize) -> Result<&'static [u8], Errno> {
    for n in 0..max {
        if !user(p + n, 1) {
            return Err(Errno::FAULT);
        }
        // SAFETY: checked to be program memory.
        if unsafe { *((p + n) as *const u8) } == 0 {
            // SAFETY: the n bytes just read.
            return Ok(unsafe { core::slice::from_raw_parts(p as *const u8, n) });
        }
    }
    Err(Errno::NAMETOOLONG)
}

/// STOPGAP(item 10, exec's kernel half): `/proc/self/exe` is init's `/init` in the guest, so ld.so
/// can't find `$ORIGIN` (RUNPATHs like the fixtures'); the dispatcher answers `readlink` of it
/// with the path exec loaded, made absolute. `new_exec` doesn't change it: it doesn't set the
/// task's `mm->exe_file` (`set_mm_exe_file`, from the file the host loaded), and every host task
/// shares init's stub mm, so one link would be every process's. What the kernel needs: new_exec
/// given the file (or opening `path` itself) and an exe link per process (its own mm, as fork
/// mode's processes will need anyway, or the link kept on the task for `proc_exe_link`).
fn set_exe(path: &[u8]) {
    // SAFETY: only exec and readlink use it, never at once.
    let exe = unsafe { EXE.get() };
    let mut n = 0;
    if path.first() != Some(&b'/') {
        let r = lkl_quiet(l::__lkl__NR_getcwd, [exe.as_mut_ptr() as usize, exe.len(), 0, 0, 0, 0]);
        if r > 0 {
            n = r as usize - 1; // without its NUL
            if n > 1 && n < exe.len() {
                exe[n] = b'/';
                n += 1;
            }
        }
    }
    let m = path.len().min(exe.len() - n);
    exe[n..n + m].copy_from_slice(&path[..m]);
    S.exe_len.set(n + m);
}

/// `readlink`/`readlinkat` of `/proc/self/exe` (or `/proc/1/exe`): the program's path.
fn readlink_exe(path: usize, buf: usize, size: usize) -> Option<isize> {
    let p = user_cstr(path, 32).ok()?;
    // The path is this process's (fork mode: each process keeps its own, copied by the fork and
    // replaced by its exec); /proc/1/exe is init's, so only init's own answers it.
    let init = p == b"/proc/1/exe" && !par::forked();
    if (p != b"/proc/self/exe" && !init) || S.exe_len.get() == 0 {
        return None;
    }
    // SAFETY: as set_exe.
    let exe = &unsafe { EXE.get() }[..S.exe_len.get()];
    let n = exe.len().min(size);
    if !user(buf, n) {
        return Some(-(Errno::FAULT.raw_os_error() as isize));
    }
    // SAFETY: checked to be program memory.
    unsafe { core::ptr::copy_nonoverlapping(exe.as_ptr(), buf as *mut u8, n) };
    Some(n as isize)
}

/// `execve(path, argv, envp)` inside the guest: the new image replaces the old one in the arena
/// and the calling thread resumes at its start. Errors before the point of no return leave the old
/// image as it was. The kernel's half (the other threads ended, close-on-exec files, handlers
/// reset: item 10) is `new_exec`, in `load`. Handlers the runtime was running for this thread
/// are gone with the image (an exec from a handler).
fn execve(uc: &mut Ucontext, path: usize, argv: usize, envp: usize) -> Result<usize, Errno> {
    // SAFETY: the guest's execve runs one at a time (nothing in it suspends while these are
    // being filled: user memory is read directly).
    let (strings, args) = unsafe { (EXEC_STRINGS.get(), EXEC_ARGS.get()) };
    let mut used = 0;
    let mut copy = |s: &[u8]| -> Result<&'static [u8], Errno> {
        let at = used;
        used += s.len();
        if used > strings.len() {
            return Err(Errno::TOOBIG);
        }
        strings[at..used].copy_from_slice(s);
        // SAFETY: the static buffer; this region isn't written again during this exec.
        Ok(unsafe { core::slice::from_raw_parts(strings.as_ptr().add(at), s.len()) })
    };
    let path = copy(user_cstr(path, exec::PATH_MAX)?)?;
    let mut n = 0;
    let mut vector = |v: usize| -> Result<usize, Errno> {
        let start = n;
        if v == 0 {
            return Ok(0);
        }
        loop {
            let p: usize = read_user(v + (n - start) * 8)?;
            if p == 0 {
                return Ok(n - start);
            }
            if n == args.len() {
                return Err(Errno::TOOBIG);
            }
            args[n] = copy(user_cstr(p, exec::MAX_ARG_STRLEN)?)?;
            n += 1;
        }
    };
    let nargv = vector(argv)?;
    let nenvp = vector(envp)?;
    let (argv, envp) = args[..nargv + nenvp].split_at(nargv);
    let regs = load(path, argv, envp, true)?;
    let m = &mut uc.mcontext;
    (m.rax, m.rbx, m.rcx, m.rdx, m.rsi, m.rdi, m.rbp) = (0, 0, 0, 0, 0, 0, 0);
    (m.r8, m.r9, m.r10, m.r11, m.r12, m.r13, m.r14, m.r15) = (0, 0, 0, 0, 0, 0, 0, 0);
    m.rsp = regs.rsp;
    m.rip = regs.rip;
    m.fs_base = 0;
    Ok(0)
}

// ------------------------------------------------------------------------------------------------
// The dispatcher.

fn ret(r: Result<usize, Errno>) -> isize {
    match r {
        Ok(v) => v as isize,
        Err(e) => -(e.raw_os_error() as isize),
    }
}

/// The target-stack hook (`trap::Target`): the trapping coroutine's control stack, or below the
/// trap's sp when the trap came from runtime code already on it (or host code in the setup
/// phase, on the root's stack).
fn target(uc: &Ucontext) -> usize {
    let sp = uc.mcontext.rsp as usize;
    // Before the program: host code (the setup phase's, or any thread's in passthrough) on its
    // own stack; no coroutine's control stack is the trapping thread's (the current coroutine may
    // be a kernel thread's, borrowed by setup's LKL call, and another thread may trap meanwhile).
    if S.phase.get() != Phase::Program {
        return trap::below_red_zone(uc);
    }
    // Threaded mode: the trapping host thread's bound coroutine (via its GS record), not the shared
    // `current` (set by whichever host last held the token). `(0, 0)`: the main thread's root.
    let (lo, size) = if par::enabled() {
        let (l, h) = par::target_ctl();
        (l, h - l)
    } else {
        SCHED.stack()
    };
    let top = if size == 0 {
        // The root: the host thread's own stack, whose extent the scheduler doesn't know.
        let top = S.root_top.get();
        // The program runs on the arena; anything else is runtime code on the root's stack.
        if top == 0 || !(S.arena_lo.get()..S.arena_hi.get()).contains(&sp) {
            return trap::below_red_zone(uc);
        }
        top
    } else {
        if (lo..lo + size).contains(&sp) {
            return trap::below_red_zone(uc);
        }
        lo + size
    };
    // A program trap: while a handler the runtime runs for this thread is live, the control
    // stack above its saved place is in use.
    handler_top(uc).unwrap_or(top)
}

/// The dispatcher (`trap::Dispatch`).
fn dispatch(uc: &mut Ucontext) {
    match S.phase.get() {
        Phase::Program => {}
        Phase::Setup if host_tid() == S.setup_tid.get() => {}
        // No setup phase, or another thread's call during one: the host's.
        _ => return crate::passthrough::serve(uc),
    }
    let (nr, a) = uc.syscall();
    if par::enabled() {
        // Threaded mode: hold the CPU token while serving (the kernel, the scheduler, the futexes
        // and the arena are shared). A call that blocks releases and reclaims it inside the
        // scheduler; the exit paths end the host thread holding it. Program code runs in parallel
        // outside the token, so no fairness yield is needed.
        let id = par::enter();
        served(uc, nr, a);
        par::leave(id);
        return;
    }
    served(uc, nr, a);
    // No preemption here: a thread whose calls never block (a poll with timeout 0 in a loop)
    // would keep every other coroutine from running, a new thread among them (it isn't the
    // kernel's to schedule until its first call attaches it). So every so many calls, the others
    // get a turn (threadpoll's last run hung without it).
    let n = S.served.get().wrapping_add(1);
    S.served.set(n);
    if n.is_multiple_of(32) && S.phase.get() == Phase::Program {
        // (and the hooks' fds looked at: the idle wait that watches them doesn't run meanwhile)
        crate::executor::busy_poll();
        SCHED.yield_now();
    }
}


/// One trap served: the call, its result, the program's mask back if the runtime's own calls
/// blocked signals ([`unquiet`]: what came meanwhile is delivered then). `uc` is the thread's
/// innermost trap meanwhile, which a handler interrupts.
fn served(uc: &mut Ucontext, nr: usize, a: [usize; 6]) {
    let t = cur();
    let outer = t.uc.replace(uc as *mut Ucontext as usize);
    let r = serve(uc, nr, a);
    uc.set_return(r);
    unquiet(t);
    t.uc.set(outer);
}

fn serve(uc: &mut Ucontext, nr: usize, a: [usize; 6]) -> isize {
    // A test hook, in debug builds only: a runtime panic on demand, inside a served call (in
    // threaded mode, holding the CPU token), which must end the sandbox (runtime_panic.c). With
    // 1, armed for the next thread's clone instead, after its guest task is made: the guest is
    // left mid-change, as the panic that found the hang left it.
    #[cfg(debug_assertions)]
    if nr == TEST_PANIC {
        if a[0] == 1 {
            TEST_PANIC_CLONE.store(true, core::sync::atomic::Ordering::Relaxed);
            return 0;
        }
        panic!("runtime_panic.c's test hook");
    }
    // STOPGAP(item 10): readlink, readlinkat(AT_FDCWD) of /proc/self/exe.
    let exe = match nr {
        NR_READLINK => readlink_exe(a[0], a[1], a[2]),
        NR_READLINKAT if a[0] as i32 == k::AT_FDCWD => readlink_exe(a[1], a[2], a[3]),
        _ => None,
    };
    if let Some(r) = exe {
        return r;
    }
    // A guard is the guest's init, the machine's administrator: it names the machine
    // (sethostname, setdomainname: the kernel's 161, 162) and sets its clock (settimeofday,
    // clock_settime: 170, 112; their structs are x86-64's). The program gets sysmap's EPERM for
    // them, as a machine's administration.
    if S.phase.get() == Phase::Setup {
        let admin = match nr {
            170 => 161,
            171 => 162,
            164 => 170,
            227 => 112,
            _ => 0,
        };
        if admin != 0 {
            return lkl_call(admin, a);
        }
    }
    match sysmap::route(nr) {
        Route::Lkl(n) if sends_signal(nr) => {
            let r = lkl_call(n as c_long, a);
            SCHED.interrupt_waits();
            r
        }
        Route::Lkl(n) => lkl_call(n as c_long, a),
        // fork and vfork: clone(SIGCHLD). vfork is a fork: its child can't share the parent's
        // memory, a host process of its own.
        Route::Rewrite(Rewrite::Fork) if fork::enabled() => ret(fork::clone_process(uc, [fork::SIGCHLD, 0, 0, 0, 0, 0])),
        Route::Rewrite(rw) => rewrite(rw, a),
        Route::Emulate(e) => emulate(uc, e, nr, a),
        Route::Errno(e) => e.ret(),
    }
}

fn rewrite(rw: Rewrite, a: [usize; 6]) -> isize {
    let at = k::AT_FDCWD as isize as usize;
    match rw {
        Rewrite::Args(x) => lkl_call(x.lkl as c_long, x.apply(&a)),
        Rewrite::Stat(form) => {
            let mut st = LklStat::default();
            let tmp = &mut st as *mut LklStat as usize;
            let (r, buf) = match form {
                StatForm::Path => (lkl_call(lkl::NEWFSTATAT as c_long, [at, a[0], tmp, 0, 0, 0]), a[1]),
                StatForm::Lpath => {
                    (lkl_call(lkl::NEWFSTATAT as c_long, [at, a[0], tmp, k::AT_SYMLINK_NOFOLLOW as usize, 0, 0]), a[1])
                }
                StatForm::Fd => (lkl_call(lkl::FSTAT as c_long, [a[0], tmp, 0, 0, 0, 0]), a[1]),
                StatForm::At => (lkl_call(lkl::NEWFSTATAT as c_long, [a[0], a[1], tmp, a[3], 0, 0]), a[2]),
            };
            if r < 0 {
                return r;
            }
            ret(write_user::<X86Stat>(buf, xabi::stat_to_x86(&st)).map(|_| 0))
        }
        Rewrite::Poll => {
            let ts = xabi::poll_timeout(a[2] as i32);
            let tp = ts.as_ref().map_or(0, |t| t as *const Timespec as usize);
            lkl_call(lkl::PPOLL as c_long, [a[0], a[1], tp, 0, 8, 0])
        }
        Rewrite::Select => {
            let tvp = a[4];
            let mut ts = None;
            if tvp != 0 {
                match read_user::<Timeval>(tvp) {
                    Ok(tv) => ts = Some(xabi::select_timeout(&tv)),
                    Err(e) => return -(e.raw_os_error() as isize),
                }
            }
            let tp = ts.as_mut().map_or(0, |t| t as *mut Timespec as usize);
            let r = lkl_call(lkl::PSELECT6 as c_long, [a[0], a[1], a[2], a[3], tp, 0]);
            if let Some(t) = ts {
                let _ = write_user(tvp, xabi::select_remaining(&t));
            }
            r
        }
        Rewrite::Dup2 => {
            if a[0] == a[1] {
                let r = lkl_call(lkl::FCNTL as c_long, [a[0], k::F_GETFD as usize, 0, 0, 0, 0]);
                return if r < 0 { r } else { a[1] as isize };
            }
            lkl_call(lkl::DUP3 as c_long, [a[0], a[1], 0, 0, 0, 0])
        }
        Rewrite::EpollCreate => {
            if a[0] as i32 <= 0 {
                return -(Errno::INVAL.raw_os_error() as isize);
            }
            lkl_call(lkl::EPOLL_CREATE1 as c_long, [0; 6])
        }
        Rewrite::Time => {
            let mut ts = Timespec::default();
            let r = lkl_call(lkl::CLOCK_GETTIME as c_long, [k::CLOCK_REALTIME as usize, &mut ts as *mut _ as usize, 0, 0, 0, 0]);
            if r < 0 {
                return r;
            }
            if a[0] != 0 && write_user(a[0], ts.tv_sec).is_err() {
                return -(Errno::FAULT.raw_os_error() as isize);
            }
            ts.tv_sec as isize
        }
        Rewrite::Utime => {
            if a[1] == 0 {
                return lkl_call(lkl::UTIMENSAT as c_long, [at, a[0], 0, 0, 0, 0]);
            }
            match read_user::<[i64; 2]>(a[1]) {
                Ok([ac, m]) => {
                    let ts = xabi::utimbuf_to_timespecs(ac, m);
                    lkl_call(lkl::UTIMENSAT as c_long, [at, a[0], ts.as_ptr() as usize, 0, 0, 0])
                }
                Err(e) => -(e.raw_os_error() as isize),
            }
        }
        Rewrite::Utimes | Rewrite::Futimesat => {
            let (dfd, path, tvp) = if rw == Rewrite::Utimes { (at, a[0], a[1]) } else { (a[0], a[1], a[2]) };
            if tvp == 0 {
                return lkl_call(lkl::UTIMENSAT as c_long, [dfd, path, 0, 0, 0, 0]);
            }
            match read_user::<[Timeval; 2]>(tvp) {
                Ok(tv) => match xabi::utimes_to_timespecs(&tv) {
                    Some(ts) => lkl_call(lkl::UTIMENSAT as c_long, [dfd, path, ts.as_ptr() as usize, 0, 0, 0]),
                    None => -(Errno::INVAL.raw_os_error() as isize),
                },
                Err(e) => -(e.raw_os_error() as isize),
            }
        }
        Rewrite::Alarm => {
            let new = Itimerval { it_interval: Timeval::default(), it_value: Timeval { tv_sec: a[0] as u32 as i64, tv_usec: 0 } };
            let mut old = Itimerval::default();
            let r = lkl_call(
                lkl::SETITIMER as c_long,
                [k::ITIMER_REAL as usize, &new as *const _ as usize, &mut old as *mut _ as usize, 0, 0, 0],
            );
            if r < 0 { r } else { xabi::alarm_remaining(&old) as isize }
        }
        Rewrite::Pause => {
            // rt_sigsuspend with the mask as it is: sleeps until a handler has run, then EINTR.
            let mut m = 0u64;
            const SIG_BLOCK: usize = 0;
            let r = lkl_call(l::__lkl__NR_rt_sigprocmask, [SIG_BLOCK, 0, &mut m as *mut u64 as usize, 8, 0, 0]);
            if r < 0 {
                return r;
            }
            lkl_call(l::__lkl__NR_rt_sigsuspend, [&m as *const u64 as usize, 8, 0, 0, 0, 0])
        }
        Rewrite::Uname => {
            if !user(a[0], xabi::UTS_SIZE) {
                return -(Errno::FAULT.raw_os_error() as isize);
            }
            let r = lkl_call(lkl::UNAME as c_long, [a[0], 0, 0, 0, 0, 0]);
            if r == 0 {
                // SAFETY: checked to be program memory, UTS_SIZE bytes.
                xabi::uts_set_machine(unsafe { &mut *(a[0] as *mut [u8; xabi::UTS_SIZE]) });
            }
            r
        }
        Rewrite::SigAction => sigaction(a),
        Rewrite::Statx => statx(a),
        // Fork mode's are `serve`'s; the other modes have no processes.
        Rewrite::Fork => -(Errno::NOSYS.raw_os_error() as isize),
    }
}

/// `Rewrite::Statx`: the program's pointers checked before LKL reads or writes them. The errors
/// are Linux's, in its order: the path's (`EFAULT`, `ENAMETOOLONG`), the lookup's, the buffer's.
fn statx(a: [usize; 6]) -> isize {
    let (dfd, path, flags) = (a[0] as i32, a[1], a[2] as i32);
    // `sys_statx`'s short cut, which never reads a NULL path (`vfs_empty_path`).
    let empty_form = flags & !(k::AT_NO_AUTOMOUNT | k::AT_STATX_SYNC_TYPE) == k::AT_EMPTY_PATH && dfd >= 0;
    if path == 0 && !empty_form {
        return -(Errno::FAULT.raw_os_error() as isize);
    }
    if path != 0
        && let Err(e) = user_cstr(path, exec::PATH_MAX)
    {
        return -(e.raw_os_error() as isize);
    }
    // `struct statx` is 256 bytes, the same on both (`xabi`); LKL fills all of it.
    let mut tmp = [0u64; 32];
    let r = lkl_call(lkl::STATX as c_long, [a[0], path, a[2], a[3], tmp.as_mut_ptr() as usize, 0]);
    if r < 0 {
        return r;
    }
    ret(write_user(a[4], tmp).map(|_| 0))
}

fn sigaction(a: [usize; 6]) -> isize {
    let (sig, act, oldp, size) = (a[0], a[1], a[2], a[3]);
    if size != 8 {
        return -(Errno::INVAL.raw_os_error() as isize);
    }
    let mut new = None;
    if act != 0 {
        match read_user::<X86Sigaction>(act) {
            Ok(x) => new = Some(xabi::sigaction_to_lkl(&x)),
            Err(e) => return -(e.raw_os_error() as isize),
        }
    }
    if oldp != 0 && !user(oldp, size_of::<X86Sigaction>()) {
        return -(Errno::FAULT.raw_os_error() as isize);
    }
    let mut old = LklSigaction::default();
    let np = new.as_ref().map_or(0, |(n, _)| n as *const LklSigaction as usize);
    let op = if oldp != 0 { &mut old as *mut LklSigaction as usize } else { 0 };
    // The restorer is recorded first: the signal may be delivered at this very call's return
    // (pending and now caught), its handler returning through it. Put back if LKL refuses.
    let slot = S.restorers.get(sig).filter(|_| sig != 0);
    let prev = slot.map_or(0, Cell::get);
    if let (Some(slot), Some((_, restorer))) = (slot, new) {
        slot.set(restorer);
    }
    let r = lkl_call(lkl::RT_SIGACTION as c_long, [sig, np, op, 8, 0, 0]);
    match slot {
        Some(slot) if r != 0 => slot.set(prev),
        Some(_) if oldp != 0 => {
            let _ = write_user(oldp, xabi::sigaction_to_x86(&old, prev));
        }
        _ => {}
    }
    r
}

/// A memory call in the setup phase: host code's own memory, the host's (see the module comment).
fn host_memory_call(nr: usize, a: [usize; 6]) -> isize {
    if S.host_memory.get() {
        // SAFETY: the host code's own call, as it made it; the routing filter allows it.
        return unsafe { trap::gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) };
    }
    match nr {
        9 | 25 => -(Errno::NOMEM.raw_os_error() as isize), // mmap, mremap
        12 => 0,                                            // brk: no break
        _ => 0,
    }
}

fn emulate(uc: &mut Ucontext, e: Emulate, nr: usize, a: [usize; 6]) -> isize {
    let program = S.phase.get() == Phase::Program;
    use Emulate as E;
    match e {
        E::Mmap | E::Munmap | E::Mremap | E::Mprotect | E::Madvise | E::Msync | E::Brk | E::Mincore if !program => {
            host_memory_call(nr, a)
        }
        E::Mmap => {
            let flags = a[3] as u32;
            let file = if flags & arena::MAP_ANONYMOUS != 0 {
                None
            } else {
                Some(FileMap { file: a[4] as i32 as u64, offset: a[5] as u64 })
            };
            if file.is_some_and(|f| f.file > i32::MAX as u64) {
                return -(Errno::BADF.raw_os_error() as isize);
            }
            ret(with_arena(|ar, b| ar.mmap(b, a[0], a[1], a[2] as u32, flags, file)))
        }
        E::Munmap => ret(with_arena(|ar, b| ar.munmap(b, a[0], a[1]))),
        E::Mremap => ret(with_arena(|ar, b| ar.mremap(b, a[0], a[1], a[2], a[3] as u32, a[4]))),
        E::Mprotect => ret(with_arena(|ar, _| ar.mprotect(a[0], a[1], a[2] as u32))),
        E::Madvise => ret(with_arena(|ar, b| ar.madvise(b, a[0], a[1], a[2] as u32))),
        E::Msync => ret(with_arena(|ar, b| ar.msync(b, a[0], a[1], a[2] as u32))),
        E::Brk => with_arena(|ar, _| ar.brk(a[0])) as isize,
        E::Mincore => {
            let pages = a[1].div_ceil(arena::PAGE);
            if !user(a[2], pages) {
                return -(Errno::FAULT.raw_os_error() as isize);
            }
            // SAFETY: checked to be program memory, `pages` bytes.
            let vec = unsafe { core::slice::from_raw_parts_mut(a[2] as *mut u8, pages) };
            ret(with_arena(|ar, _| ar.mincore(a[0], a[1], vec)))
        }
        E::NoOp => 0,
        E::Clone if !program => -(Errno::NOSYS.raw_os_error() as isize), // setup is single-threaded
        E::Clone => ret(clone(uc, a)),
        E::Exit if !program => exit_group(a[0]),
        E::Exit => exit_thread(a[0]),
        E::ExitGroup => exit_group(a[0]),
        E::SetRobustList => 0, // TODO: robust futexes are not released at a thread's death
        E::SetTidAddress => {
            if par::enabled() {
                par::set_clear_tid(a[0]);
            } else {
                me().clear_tid.set(a[0]);
            }
            lkl_call(l::__lkl__NR_gettid, [0; 6])
        }
        E::Futex if !program => {
            // SAFETY: host code's futex on its own memory (one thread: only wakes happen).
            unsafe { trap::gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
        }
        E::Futex => futex_call(a),
        E::SchedYield => {
            SCHED.yield_now();
            0
        }
        E::SchedGetaffinity => {
            if a[1] < 8 {
                return -(Errno::INVAL.raw_os_error() as isize);
            }
            ret(write_user(a[2], 1u64).map(|_| 8))
        }
        E::SchedSetaffinity => 0,
        E::Getcpu => {
            for p in [a[0], a[1]] {
                if p != 0 && write_user(p, 0u32).is_err() {
                    return -(Errno::FAULT.raw_os_error() as isize);
                }
            }
            0
        }
        E::ArchPrctl if !program => unsafe { trap::gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) },
        E::ArchPrctl => {
            const ARCH_SET_GS: usize = 0x1001;
            const ARCH_SET_FS: usize = 0x1002;
            const ARCH_GET_FS: usize = 0x1003;
            const ARCH_GET_GS: usize = 0x1004;
            match a[0] {
                ARCH_SET_FS => {
                    uc.mcontext.fs_base = a[1] as u64;
                    0
                }
                ARCH_GET_FS => ret(write_user(a[1], uc.mcontext.fs_base).map(|_| 0)),
                // The GS base is the program's alone: the runtime never reads or writes it (the
                // trap leaves it as it was; `par` finds its records from the stack pointer), so
                // the host thread's own is the program's. In coroutine mode the program's threads
                // share the host thread, and so one GS base (switches don't carry it).
                // Linux's bound (TASK_SIZE_MAX); a non-canonical base would fault the wrgsbase.
                ARCH_SET_GS if a[1] >= 0x7fff_ffff_f000 => -(Errno::PERM.raw_os_error() as isize),
                ARCH_SET_GS => {
                    // SAFETY: sets a register only the program uses.
                    unsafe { core::arch::asm!("wrgsbase {}", in(reg) a[1], options(nomem, nostack, preserves_flags)) };
                    0
                }
                ARCH_GET_GS => {
                    let gs: usize;
                    // SAFETY: reads a register.
                    unsafe { core::arch::asm!("rdgsbase {}", out(reg) gs, options(nomem, nostack, preserves_flags)) };
                    ret(write_user(a[1], gs).map(|_| 0))
                }
                _ => -(Errno::INVAL.raw_os_error() as isize),
            }
        }
        E::Execve if !program => -(Errno::NOSYS.raw_os_error() as isize),
        E::Execve => ret(execve(uc, a[0], a[1], a[2])),
        // execveat(dfd, path, argv, envp, flags): from the working directory only, so far.
        E::Execveat if program && a[0] as i32 == k::AT_FDCWD && a[4] == 0 => ret(execve(uc, a[1], a[2], a[3])),
        E::Execveat => -(Errno::NOSYS.raw_os_error() as isize),
        E::SigReturn => sigreturn(uc),
        E::Prctl => {
            const PR_SET_MM: usize = 35;
            const PR_SET_VMA: usize = 0x5356_4d41;
            match a[0] {
                PR_SET_VMA => 0,
                PR_SET_MM => -(Errno::PERM.raw_os_error() as isize),
                _ => lkl_call(lkl::PRCTL as c_long, a),
            }
        }
    }
}

fn futex_call(a: [usize; 6]) -> isize {
    let (uaddr, op, val, tp, val3) = (a[0], a[1] as u32, a[2] as u32, a[3], a[5] as u32);
    if !user(uaddr, 4) {
        return -(Errno::FAULT.raw_os_error() as isize);
    }
    let cmd = op & !(futex::FUTEX_PRIVATE_FLAG | futex::FUTEX_CLOCK_REALTIME);
    let mut ts = None;
    if (cmd == futex::FUTEX_WAIT || cmd == futex::FUTEX_WAIT_BITSET) && tp != 0 {
        match read_user::<futex::Timespec>(tp) {
            Ok(t) => ts = Some(t),
            Err(e) => return -(e.raw_os_error() as isize),
        }
    }
    loop {
        // A wait of the runtime's own, not the kernel's: a group exit, an exec's kill or a signal
        // can't reach it, so `SCHED.interrupt_waits` wakes it (Interrupted: EINTR here) to ask.
        SCHED.set_interruptible(true);
        // SAFETY: uaddr is program memory (checked).
        // Keyed by this process (fork mode: each process's memory is its own).
        let r = unsafe { futexes().futex_in(&SCHED, par::proc_id(), uaddr as *const u32, op, val, ts.as_ref(), val3) };
        SCHED.set_interruptible(false);
        if r != Err(Errno::INTR) {
            return ret(r);
        }
        // Ask the kernel: one call, at whose start a killed task ends (the task_exit host op) and
        // at whose return a caught signal's handler runs. Neither: nothing for this thread, and an
        // untimed wait on an unchanged word waits again (the wake is invisible); otherwise a
        // wakeup for nothing, which a futex wait may return (0). A handler ran: EINTR, as Linux's
        // (or the wait again, for an untimed wait under SA_RESTART: Linux's -ERESTARTSYS).
        let t = cur();
        let before = t.handled.get();
        lkl_call(l::__lkl__NR_getpid, [0; 6]);
        if t.handled.get() == before {
            // SAFETY: program memory (checked), 4-aligned (futex checked), read atomically.
            let now = unsafe { core::sync::atomic::AtomicU32::from_ptr(uaddr as *mut u32) }
                .load(core::sync::atomic::Ordering::SeqCst);
            if ts.is_none() && now == val {
                continue;
            }
            return 0;
        }
        if !(t.handled_restart.get() && ts.is_none()) {
            return -(Errno::INTR.raw_os_error() as isize);
        }
    }
}
