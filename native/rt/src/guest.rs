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
//! those passed to LKL are LKL's to read (it has no MMU: a bad one is a fault in the sandbox).
//!
//! **Ends.** A task's end comes back from the kernel as the `task_exit` host op (item 6), on the
//! task's own coroutine: init's (pid 1, after its exit ran in the guest) ends the sandbox with
//! its status; another thread's ends its coroutine.
//!
//! **Stopgap** for a kernel item not landed yet, marked `STOPGAP(item 8)`: signals. A signal the
//! program sends its own process whose action is the default and fatal ends the sandbox with
//! 128 + the signal, as capnix did; handlers are recorded by LKL but never run.

use core::cell::{Cell, UnsafeCell};
use core::ffi::{CStr, c_long};
use core::mem::size_of;

use lkl_sys as l;
use rustix::io::Errno;

use crate::arena::{self, Arena, Backing, Extent, FileMap};
use crate::context::{self, Registers};
use crate::exec::{self, Files, Scratch, StackParams};
use crate::filter::{self, Deny, Params, Policy, Program as Filter};
use crate::futex::{self, Futexes};
use crate::host::{self, SysHost};
use crate::par;
use crate::sched::{Config, Sched, Stacks, Tid};
use crate::sync::TlsKey;
use crate::sysmap::{self, Emulate, Rewrite, Route, StatForm, k, lkl};
use crate::trap::{self, Ucontext};
use crate::xabi::{self, Itimerval, LklSigaction, LklStat, Timespec, Timeval, X86Sigaction, X86Stat};

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

static SCHED: Sched = Sched::new();
static SYS: SysHost = SysHost;
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
    /// The routing filter is in; host code runs as init (see the module comment).
    Setup,
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
    threads: [const { Thread { used: Cell::new(false), co: Cell::new(0), attach: Cell::new(0), clear_tid: Cell::new(0) } };
        THREADS],
    restorers: [const { Cell::new(0) }; 65],
    served: Cell::new(0),
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
        let table: &'static mut [Extent] = &mut ARENA_TABLE.get()[..];
        let a = Arena::new(b.arena.0, b.arena.1, arena::Mode::Release, table).map_err(err("arena"))?;
        *ARENA.get() = Some(a);
    }
    S.arena_lo.set(b.arena.0);
    S.arena_hi.set(b.arena.0 + b.arena.1);
    let key = TlsKey::alloc(&SCHED, None).ok_or(Error { what: "a TLS key", errno: Errno::NOMEM })?;
    S.key.set(Some(key));
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

/// Install the routing-only filter (`filter::Policy::RouteOnly`): from now on every syscall not
/// from the gate traps and is served by the guest, as init. The setup phase begins.
pub fn route() -> Result<(), Error> {
    let p = Params { policy: Policy::RouteOnly, deny: Deny::Kill, gate_ip: trap::gate_ip(), arena: &[], token_fds: (0, 0), extra: &[] };
    // SAFETY: the static program, used only here and in `lock`, one at a time.
    let prog = unsafe { FILTER.get() };
    filter::compile(&p, prog).map_err(|_| Error { what: "the routing filter", errno: Errno::INVAL })?;
    // Threaded mode: sync to every thread (the kernel idler host thread already exists), so its
    // syscalls route through the gate too. SECCOMP_FILTER_FLAG_TSYNC = 1.
    let flags = if par::enabled() { 1 } else { 0 };
    filter::install(prog, flags).map_err(err("installing the routing filter"))?;
    S.phase.set(Phase::Setup);
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

/// A guest syscall from runtime code (generic number), as the current coroutine's task.
pub fn syscall(nr: c_long, a: [usize; 6]) -> isize {
    lkl_call(nr, a)
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
    match load(path, argv, envp, false) {
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
    let r = lkl_call(l::__lkl__NR_getrandom, [random.as_mut_ptr() as usize, 16, 0, 0, 0, 0]);
    if r != 16 {
        return Err(Errno::IO);
    }
    let p = StackParams {
        execfn: path,
        argv,
        envp,
        uid: 0,
        euid: 0,
        gid: 0,
        egid: 0,
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

impl Files for Guest {
    fn open(&mut self, path: &[u8]) -> arena::Result<u64> {
        if path.len() >= exec::PATH_MAX || path.contains(&0) {
            return Err(Errno::NAMETOOLONG);
        }
        // SAFETY: used only for the duration of these calls, which don't touch it again.
        let buf = unsafe { PATH.get() };
        buf[..path.len()].copy_from_slice(path);
        buf[path.len()] = 0;
        const O_CLOEXEC: usize = 0o2000000;
        let p = buf.as_ptr() as usize;
        // execve's checks: a regular file this user may execute.
        const X_OK: usize = 1;
        res(lkl_call(lkl::FACCESSAT as c_long, [k::AT_FDCWD as isize as usize, p, X_OK, 0, 0, 0]))?;
        let fd = res(lkl_call(lkl::OPENAT as c_long, [k::AT_FDCWD as isize as usize, p, O_CLOEXEC, 0, 0, 0]))?;
        let mut st = LklStat::default();
        let r = res(lkl_call(lkl::FSTAT as c_long, [fd, &mut st as *mut _ as usize, 0, 0, 0, 0]));
        if r.is_err() || st.st_mode & 0o170000 != 0o100000 {
            lkl_call(l::__lkl__NR_close, [fd, 0, 0, 0, 0, 0]);
            return Err(r.err().unwrap_or(Errno::ACCESS));
        }
        Ok(fd as u64)
    }

    fn size(&mut self, file: u64) -> arena::Result<u64> {
        let mut st = LklStat::default();
        res(lkl_call(lkl::FSTAT as c_long, [file as usize, &mut st as *mut _ as usize, 0, 0, 0, 0]))?;
        Ok(st.st_size as u64)
    }

    fn pread(&mut self, file: u64, offset: u64, buf: &mut [u8]) -> arena::Result<usize> {
        res(lkl_call(l::__lkl__NR_pread64, [file as usize, buf.as_mut_ptr() as usize, buf.len(), offset as usize, 0, 0]))
    }

    fn close_file(&mut self, file: u64) {
        lkl_call(l::__lkl__NR_close, [file as usize, 0, 0, 0, 0, 0]);
    }
}

impl Backing for Guest {
    fn read(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> arena::Result<usize> {
        res(lkl_call(l::__lkl__NR_pread64, [file as usize, addr, len, offset as usize, 0, 0]))
    }

    fn write(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> arena::Result<usize> {
        res(lkl_call(l::__lkl__NR_pwrite64, [file as usize, addr, len, offset as usize, 0, 0]))
    }

    fn retain(&mut self, file: u64) -> arena::Result<u64> {
        const F_GETFL: usize = 3;
        const F_DUPFD_CLOEXEC: usize = 1030;
        const O_ACCMODE: usize = 3;
        const O_RDWR: usize = 2;
        let fl = res(lkl_call(lkl::FCNTL as c_long, [file as usize, F_GETFL, 0, 0, 0, 0]))?;
        if fl & O_ACCMODE != O_RDWR {
            return Err(Errno::ACCESS);
        }
        // A high fd, out of the way of the program's own numbering (it is in its table).
        res(lkl_call(lkl::FCNTL as c_long, [file as usize, F_DUPFD_CLOEXEC, 512, 0, 0, 0])).map(|f| f as u64)
    }

    fn close(&mut self, file: u64) {
        lkl_call(l::__lkl__NR_close, [file as usize, 0, 0, 0, 0, 0]);
    }

    fn release(&mut self, addr: usize, len: usize) -> arena::Result<()> {
        // SAFETY: the arena gives back only pages nothing relies on.
        unsafe { trap::madvise_dontneed(addr, len) }
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
    if flags & (CLONE_VM | CLONE_THREAD) != CLONE_VM | CLONE_THREAD || flags & CLONE_VFORK != 0 {
        // TODO(fork mode): a guest fork is a host fork.
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
    let tid = res(lkl_call(l::__lkl__NR_new_thread, [0; 6]))?;
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
    }
    if flags & CLONE_PARENT_SETTID != 0 {
        write_user(ptid, tid as u32)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        write_user(ctid, tid as u32)?;
    }
    Ok(tid)
}

/// The sandbox ends with `code`: the host's exit.
fn finish(code: i32) -> ! {
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
    lkl_call(l::__lkl__NR_exit_group, [code, 0, 0, 0, 0, 0]);
    // Only if the kernel refused (it doesn't): end anyway.
    finish(code as i32 & 0xff)
}

/// A thread's `exit`: its tid word cleared and woken, then the guest's exit, which comes back as
/// `task_exit`.
fn exit_thread(code: usize) -> ! {
    let ct = if par::enabled() { par::take_clear_tid() } else { me().clear_tid.replace(0) };
    if ct != 0 && write_user(ct, 0u32).is_ok() {
        futexes().wake(&SCHED, ct, 1, futex::FUTEX_BITSET_MATCH_ANY);
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
/// released and LKL's TLS for it cleared. pid 1: init's end, the sandbox's, with its wait status
/// (a fatal signal as 128 + it, as a shell reports it). Otherwise a thread: its coroutine ends.
unsafe extern "C" fn task_exit(pid: core::ffi::c_int, status: core::ffi::c_int) {
    if pid == 1 {
        let code = if status & 0x7f == 0 { (status >> 8) & 0xff } else { 128 + (status & 0x7f) };
        finish(code);
    }
    if par::enabled() {
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

const NR_KILL: usize = 62;
const NR_READLINK: usize = 89;
const NR_READLINKAT: usize = 267;
const NR_TKILL: usize = 200;
const NR_TGKILL: usize = 234;

// ------------------------------------------------------------------------------------------------
// STOPGAP(item 8): signals the program sends its own process.

const SIGCHLD: usize = 17;
const SIGCONT: usize = 18;
const SIGSTOP: usize = 19;
const SIGTTOU: usize = 22;
const SIGURG: usize = 23;
const SIGWINCH: usize = 28;

/// `kill`, `tkill`, `tgkill` aimed at our own process: what its action would do, done here (LKL
/// records actions and masks but delivers nothing to the program yet; and its init would ignore
/// a default-fatal signal, as Linux's does). Other targets: LKL's.
fn self_signal(nr: usize, a: [usize; 6]) -> Option<isize> {
    let pid = lkl_call(l::__lkl__NR_getpid, [0; 6]);
    let sig = match nr {
        NR_KILL if a[0] as i32 == 0 || a[0] as isize == pid => a[1],
        NR_TGKILL if a[0] as isize == pid => a[2],
        NR_TKILL if lkl_call(l::__lkl__NR_tgkill, [pid as usize, a[0], 0, 0, 0, 0]) == 0 => a[1],
        _ => return None,
    };
    if sig == 0 || sig > 64 {
        return None;
    }
    let mut old = LklSigaction::default();
    if lkl_call(lkl::RT_SIGACTION as c_long, [sig, 0, &mut old as *mut _ as usize, 8, 0, 0]) != 0 {
        return None;
    }
    const SIG_DFL: usize = 0;
    let ignored_by_default = matches!(sig, SIGCHLD | SIGCONT | SIGURG | SIGWINCH | SIGSTOP..=SIGTTOU);
    if old.handler == SIG_DFL && !ignored_by_default {
        writeback();
        finish(128 + sig as i32);
    }
    // TODO(item 8): a handler is recorded but not run; SIG_IGN and ignored defaults do nothing.
    Some(0)
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
/// with the path exec loaded, made absolute.
fn set_exe(path: &[u8]) {
    // SAFETY: only exec and readlink use it, never at once.
    let exe = unsafe { EXE.get() };
    let mut n = 0;
    if path.first() != Some(&b'/') {
        let r = lkl_call(l::__lkl__NR_getcwd, [exe.as_mut_ptr() as usize, exe.len(), 0, 0, 0, 0]);
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
    if (p != b"/proc/self/exe" && p != b"/proc/1/exe") || S.exe_len.get() == 0 {
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
/// image as it was. Not yet: the kernel's half (close-on-exec fds, handlers reset: item 10) and
/// ending the process's other threads.
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
    // Threaded mode: the trapping host thread's bound coroutine (via its GS record), not the shared
    // `current` (set by whichever host last held the token). `(0, 0)`: the main thread's root.
    let (lo, size) = if par::enabled() {
        let (l, h) = par::target_ctl();
        (l, h - l)
    } else {
        SCHED.stack()
    };
    if size == 0 {
        // The root: the host thread's own stack, whose extent the scheduler doesn't know.
        let top = S.root_top.get();
        // The program runs on the arena; anything else is runtime code on the root's stack.
        let program = top != 0 && (S.arena_lo.get()..S.arena_hi.get()).contains(&sp);
        return if program { top } else { trap::below_red_zone(uc) };
    }
    if (lo..lo + size).contains(&sp) { trap::below_red_zone(uc) } else { lo + size }
}

/// The dispatcher (`trap::Dispatch`).
fn dispatch(uc: &mut Ucontext) {
    let (nr, a) = uc.syscall();
    if par::enabled() {
        // Threaded mode: hold the CPU token while serving (the kernel, the scheduler, the futexes
        // and the arena are shared). A call that blocks releases and reclaims it inside the
        // scheduler; the exit paths end the host thread holding it. Program code runs in parallel
        // outside the token, so no fairness yield is needed.
        let id = par::enter();
        let r = serve(uc, nr, a);
        uc.set_return(r);
        par::leave(id);
        return;
    }
    let r = serve(uc, nr, a);
    uc.set_return(r);
    // No preemption here: a thread whose calls never block (a poll with timeout 0 in a loop)
    // would keep every other coroutine from running, a new thread among them (it isn't the
    // kernel's to schedule until its first call attaches it). So every so many calls, the others
    // get a turn (threadpoll's last run hung without it).
    let n = S.served.get().wrapping_add(1);
    S.served.set(n);
    if n.is_multiple_of(32) && S.phase.get() == Phase::Program {
        SCHED.yield_now();
    }
}


fn serve(uc: &mut Ucontext, nr: usize, a: [usize; 6]) -> isize {
    if matches!(nr, NR_KILL | NR_TKILL | NR_TGKILL)
        && let Some(r) = self_signal(nr, a)
    {
        return r;
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
    match sysmap::route(nr) {
        Route::Lkl(n) => lkl_call(n as c_long, a),
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
        Rewrite::Pause => lkl_call(lkl::PPOLL as c_long, [0; 6]),
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
        // TODO(fork mode): fork and vfork are host forks; coroutine mode has no processes.
        Rewrite::Fork => -(Errno::NOSYS.raw_os_error() as isize),
    }
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
    let r = lkl_call(lkl::RT_SIGACTION as c_long, [sig, np, op, 8, 0, 0]);
    // LKL checked `sig` (1..=64): the table is safe to index now.
    if r == 0 {
        let slot = &S.restorers[sig];
        if oldp != 0 {
            let _ = write_user(oldp, xabi::sigaction_to_x86(&old, slot.get()));
        }
        if let Some((_, restorer)) = new {
            slot.set(restorer);
        }
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
            const ARCH_SET_FS: usize = 0x1002;
            const ARCH_GET_FS: usize = 0x1003;
            match a[0] {
                ARCH_SET_FS => {
                    uc.mcontext.fs_base = a[1] as u64;
                    0
                }
                ARCH_GET_FS => ret(write_user(a[1], uc.mcontext.fs_base).map(|_| 0)),
                _ => -(Errno::INVAL.raw_os_error() as isize),
            }
        }
        // TODO: the guest's own execve (argv and envp copied out before the old image goes).
        E::Execve if !program => -(Errno::NOSYS.raw_os_error() as isize),
        E::Execve => ret(execve(uc, a[0], a[1], a[2])),
        // execveat(dfd, path, argv, envp, flags): from the working directory only, so far.
        E::Execveat if program && a[0] as i32 == k::AT_FDCWD && a[4] == 0 => ret(execve(uc, a[1], a[2], a[3])),
        E::Execveat => -(Errno::NOSYS.raw_os_error() as isize),
        // TODO(item 8): no handler is run, so there is nothing to return from.
        E::SigReturn => -(Errno::NOSYS.raw_os_error() as isize),
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
    // SAFETY: uaddr is program memory (checked).
    ret(unsafe { futexes().futex(&SCHED, uaddr as *const u32, op, val, ts.as_ref(), val3) })
}
