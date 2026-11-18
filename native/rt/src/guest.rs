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
//! **Stopgaps** for kernel items not landed yet, each marked `STOPGAP(item N)`:
//! - item 11 (host stdio as guest files): the guest's fds 0-2 are placeholders (`/dev/null`,
//!   opened by setup), and reads and writes on the fds that are, or were dup'ed from, them go to
//!   the host's 0/1/2 here ([`Stdio`]). Redirections the program makes itself (`dup2` of another
//!   file onto 1) work; a pipe can't carry them to another process, and a read of stdin holds the
//!   one host thread until it returns.
//! - item 13 (the memory size): `sysinfo` reports the arena's size and free space.
//! - item 8 (signals): a signal the program sends its own process whose action is the default
//!   and fatal ends the sandbox with 128 + the signal, as capnix did; handlers are recorded by
//!   LKL but never run.
//! - item 6 (exit reporting): init's exit status is what `lkl_syscall` returns for its
//!   `exit_group` (item 4); a thread's exit is its coroutine's end (LKL's TLS destructor ends
//!   its task).

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
/// Guest fds whose host-stdio placeholder status is tracked (STOPGAP(item 11)).
const STDIO_FDS: usize = 64;

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
    stdio: Stdio,
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
    stdio: Stdio::new(),
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
    // SAFETY: the table and its scheduler are installed; one kernel per process.
    let r = unsafe { l::lkl_init(host::ops()) };
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
    filter::install(prog, 0).map_err(err("installing the routing filter"))?;
    S.phase.set(Phase::Setup);
    Ok(())
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
    match load(path, argv, envp, aux) {
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

fn load(path: &[u8], argv: &[&[u8]], envp: &[&[u8]], aux: Aux) -> Result<Registers, Errno> {
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
    with_arena(|a, b| {
        let img = prog.map(a, b)?;
        let lo = a.mmap(b, 0, STACK, arena::PROT_READ | arena::PROT_WRITE, arena::MAP_PRIVATE | arena::MAP_ANONYMOUS, None)?;
        // SAFETY: just mapped, read/write, the program's from now on.
        let start = unsafe { img.build_stack(lo, lo + STACK, &p) }?;
        Ok(start.registers())
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
        fill(fd);
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
    let t = me();
    let tid = t.attach.replace(0);
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
    let i = S.threads.iter().position(|t| !t.used.get()).ok_or(Errno::AGAIN)?;
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
    // SAFETY: the program's own state after its `clone`, as Linux starts the child.
    // TODO: on failure the guest thread new_thread made stays, never run (item 6 will end it).
    let co: Tid = unsafe { SCHED.spawn_registers(&regs, fs) }.map_err(|_| Errno::AGAIN)?;
    let _ = SCHED.detach(co);
    let t = &S.threads[i];
    t.used.set(true);
    t.co.set(co.raw());
    t.attach.set(tid as i32);
    t.clear_tid.set(if flags & CLONE_CHILD_CLEARTID != 0 { ctid } else { 0 });
    if flags & CLONE_PARENT_SETTID != 0 {
        write_user(ptid, tid as u32)?;
    }
    if flags & CLONE_CHILD_SETTID != 0 {
        write_user(ctid, tid as u32)?;
    }
    Ok(tid)
}

/// The sandbox ends with `code`: shared file mappings written back, then the host's exit.
fn finish(code: i32) -> ! {
    if S.phase.get() == Phase::Program {
        let _ = with_arena(|a, b| a.writeback_all(b));
    }
    trap::exit_group(code)
}

/// init's end: `lkl_syscall` returns its wait status (item 4).
fn exit_group(code: usize) -> ! {
    let st = lkl_call(l::__lkl__NR_exit_group, [code, 0, 0, 0, 0, 0]);
    finish(if st >= 0 { ((st >> 8) & 0xff) as i32 } else { code as i32 & 0xff })
}

/// A thread's `exit`: its tid word cleared and woken, then its coroutine ends (and LKL's TLS
/// destructor ends its task). The main thread's exit while others run: not yet.
fn exit_thread(code: usize) -> ! {
    let t = me();
    let ct = t.clear_tid.replace(0);
    if ct != 0 && write_user(ct, 0u32).is_ok() {
        futexes().wake(&SCHED, ct, 1, futex::FUTEX_BITSET_MATCH_ANY);
    }
    if core::ptr::eq(t, &S.threads[0]) {
        // init's last thread: its exit is init's (lkl_syscall returns the status).
        let st = lkl_call(l::__lkl__NR_exit, [code, 0, 0, 0, 0, 0]);
        if st >= 0 {
            finish(((st >> 8) & 0xff) as i32);
        }
        // TODO(item 6): the main thread ends before its other threads; it waits forever here.
        loop {
            SCHED.block(None);
        }
    }
    // Its first LKL call (a thread that made none still has a guest task waiting to be taken).
    lkl_call(l::__lkl__NR_gettid, [0; 6]);
    t.co.set(0);
    t.used.set(false);
    SCHED.exit(0)
}

// ------------------------------------------------------------------------------------------------
// STOPGAP(item 12): image files filled on first open.

/// A regular file of an image unpacked into the guest's ramfs (`exobox::setup::mount_erofs`)
/// empty: its contents are written in from the host mapping the first time any open of it
/// succeeds, so a closure of hundreds of MB costs only what the program opens; until then stat
/// calls report its real size. Until memblk mounts images in place.
#[derive(Debug)]
pub struct LazyFile {
    /// Its inode number on the guest's root filesystem.
    pub ino: u64,
    /// Its contents, in the image's host mapping.
    pub data: &'static [u8],
    /// 0: empty, 1: being filled, 2: filled.
    state: Cell<u8>,
}

impl LazyFile {
    pub fn new(ino: u64, data: &'static [u8]) -> Self {
        LazyFile { ino, data, state: Cell::new(0) }
    }
}

const LAZY_TABLES: usize = 256;

struct Lazy {
    /// The root filesystem's `st_dev`, which the inode numbers are of, and as statx gives it.
    dev: Cell<u64>,
    statx_dev: Cell<(u32, u32)>,
    tables: [Cell<&'static [LazyFile]>; LAZY_TABLES],
}

// SAFETY: one host thread (see `Local`).
unsafe impl Sync for Lazy {}

static LAZY: Lazy = Lazy { dev: Cell::new(u64::MAX), statx_dev: Cell::new((0, 0)), tables: [const { Cell::new(&[]) }; LAZY_TABLES] };

/// Register an image's lazy files, sorted by `ino`, all on the filesystem of `/`.
pub fn lazy_files(files: &'static [LazyFile]) -> Result<(), Error> {
    debug_assert!(files.is_sorted_by_key(|f| f.ino));
    if LAZY.dev.get() == u64::MAX {
        let mut st = LklStat::default();
        let r = lkl_call(lkl::NEWFSTATAT as c_long, [k::AT_FDCWD as isize as usize, c"/".as_ptr() as usize, &mut st as *mut _ as usize, 0, 0, 0]);
        res(r).map_err(err("stat /"))?;
        let mut stx = [0u8; 256];
        const STATX_BASIC_STATS: usize = 0x7ff;
        let r = lkl_call(l::__lkl__NR_statx, [k::AT_FDCWD as isize as usize, c"/".as_ptr() as usize, 0, STATX_BASIC_STATS, stx.as_mut_ptr() as usize, 0]);
        res(r).map_err(err("statx /"))?;
        let u32_at = |o: usize| u32::from_ne_bytes(stx[o..o + 4].try_into().unwrap());
        LAZY.statx_dev.set((u32_at(STX_DEV_MAJOR), u32_at(STX_DEV_MINOR)));
        LAZY.dev.set(st.st_dev);
    }
    let slot = LAZY.tables.iter().find(|t| t.get().is_empty()).ok_or(Error { what: "lazy image tables", errno: Errno::NOSPC })?;
    slot.set(files);
    Ok(())
}

// struct statx's fields the size fix reads and writes.
const STX_INO: usize = 32;
const STX_SIZE: usize = 40;
const STX_DEV_MAJOR: usize = 136;
const STX_DEV_MINOR: usize = 140;

fn lazy_file(ino: u64) -> Option<&'static LazyFile> {
    LAZY.tables.iter().find_map(|t| {
        let t = t.get();
        t.binary_search_by_key(&ino, |f| f.ino).ok().map(|i| &t[i])
    })
}

/// A stat result for an image file not filled yet: its real size, not the placeholder's 0.
fn lazy_stat(st: &mut LklStat) {
    if st.st_dev == LAZY.dev.get() && st.st_size == 0 && st.st_mode & 0o170000 == 0o100000
        && let Some(f) = lazy_file(st.st_ino).filter(|f| f.state.get() != 2)
    {
        st.st_size = f.data.len() as i64;
        st.st_blocks = f.data.len().div_ceil(512) as i64;
    }
}

/// The same for a statx result the program asked for, in its buffer.
fn lazy_statx(buf: usize) {
    if LAZY.dev.get() == u64::MAX || !user(buf, 256) {
        return;
    }
    // SAFETY: checked to be program memory, struct statx's 256 bytes.
    let b = unsafe { core::slice::from_raw_parts_mut(buf as *mut u8, 256) };
    let u32_at = |b: &[u8], o: usize| u32::from_ne_bytes(b[o..o + 4].try_into().unwrap());
    let u64_at = |b: &[u8], o: usize| u64::from_ne_bytes(b[o..o + 8].try_into().unwrap());
    if (u32_at(b, STX_DEV_MAJOR), u32_at(b, STX_DEV_MINOR)) != LAZY.statx_dev.get() || u64_at(b, STX_SIZE) != 0 {
        return;
    }
    if let Some(f) = lazy_file(u64_at(b, STX_INO)).filter(|f| f.state.get() != 2) {
        b[STX_SIZE..STX_SIZE + 8].copy_from_slice(&(f.data.len() as u64).to_ne_bytes());
    }
}

/// After a successful open of `fd`: if it is an image file not filled yet, fill it.
fn fill(fd: usize) {
    if LAZY.dev.get() == u64::MAX {
        return;
    }
    let mut st = LklStat::default();
    if lkl_call(lkl::FSTAT as c_long, [fd, &mut st as *mut _ as usize, 0, 0, 0, 0]) != 0
        || st.st_dev != LAZY.dev.get()
        || st.st_mode & 0o170000 != 0o100000
    {
        return;
    }
    let Some(f) = lazy_file(st.st_ino) else {
        return;
    };
    while f.state.get() == 1 {
        SCHED.yield_now();
    }
    if f.state.get() == 2 {
        return;
    }
    f.state.set(1);
    // A write handle on the same file (the program's fd may be read-only): /proc/self/fd/<fd>.
    let mut path = *b"/proc/self/fd/\0\0\0\0\0\0\0\0\0\0\0";
    let mut n = 14;
    let mut digits = [0u8; 10];
    let (mut v, mut d) = (fd, 0);
    loop {
        digits[d] = b'0' + (v % 10) as u8;
        d += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    while d > 0 {
        d -= 1;
        path[n] = digits[d];
        n += 1;
    }
    const O_WRONLY: usize = 1;
    const O_CLOEXEC: usize = 0o2000000;
    let w = lkl_call(lkl::OPENAT as c_long, [k::AT_FDCWD as isize as usize, path.as_ptr() as usize, O_WRONLY | O_CLOEXEC, 0, 0, 0]);
    if w >= 0 {
        let mut off = 0;
        while off < f.data.len() {
            let chunk = (f.data.len() - off).min(1 << 20);
            let r = lkl_call(l::__lkl__NR_pwrite64, [w as usize, f.data[off..].as_ptr() as usize, chunk, off, 0, 0]);
            if r <= 0 {
                break;
            }
            off += r as usize;
        }
        lkl_call(l::__lkl__NR_close, [w as usize, 0, 0, 0, 0, 0]);
    }
    f.state.set(2);
}

// ------------------------------------------------------------------------------------------------
// STOPGAP(item 11): host stdio behind the guest's placeholder fds.

struct Stdio {
    /// For each guest fd below STDIO_FDS: the host fd it stands for, or -1.
    host: [Cell<i8>; STDIO_FDS],
}

impl Stdio {
    const fn new() -> Self {
        let mut host = [const { Cell::new(-1) }; STDIO_FDS];
        host[0] = Cell::new(0);
        host[1] = Cell::new(1);
        host[2] = Cell::new(2);
        Stdio { host }
    }
    fn of(&self, fd: usize) -> Option<u32> {
        let h = self.host.get(fd)?.get();
        (h >= 0).then_some(h as u32)
    }
    fn set(&self, fd: usize, h: Option<u32>) {
        if let Some(c) = self.host.get(fd) {
            c.set(h.map_or(-1, |h| h as i8));
        }
    }
}

const NR_READ: usize = 0;
const NR_WRITE: usize = 1;
const NR_CLOSE: usize = 3;
const NR_READV: usize = 19;
const NR_WRITEV: usize = 20;
const NR_DUP: usize = 32;
const NR_KILL: usize = 62;
const NR_FCNTL: usize = 72;
const NR_SYSINFO: usize = 99;
const NR_TKILL: usize = 200;
const NR_TGKILL: usize = 234;
const NR_DUP3: usize = 292;
const NR_CLOSE_RANGE: usize = 436;

/// One read or write on host stdio `h`: the filter allows reads of 0 and writes of 1 and 2.
fn stdio_io(write: bool, h: u32, p: usize, n: usize) -> isize {
    if !user(p, n) {
        return -(Errno::FAULT.raw_os_error() as isize);
    }
    // SAFETY: checked to be program memory.
    let r = unsafe {
        if write {
            if h == 0 {
                return -(Errno::BADF.raw_os_error() as isize);
            }
            trap::write(h, core::slice::from_raw_parts(p as *const u8, n))
        } else {
            if h != 0 {
                return -(Errno::BADF.raw_os_error() as isize);
            }
            trap::read(0, core::slice::from_raw_parts_mut(p as *mut u8, n))
        }
    };
    ret(r)
}

#[repr(C)]
#[derive(Clone, Copy)]
struct Iovec {
    base: usize,
    len: usize,
}

/// The calls on fds that may be host stdio, before routing (None: not stdio, route as usual).
fn stdio_call(nr: usize, a: [usize; 6]) -> Option<isize> {
    let st = &S.stdio;
    match nr {
        NR_READ | NR_WRITE => {
            let h = st.of(a[0])?;
            Some(stdio_io(nr == NR_WRITE, h, a[1], a[2]))
        }
        NR_READV | NR_WRITEV => {
            let h = st.of(a[0])?;
            let mut total = 0isize;
            for i in 0..a[2].min(1024) {
                let v: Iovec = match read_user(a[1] + i * size_of::<Iovec>()) {
                    Ok(v) => v,
                    Err(e) => return Some(-(e.raw_os_error() as isize)),
                };
                if v.len == 0 {
                    continue;
                }
                let r = stdio_io(nr == NR_WRITEV, h, v.base, v.len);
                if r < 0 {
                    return Some(if total > 0 { total } else { r });
                }
                total += r;
                if (r as usize) < v.len {
                    break;
                }
            }
            Some(total)
        }
        NR_CLOSE => {
            st.set(a[0], None);
            None
        }
        NR_DUP | NR_DUP3 | NR_FCNTL => {
            const F_DUPFD: usize = 0;
            const F_DUPFD_CLOEXEC: usize = 1030;
            let h = st.of(a[0]);
            if nr == NR_FCNTL && a[1] != F_DUPFD && a[1] != F_DUPFD_CLOEXEC {
                return None;
            }
            let r = match nr {
                NR_DUP => lkl_call(23, a),
                NR_DUP3 => lkl_call(lkl::DUP3 as c_long, a),
                _ => lkl_call(lkl::FCNTL as c_long, a),
            };
            if r >= 0 {
                st.set(r as usize, h);
            }
            Some(r)
        }
        NR_CLOSE_RANGE => {
            const CLOSE_RANGE_CLOEXEC: usize = 4;
            if a[2] & CLOSE_RANGE_CLOEXEC == 0 {
                for fd in a[0]..=a[1].min(STDIO_FDS - 1) {
                    st.set(fd, None);
                }
            }
            None
        }
        _ => None,
    }
}

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
        finish(128 + sig as i32);
    }
    // TODO(item 8): a handler is recorded but not run; SIG_IGN and ignored defaults do nothing.
    Some(0)
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
    let (lo, size) = SCHED.stack();
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
    let r = serve(uc, nr, a);
    uc.set_return(r);
}

fn serve(uc: &mut Ucontext, nr: usize, a: [usize; 6]) -> isize {
    if let Some(r) = stdio_call(nr, a) {
        return r;
    }
    match nr {
        NR_KILL | NR_TKILL | NR_TGKILL => {
            if let Some(r) = self_signal(nr, a) {
                return r;
            }
        }
        NR_SYSINFO => return sysinfo(a[0]),
        _ => {}
    }
    let r = match sysmap::route(nr) {
        Route::Lkl(n) => lkl_call(n as c_long, a),
        Route::Rewrite(rw) => rewrite(rw, a),
        Route::Emulate(e) => emulate(uc, e, nr, a),
        Route::Errno(e) => e.ret(),
    };
    // STOPGAP(item 12): open, openat, openat2 of an image file not filled yet.
    if matches!(nr, 2 | 257 | 437) && r >= 0 {
        fill(r as usize);
    }
    if nr == 332 && r == 0 {
        lazy_statx(a[4]);
    }
    r
}

/// STOPGAP(item 13): `sysinfo` says the arena's size (the program's memory), not the kernel's pool.
fn sysinfo(p: usize) -> isize {
    if !user(p, 112) {
        return -(Errno::FAULT.raw_os_error() as isize);
    }
    let r = lkl_call(l::__lkl__NR_sysinfo, [p, 0, 0, 0, 0, 0]);
    if r == 0 && S.phase.get() == Phase::Program {
        let st = with_arena(|a, _| a.stats());
        // struct sysinfo: totalram at 32, freeram at 40, mem_unit at 104.
        // SAFETY: checked above.
        unsafe {
            ((p + 32) as *mut u64).write_unaligned(st.size as u64);
            ((p + 40) as *mut u64).write_unaligned((st.size - st.mapped) as u64);
            ((p + 104) as *mut u32).write_unaligned(1);
        }
    }
    r
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
            lazy_stat(&mut st);
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
            let h = S.stdio.of(a[0]);
            let r = lkl_call(lkl::DUP3 as c_long, [a[0], a[1], 0, 0, 0, 0]);
            if r >= 0 {
                S.stdio.set(a[1], h);
            }
            r
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
                if a[4] as i32 >= 0 && S.stdio.of(a[4]).is_some() {
                    return -(Errno::NODEV.raw_os_error() as isize);
                }
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
            me().clear_tid.set(a[0]);
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
        E::Execve | E::Execveat => -(Errno::NOSYS.raw_os_error() as isize),
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
