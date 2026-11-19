//! Fork mode: a guest fork is a host fork, and the processes run one kernel.
//!
//! - **What's shared** (`share`): the kernel's memory (its data, its pool, every coroutine stack,
//!   kernel stacks among them) and the runtime state that runs it (the scheduler, the CPU token and
//!   every process's host-thread slots, the host ops' pools, the futex table), mapped shared before
//!   lockdown. **What's private**, copied by the host fork: the program's memory (the arena) and
//!   the runtime's per-process state (the arena's table, signal restorers, the exec's buffers and
//!   `/proc/self/exe`, the guest's per-thread records).
//! - **One CPU.** The processes' host threads take turns on threaded mode's CPU token (`par`), in
//!   shared memory; a thread waits for it on its slot's eventfd, made before lockdown for every slot
//!   and inherited by every fork, so a hand-off to a thread of another process is a write there.
//!   A coroutine bound to a host thread runs only on it, in its process; the kernel's own (its
//!   threads, the timers) run wherever the token is.
//! - **Kernel stacks are shared memory.** Kernel code keeps objects on its stack that other tasks
//!   reach (a wait queue entry while a `wait4` blocks): every trap is served on a coroutine stack,
//!   init's main thread's too (`par::root_on_shared_stack`).
//! - **fork** is the kernel's clone ([`clone_process`]): the child task, its files, its parent, the
//!   wait for a vfork. Inside it the kernel calls the `fork` host op ([`fork_op`]) on the parent's
//!   host thread with the CPU held: it takes a slot for the child's first thread, leaves the
//!   child's start state in that slot's boot region (private memory) and forks the host process
//!   from there (`par::host_fork`: `clone(SIGCHLD)` through the gate, as the filter allows; a
//!   child of a child with `CLONE_PARENT`, so every process is init's host child). The child
//!   ([`fork_child`]) takes the token, runs the kernel's bootstrap on its control stack until the
//!   kernel first schedules its task, then resumes the program after its clone with 0.
//! - **exec** in a forked process is the guest's (`execve`, with `new_exec`), into its own arena;
//!   memory is high-water there (no `madvise` with host threads), so the old image's pages are
//!   reused.
//! - **Ends.** A forked process's `exit_group` and fatal signals are the kernel's: its parent waits
//!   for the status. Its last task's `task_exit` ends the host process (`par::process_exited`).
//!   Init's end is the sandbox's: the other processes see init's pidfd (made before lockdown) in
//!   their token waits and exit. A process dying on the host instead (a crash; the filter's kill)
//!   is seen by init, every process's host parent: its SIGCHLD ([`on_sigchld`], children reaped by
//!   `SA_NOCLDWAIT`) for anything but a clean exit ends the sandbox with the same signal, since the
//!   kernel's shared state may be half-updated.
//! - **The bound** (`--max-procs`): a fork past it fails with EAGAIN, in the op.
//! - **Not here**: the network's hooks (they run in init's process; a child's host ops would have
//!   to reach init's executor: `net_fork`); a `MAP_SHARED` mapping of the arena shared across a
//!   fork (each process's memory is its own copy).

use super::*;

/// clone's flags for a plain fork.
pub(super) const SIGCHLD: usize = trap::SIGCHLD as usize;
const CLONE_PARENT: u64 = trap::CLONE_PARENT;
const SA_NOCLDWAIT: u64 = 2;

/// Fork mode is on (this process's: set before lockdown, copied by every fork).
static ENABLED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

pub(super) fn enabled() -> bool {
    ENABLED.load(core::sync::atomic::Ordering::Relaxed)
}

/// Fork mode, in init's process before lockdown, after [`enable_threaded`]: the `fork` host op,
/// the bound on processes, init's pidfd for the others to watch (`init_pidfd`, the host's: made
/// by exobox's inventory), the SIGCHLD handler that sees a process die on the host, and init's
/// main thread's traps on a shared stack.
pub fn enable_fork(max_procs: u32, init_pidfd: i32) -> Result<(), Error> {
    par::set_max_procs(max_procs);
    par::set_init_pidfd(init_pidfd);
    // SAFETY: the handler makes only gate calls; before lockdown.
    unsafe { trap::install_handler(17, on_sigchld, SA_NOCLDWAIT) }.map_err(err("the SIGCHLD handler"))?;
    par::root_on_shared_stack().map_err(err("init's kernel stack"))?;
    // The hooks' executor is init's process's: its coroutine runs only on init's kernel thread.
    crate::executor::set_home(par::KERNEL);
    // SAFETY: written once before the kernel's first clone reads it.
    unsafe { (*host::ops()).fork = Some(fork_op) };
    ENABLED.store(true, core::sync::atomic::Ordering::Relaxed);
    Ok(())
}

/// A clone that makes a process (no `CLONE_THREAD`: fork, vfork, posix_spawn's `CLONE_VM |
/// CLONE_VFORK` with a stack): the kernel's clone, whose `fork` op forks the host process. With
/// `CLONE_VM` the child still gets a copy of the memory, not the parent's (a host process of its
/// own): posix_spawn's child runs on the stack it was given there, and an exec failure it records
/// for its parent is lost (the parent sees it exit 127).
pub(super) fn clone_process(uc: &Ucontext, a: [usize; 6]) -> Result<usize, Errno> {
    let (flags, newsp, ptid, ctid, tls) = (a[0], a[1], a[2], a[3], a[4]);
    if (flags & CLONE_PARENT_SETTID != 0 && !user(ptid, 4))
        || (flags & (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID) != 0 && !user(ctid, 4))
    {
        return Err(Errno::FAULT);
    }
    let t = cur();
    t.fork_sp.set(newsp);
    t.fork_fs.set(if flags & CLONE_SETTLS != 0 { tls } else { uc.mcontext.fs_base as usize });
    // The kernel's own order (generic clone: flags, newsp, ptid, ctid, tls); the stack is the
    // host's business (`fork_op`).
    let r = lkl_call(l::__lkl__NR_clone, [flags & !CLONE_SETTLS, 0, ptid, ctid, 0, 0]);
    t.fork_sp.set(0);
    res(r)
}

/// What a fork's child starts from, left in its first slot's boot region by the parent.
struct ForkStart {
    /// The program's state after its clone (rax 0, the child's stack and FS base): the child
    /// resumes from it, and a signal delivered at the clone's return builds its frame from it.
    uc: Ucontext,
    f: unsafe extern "C" fn(*mut core::ffi::c_void),
    arg: *mut core::ffi::c_void,
    proc: u32,
    slot: u16,
}

/// The `fork` host op (the kernel series' item 9), on the parent's host thread inside its clone,
/// the CPU held (no calls into the kernel): fork the host process; in the child, a thread runs
/// `f(arg)` and then the program. Returns that thread's id (its bound coroutine: what
/// `thread_self` says there), or 0 (the clone fails with EAGAIN).
unsafe extern "C" fn fork_op(f: Option<unsafe extern "C" fn(*mut core::ffi::c_void)>, arg: *mut core::ffi::c_void) -> l::lkl_thread_t {
    let Some(f) = f else { return 0 };
    let t = cur();
    let ucp = t.uc.get();
    if ucp == 0 {
        return 0; // not a program's clone (none other reaches here)
    }
    // SAFETY: the dispatch's trap frame, live below us.
    let trap_uc = unsafe { *(ucp as *const Ucontext) };
    let Some(proc) = par::take_proc() else { return 0 };
    let (id, bound) = match par::fork_slot(proc) {
        Ok(x) => x,
        Err(_) => {
            par::drop_proc();
            return 0;
        }
    };
    // The child's start in the slot's boot region: private memory, the child's copy its own.
    let top = par::boot_top(id);
    let start_at = (top - size_of::<ForkStart>()) & !63;
    let mut u = trap_uc;
    u.link = 0;
    u.mcontext.rax = 0;
    if t.fork_sp.get() != 0 {
        u.mcontext.rsp = t.fork_sp.get() as u64;
    }
    u.mcontext.fs_base = t.fork_fs.get() as u64;
    u.mcontext.fpregs = 0;
    // SAFETY: the slot's boot region, unused until the child starts there.
    unsafe { (start_at as *mut ForkStart).write(ForkStart { uc: u, f, arg, proc, slot: id }) };
    // The frame the host child's `rt_sigreturn` takes (`par::host_fork`): `fork_child(start_at)`
    // on the boot stack, below the frame, with the slot's alternate stack installed and the
    // trap's host signal mask.
    let frame = ((start_at - 8 - size_of::<Ucontext>()) & !63) - 8;
    let mut fu = trap_uc;
    fu.link = 0;
    let (alt, alt_len) = par::alt_stack(id);
    fu.stack = StackT { sp: alt, flags: 0, size: alt_len };
    fu.mcontext.rip = fork_child as *const () as u64;
    fu.mcontext.rdi = start_at as u64;
    fu.mcontext.rsp = (((frame - 256) & !15) - 8) as u64;
    fu.mcontext.rbp = 0;
    fu.mcontext.fpregs = 0;
    // SAFETY: inside the boot region, below the start state.
    unsafe {
        (frame as *mut usize).write(0);
        ((frame + 8) as *mut Ucontext).write(fu);
    }
    // Every process is init's host child: init's SIGCHLD sees any of them die.
    let flags = if par::forked() { SIGCHLD as u64 | CLONE_PARENT } else { SIGCHLD as u64 };
    // SAFETY: below the frame, in the slot's boot region; the frame starts the child.
    let pid = unsafe { par::host_fork(((frame - 4096) & !15) as usize, flags, frame) };
    if pid < 0 {
        par::drop_slot(id);
        par::drop_proc();
        return 0;
    }
    bound.raw() as l::lkl_thread_t
}

/// The child's bootstrap is running on this process's first thread (private: the `thread_exit`
/// host op ends the process when it is).
static BOOTSTRAP: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

/// The host fork's child, entered by `rt_sigreturn` on its first slot's boot stack with its own
/// alternate stack: become that slot's host thread, take the token, run the kernel's bootstrap
/// (`f`) on the slot's control stack, then resume the program after its clone.
extern "C" fn fork_child(start_at: usize) -> ! {
    // SAFETY: the parent left it there; this process's own copy.
    let st = unsafe { &mut *(start_at as *mut ForkStart) };
    par::become_child(st.proc);
    // The parent's per-process state, as the fork copied it: nothing of it is this process's
    // threads' (they are this one), and an arena operation another of the parent's threads had
    // in progress has no thread here to finish it.
    S.arena_busy.set(false);
    let t = &S.threads[st.slot as usize];
    t.reset_signals();
    t.fork_sp.set(0);
    par::child_start(st.slot);
    // SAFETY: the bound coroutine's control stack is this thread's; `bootstrap` returns.
    unsafe { par::call_on_stack(par::ctl_top(), bootstrap, start_at) };
    let m = &st.uc.mcontext;
    let regs = Registers {
        rax: m.rax,
        rbx: m.rbx,
        rcx: m.rcx,
        rdx: m.rdx,
        rsi: m.rsi,
        rdi: m.rdi,
        rbp: m.rbp,
        rsp: m.rsp,
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
    let fs = m.fs_base;
    par::leave(st.slot);
    // SAFETY: the program's state after its clone; no Rust code runs between the two.
    unsafe {
        core::arch::asm!("wrfsbase {}", in(reg) fs, options(nomem, nostack));
        context::restore(&regs)
    }
}

/// The kernel's bootstrap for the child (`fork_bootstrap`), on the control stack: it waits until
/// the kernel first schedules the child's task, makes it this thread's, and delivers the clone's
/// return (a signal's handler runs from the start state, which it may change).
extern "C" fn bootstrap(start_at: usize) {
    // SAFETY: as fork_child's.
    let st = unsafe { &mut *(start_at as *mut ForkStart) };
    let t = cur();
    t.uc.set(&raw mut st.uc as usize);
    BOOTSTRAP.store(true, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: the kernel's function and argument, called on a thread of its own as it asks.
    unsafe { (st.f)(st.arg) };
    BOOTSTRAP.store(false, core::sync::atomic::Ordering::Relaxed);
    t.uc.set(0);
}

/// The `thread_exit` host op on a fork's child during its bootstrap: the clone failed after the
/// host fork (a signal came, and it restarts). The parent's `thread_join` waits for the thread's
/// coroutine; the process ends.
pub(crate) fn bootstrap_exit() {
    if BOOTSTRAP.load(core::sync::atomic::Ordering::Relaxed) {
        SCHED.retire_current(0);
        // Its joiner frees the coroutine, not the slot's end.
        par::disown_bound();
        par::process_exited(par::my_id());
    }
}

/// Init's SIGCHLD: a process of the sandbox ended on the host. A clean exit (status 0) is how
/// every process ends (`par::process_end`, or init's end seen); anything else is a death the
/// kernel didn't see (a crash, the filter's kill), with the kernel's shared state possibly
/// half-updated: the sandbox ends with it, by the same signal.
unsafe extern "C" fn on_sigchld(_sig: i32, info: *mut trap::Siginfo, _uc: *mut Ucontext) {
    const CLD_EXITED: i32 = 1;
    // SAFETY: the kernel's siginfo; SIGCHLD's si_status is at 24.
    let (code, status) = unsafe { ((*info).code, ((info as usize + 24) as *const i32).read()) };
    if code == CLD_EXITED && status == 0 {
        return;
    }
    if code == CLD_EXITED {
        trap::exit_group(status);
    }
    die(status)
}
