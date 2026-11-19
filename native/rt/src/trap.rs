//! The gate, and a trapped syscall's way in and out: the SIGSYS entry, the frame's move off the
//! program's stack, and the return through `rt_sigreturn`.
//!
//! **The gate.** After lockdown every syscall the program makes is trapped (`SECCOMP_RET_TRAP`
//! → SIGSYS) and served in-process; the runtime's own host syscalls are allowed only from one
//! instruction, the `syscall` in [`gate`], which the filter recognises by the address just past it
//! ([`gate_ip`], for `filter::Params::gate_ip`). rustix's wrappers have `syscall` instructions of
//! their own, inlined wherever they are called: they are **not** the gate. Before lockdown they
//! work like any syscall; after it each one traps, and the handler would serve it as if the
//! program had made it. So the host calls made after lockdown go through [`gate`] directly, by
//! the typed wrappers below (one per call the filter allows), and rustix is for setup only.
//!
//! **The way in.** The kernel delivers SIGSYS on the host thread's alternate stack
//! ([`set_altstack`]), never the program's: a native syscall writes nothing below the caller's sp,
//! and Go makes raw syscalls from goroutine stacks with ~128 bytes to spare (capnix: the ~2 KB frame
//! overflowed into the next goroutine's stack). The entry (`sigsys_entry`, asm) then, before any
//! syscall and with no TLS:
//! 1. switches FS to the runtime's (captured by [`install`]): the program has its own libc and
//!    TLS, and the runtime's code must find its own (capnix: "two libcs in one address space").
//!    The program's FS base is kept in the frame ([`Mcontext::fs_base`]) and loaded again on the
//!    way out: `rt_sigreturn` restores registers, not the FS base;
//! 2. copies the frame — from the entry sp to the alternate stack's top: the return address, the
//!    ucontext, the siginfo and the xsave area — to the stack the target hook ([`Target`]) names,
//!    keeping its offset modulo 64 (`xrstor` needs the xsave area 64-aligned) and fixing
//!    `fpregs`, the one pointer into the frame the kernel follows. In production that is the
//!    trapping coroutine's control stack, so the frame never stays on the alternate stack, which
//!    every coroutine of the host thread shares, across a coroutine switch;
//! 3. calls the dispatcher ([`Dispatch`]) on the moved frame, then returns through the restorer:
//!    `rt_sigreturn` reads the frame at the new sp (its fpstate pointer, now adjusted, too).
//!
//! **The dispatcher's contract.** The number is the trapped `rax`: a seccomp trap rolls `ax` back
//! to `orig_ax` (`syscall_rollback`, arch/x86/include/asm/syscall.h), so it equals the siginfo's
//! `si_syscall`. The arguments are rdi, rsi, rdx, r10, r8, r9 ([`Ucontext::syscall`]); the result
//! goes in `rax` ([`Ucontext::set_return`]). It may change any register in the frame (a clone's
//! child state, a signal handler's entry) and the FS base the program resumes with
//! ([`Mcontext::fs_base`]: `arch_prctl(ARCH_SET_FS)`). It runs with the runtime's FS, on the
//! target stack, and may suspend (switch coroutines): the frame is the coroutine's own. It must
//! return on the host thread it was entered on: the frame's `uc_stack` is that thread's alternate
//! stack, which `rt_sigreturn` sets again.
//!
//! **Flags** ([`install`]): `SA_SIGINFO` (the ucontext), `SA_ONSTACK` (above), `SA_RESTORER` with
//! the runtime's own restorer (no libc's `__restore_rt` needed), and `SA_NODEFER`. Without
//! `SA_NODEFER` the kernel blocks SIGSYS for the handler's duration, and a handler here is not a
//! nested scope on its host thread: it suspends, and the next coroutine may start the program fresh
//! (`context::restore`, no `rt_sigreturn` to unblock it). A seccomp trap with SIGSYS blocked
//! doesn't wait: `force_sig_info_to_task` resets the action to `SIG_DFL` and the process dies.
//! With `SA_NODEFER` the host mask never changes (the program's mask is emulated, not the host's),
//! and a trap from inside the dispatcher (a runtime bug, or code meant to trap) is delivered like
//! any other: on the alternate stack's top, free again because the outer frame was moved. capnix
//! used it too, for the first reason. Not `SA_RESTART`: it only matters for a syscall a signal
//! interrupts, and the trapped syscall never ran.
//!
//! Nothing here allocates or touches TLS. The entry switches FS before anything else, so the
//! target hook and the dispatcher both run with the runtime's.

use core::mem::offset_of;
use core::sync::atomic::{AtomicUsize, Ordering};

use rustix::io::Errno;

use crate::filter::{CLONE_HOST_THREAD, NR_CLONE, NR_EXIT, NR_EXIT_GROUP};
use crate::filter::{NR_PPOLL, NR_READ, NR_WRITE};
use crate::xabi::{SA_RESTORER, Timespec, X86Sigaction};

// ------------------------------------------------------------------------------------------------
// The gate.

/// The one `syscall` instruction the filter lets reach the host: `nr(a0, …, a5)`, returning the
/// raw result (`-errno` on failure). Before lockdown it is an ordinary syscall; after, the filter
/// decides from the mode's list (`filter::HOST`), and anything else is denied.
///
/// # Safety
/// It is a raw syscall: whatever `nr` does with the arguments (memory they point to, the process).
#[unsafe(naked)]
pub unsafe extern "C" fn gate(
    nr: usize,
    a0: usize,
    a1: usize,
    a2: usize,
    a3: usize,
    a4: usize,
    a5: usize,
) -> isize {
    // SysV passes nr..a4 in rdi, rsi, rdx, rcx, r8, r9 and a5 on the stack; the kernel wants nr in
    // rax and the arguments in rdi, rsi, rdx, r10, r8, r9.
    core::arch::naked_asm!(
        "mov rax, rdi",
        "mov rdi, rsi",
        "mov rsi, rdx",
        "mov rdx, rcx",
        "mov r10, r8",
        "mov r8, r9",
        "mov r9, [rsp + 8]",
        // The restorer's `rt_sigreturn` comes here too (see `restorer`).
        ".globl exobox_rt_gate_syscall",
        ".hidden exobox_rt_gate_syscall",
        "exobox_rt_gate_syscall:",
        "syscall",
        // What the kernel reports as the instruction pointer: the filter's `gate_ip`. A thread made
        // by `clone_thread` starts here too, on its new stack (see there).
        ".globl exobox_rt_gate_ret",
        ".hidden exobox_rt_gate_ret",
        "exobox_rt_gate_ret:",
        "ret",
    )
}

unsafe extern "C" {
    static exobox_rt_gate_ret: u8;
}

/// The address just past the gate's `syscall`: `filter::Params::gate_ip`.
pub fn gate_ip() -> u64 {
    &raw const exobox_rt_gate_ret as u64
}

/// A raw result as `Result`: -4095..-1 is an errno (the kernel's convention).
fn check(r: isize) -> Result<usize, Errno> {
    if (-4095..0).contains(&r) { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
}

// The typed wrappers: exactly the calls the filter allows from the gate, shaped so their
// arguments satisfy its pinned conditions (`filter::HOST` says what each is for).

/// `write(fd, buf)`: fd 1 or 2 (the program's stdout and stderr), or a CPU-token eventfd.
pub fn write(fd: u32, buf: &[u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel reads `buf`, which is borrowed for the call.
    check(unsafe { gate(NR_WRITE as usize, fd as usize, buf.as_ptr() as usize, buf.len(), 0, 0, 0) })
}

/// `read(fd, buf)`: fd 0 (the program's stdin), or a CPU-token eventfd.
pub fn read(fd: u32, buf: &mut [u8]) -> Result<usize, Errno> {
    // SAFETY: the kernel writes at most `buf.len()` bytes into `buf`, borrowed mutably.
    check(unsafe {
        gate(NR_READ as usize, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0)
    })
}

/// `struct pollfd`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}

/// `ppoll` on at most one fd, no signal mask (the filter pins both; [`ppoll_fds`] for more).
/// `timeout` `None` waits forever. Returns how many fds are ready (0 on timeout).
pub fn ppoll(fd: Option<&mut PollFd>, timeout: Option<&Timespec>) -> Result<usize, Errno> {
    let (fds, n) = match fd {
        Some(p) => (p as *mut PollFd as usize, 1),
        None => (0, 0),
    };
    let ts = timeout.map_or(0, |t| t as *const Timespec as usize);
    // SAFETY: the kernel reads the timespec and reads/writes the one pollfd, both borrowed.
    // sigsetsize 8 is the kernel's sigset_t, though with no mask it isn't read.
    check(unsafe { gate(NR_PPOLL as usize, fds, n, ts, 0, 8, 0) })
}

/// `ppoll` on up to [`crate::filter::PPOLL_FDS`] fds at once, no signal mask (the filter pins
/// both): the idle wait over the fds coroutines and the hooks' executor wait on. `timeout` `None`
/// waits forever. Returns how many are ready, each one's `revents` set.
pub fn ppoll_fds(fds: &mut [PollFd], timeout: Option<&Timespec>) -> Result<usize, Errno> {
    let n = fds.len().min(crate::filter::PPOLL_FDS as usize);
    let p = if n == 0 { 0 } else { fds.as_mut_ptr() as usize };
    let ts = timeout.map_or(0, |t| t as *const Timespec as usize);
    // SAFETY: the kernel reads the timespec and reads/writes the n pollfds, all borrowed.
    check(unsafe { gate(NR_PPOLL as usize, p, n, ts, 0, 8, 0) })
}

/// `exit_group(status)`: the end of the sandbox.
pub fn exit_group(status: i32) -> ! {
    // SAFETY: ends the process; nothing after it runs.
    unsafe { gate(NR_EXIT_GROUP as usize, status as usize, 0, 0, 0, 0, 0) };
    // Only if the filter denied it (deny=errno with a broken list): never return into the caller.
    loop {
        core::hint::spin_loop()
    }
}

/// `exit(0)`: the calling host thread's end (threaded and fork mode; the filter allows status 0
/// only). Its `clone_thread` tid word is cleared and futex-woken by the kernel.
///
/// # Safety
/// Nothing still needs this thread's stack: another thread may reuse it once the tid word is 0.
pub unsafe fn exit_thread() -> ! {
    // SAFETY: the caller's.
    unsafe { gate(NR_EXIT as usize, 0, 0, 0, 0, 0, 0) };
    loop {
        core::hint::spin_loop()
    }
}

/// A new host thread (`clone` with [`CLONE_HOST_THREAD`], the only flags the filter allows) that
/// runs `entry(arg)` on the stack below `run_top`, with `[alt, alt + alt_len)` installed as its
/// own alternate signal stack. Returns its tid. The kernel writes 0 to `*ctid` (and futex-wakes
/// it) when the thread exits, so set it nonzero first to tell.
///
/// The new thread has no alternate signal stack (the kernel clears it for a `CLONE_VM` child,
/// `sas_ss_reset` in copy_process), and `sigaltstack` is not in the filter: a trap delivered on
/// its ordinary stack would overrun it (Go's ~128-byte spare). The way capnix settled it (tier A,
/// `27955f1c`), with no filter entry: the child returns from the gate's `syscall` on a stack
/// whose first word is the SIGSYS restorer, so the gate's `ret` lands in `rt_sigreturn` on a frame
/// built from the trapping `clone`'s own ucontext (`tmpl`). `rt_sigreturn` (from the gate) restores that frame, installing the alternate stack (`restore_altstack`) and resuming at
/// `entry(arg)` with the program's signal mask.
///
/// # Safety
/// `run_top` is the top of writable memory only this thread will use (room for the frame built
/// here plus what `entry` uses); `alt` is this thread's alone; `ctid` stays valid until the thread
/// has exited; `tmpl` is a valid ucontext (the trapping clone's); `entry` never returns.
pub unsafe fn clone_thread(
    run_top: usize,
    alt: usize,
    alt_len: usize,
    ctid: *mut u32,
    tmpl: &Ucontext,
    entry: extern "C" fn(usize) -> !,
    arg: usize,
) -> Result<u32, Errno> {
    // The rt_sigframe the child `ret`s onto: pretcode (the restorer) then the ucontext, 16-aligned
    // so the restored rsp (below) is clean; room for `entry`'s frame below it.
    let frame = ((run_top - 8 - size_of::<Ucontext>()) & !63) - 8;
    // SAFETY: inside the caller-provided stack.
    unsafe { (frame as *mut usize).write(restorer as *const () as usize) };
    let uc = frame + 8;
    let mut u = *tmpl;
    u.link = 0;
    u.stack = StackT { sp: alt, flags: 0, size: alt_len };
    u.mcontext.rip = entry as *const () as u64;
    u.mcontext.rdi = arg as u64;
    // As if `call`ed: a fresh stack below the frame, 16-aligned then one word down.
    u.mcontext.rsp = (((frame - 256) & !15) - 8) as u64;
    u.mcontext.rbp = 0;
    u.mcontext.fpregs = 0; // the FPU starts in its initial state
    // SAFETY: `uc` is inside the stack, aligned for a Ucontext.
    unsafe { (uc as *mut Ucontext).write(u) };
    // x86-64 clone: (flags, newsp, parent_tid, child_tid, tls). The child starts at the gate's
    // `ret`, which pops the restorer at `frame`.
    // SAFETY: the caller's contract; the child runs only from the prepared frame.
    let r = unsafe { gate(NR_CLONE as usize, CLONE_HOST_THREAD as usize, frame, 0, ctid as usize, 0, 0) };
    check(r).map(|tid| tid as u32)
}

/// Host code's `clone` with a new stack, re-issued from the gate (`passthrough`): the child must
/// resume the trapped context, not the dispatcher's, so it starts as `clone_thread`'s does, from a
/// `rt_sigreturn` frame built below `newsp` (free memory: a clone's stack data sits at and above
/// it) from the trapping call's own ucontext, with `rax` 0 and `rsp` `newsp`. `altstack` is what
/// the child's alternate stack becomes (Linux resets it for a `CLONE_VM` child that isn't a
/// vfork's). The FPU starts in its initial state. Returns the raw result (the parent's).
///
/// # Safety
/// `newsp` is the top of a stack the child may use, with a few hundred bytes free below it; the
/// flags and the other arguments are the trapping call's (a raw `clone`).
pub unsafe fn clone_resume(flags: usize, newsp: usize, ptid: usize, ctid: usize, tls: usize, tmpl: &Ucontext, altstack: StackT) -> isize {
    let frame = ((newsp - 8 - size_of::<Ucontext>()) & !63) - 8;
    // SAFETY: below the child's stack top: the caller's.
    unsafe { (frame as *mut usize).write(restorer as *const () as usize) };
    let mut u = *tmpl;
    u.link = 0;
    u.stack = altstack;
    u.mcontext.rax = 0;
    u.mcontext.rsp = newsp as u64;
    u.mcontext.fpregs = 0;
    // SAFETY: inside the child's stack, aligned for a Ucontext.
    unsafe { ((frame + 8) as *mut Ucontext).write(u) };
    // SAFETY: the caller's; the child runs only from the prepared frame.
    unsafe { gate(NR_CLONE as usize, flags, frame, ptid, ctid, tls, 0) }
}

/// Return from a signal handler of host code's (`passthrough`): its `rt_sigreturn` trapped, so
/// it is made again here from the gate, at the trapped `rsp` (the frame is at `rsp - 8`, where the
/// kernel looks), with the FS base the handler ran with (`rt_sigreturn` doesn't restore it). The
/// SIGSYS frame that brought us here is abandoned: the restored frame is the whole state.
///
/// # Safety
/// `rsp` and `fs` are a trapped `rt_sigreturn`'s.
#[unsafe(naked)]
pub unsafe extern "C" fn sigreturn_at(rsp: usize, fs: usize) -> ! {
    core::arch::naked_asm!("wrfsbase rsi", "mov rsp, rdi", "mov eax, 15", "jmp exobox_rt_gate_syscall", "ud2")
}

/// Wait for an eventfd's count (a CPU token): `read` of its 8 bytes, which blocks while it is 0.
pub fn eventfd_read(fd: u32) -> Result<u64, Errno> {
    let mut v = [0u8; 8];
    read(fd, &mut v)?;
    Ok(u64::from_ne_bytes(v))
}

/// Add `v` to an eventfd's count (hand over a CPU token).
pub fn eventfd_write(fd: u32, v: u64) -> Result<(), Errno> {
    write(fd, &v.to_ne_bytes()).map(|_| ())
}

// ------------------------------------------------------------------------------------------------
// The frame's types: the kernel's x86-64 layouts (arch/x86/include/uapi/asm/sigcontext.h,
// include/uapi/asm-generic/ucontext.h, siginfo.h), not glibc's larger `ucontext_t`.

/// `stack_t`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct StackT {
    pub sp: usize,
    pub flags: i32,
    pub size: usize,
}

/// `struct sigcontext` (64-bit), the ucontext's `uc_mcontext`: the registers at the trap.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Mcontext {
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub rdx: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rsp: u64,
    pub rip: u64,
    pub eflags: u64,
    /// cs, gs, fs, ss selectors (16 bits each).
    pub csgsfs: u64,
    pub err: u64,
    pub trapno: u64,
    pub oldmask: u64,
    pub cr2: u64,
    /// The xsave area (`struct _fpstate` plus extensions), 64-aligned; 0 if the frame has none.
    pub fpregs: usize,
    /// The program's FS base, kept here by the entry and loaded again on the way out (set it to
    /// change the FS the program resumes with). The kernel's `reserved1[0]`: it neither writes
    /// it on delivery nor reads it on `rt_sigreturn` (`restore_sigcontext` copies only up to
    /// `reserved1`, arch/x86/kernel/signal_64.c), so the slot is ours.
    pub fs_base: u64,
    pub reserved: [u64; 7],
}

/// The kernel's `struct ucontext` (304 bytes; glibc's `ucontext_t` is the same up to
/// `uc_sigmask` and longer after: a 128-byte mask and its own fpregs copy).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ucontext {
    pub flags: u64,
    pub link: usize,
    pub stack: StackT,
    pub mcontext: Mcontext,
    pub sigmask: u64,
}

/// `siginfo_t` (128 bytes) with SIGSYS's fields (`_sigsys`) named.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Siginfo {
    pub signo: i32,
    pub errno: i32,
    pub code: i32,
    _pad: i32,
    /// The address past the trapping `syscall`.
    pub call_addr: u64,
    pub syscall: i32,
    pub arch: u32,
    _rest: [u64; 12],
}

const _: () = {
    assert!(size_of::<StackT>() == 24);
    assert!(size_of::<Mcontext>() == 256);
    assert!(size_of::<Ucontext>() == 304);
    assert!(size_of::<Siginfo>() == 128);
};

impl Ucontext {
    /// The trapped syscall: its number (`rax`) and arguments (rdi, rsi, rdx, r10, r8, r9).
    pub fn syscall(&self) -> (usize, [usize; 6]) {
        let m = &self.mcontext;
        let a = [m.rdi, m.rsi, m.rdx, m.r10, m.r8, m.r9];
        (m.rax as usize, a.map(|v| v as usize))
    }

    /// The trapped syscall's result, as the program will see it in `rax`.
    pub fn set_return(&mut self, v: isize) {
        self.mcontext.rax = v as u64;
    }

    /// The siginfo of the frame this ucontext is in.
    ///
    /// # Safety
    /// `self` is a frame's ucontext as delivered (or moved) by the kernel: in `struct rt_sigframe`
    /// the siginfo follows it.
    pub unsafe fn siginfo(&self) -> &Siginfo {
        // SAFETY: the caller's.
        unsafe { &*((self as *const Ucontext).add(1) as *const Siginfo) }
    }
}

// ------------------------------------------------------------------------------------------------
// Installing.

/// The dispatcher: serves the trapped syscall in the frame (see the module comment).
pub type Dispatch = fn(&mut Ucontext);

/// The target-stack hook: given the trap's frame (still on the alternate stack), the address the
/// moved frame should end below (exclusive, any alignment), or 0 to leave it where it is.
///
/// It runs on the alternate stack before the frame is moved, with the runtime's FS. It must not
/// make a syscall (it would trap, and land on the same alternate stack), suspend, or use more than
/// a few KiB of stack. The address it returns must have room below it for the frame (a few KiB:
/// [`frame_size`] plus 64), all of it free: in production, the trapping coroutine's control stack
/// top when the program trapped on its own stack (nothing of the runtime's is live there while
/// the program runs), and [`below_red_zone`] when the trap came from runtime code already on a
/// runtime stack (the frame then goes below its live data, as a native signal's would). If the
/// runtime ever runs program code (a signal handler) while a dispatch is suspended on the control
/// stack, the hook must return a top below that dispatch's frame.
///
/// 0 keeps the frame on the alternate stack: only safe if the dispatcher won't suspend.
pub type Target = fn(&Ucontext) -> usize;

/// The alternate stack each host thread needs ([`set_altstack`]): the frame (up to ~11 KiB with
/// AMX's xsave state) plus the target hook's stack.
pub const ALTSTACK_SIZE: usize = 64 * 1024;

/// Below the trap's sp, past the 128-byte red zone: [`Target`]'s answer for a trap from code on a
/// runtime stack.
pub fn below_red_zone(uc: &Ucontext) -> usize {
    uc.mcontext.rsp as usize - 128
}

static DISPATCH: AtomicUsize = AtomicUsize::new(0);
static TARGET: AtomicUsize = AtomicUsize::new(0);
/// The runtime's FS base, which the entry loads (read by the asm: an `AtomicUsize` is a `usize`).
static RUNTIME_FS: AtomicUsize = AtomicUsize::new(0);

// x86-64 signal numbers and flags (arch/x86/include/uapi/asm/signal.h, asm-generic/signal-defs.h).
const SIGBUS: usize = 7;
const SIGSEGV: usize = 11;
const SIGPIPE: usize = 13;
const SIGSYS: usize = 31;
const SA_SIGINFO: u64 = 0x4;
const SA_ONSTACK: u64 = 0x0800_0000;
const SA_NODEFER: u64 = 0x4000_0000;
const SIG_DFL: usize = 0;
const SIG_IGN: usize = 1;
const NR_RT_SIGACTION: usize = 13;
const NR_SIGALTSTACK: usize = 131;

/// Install the SIGSYS handler for the process (all its threads share it), with `dispatch` and
/// `target`, and capture the calling thread's FS base as the runtime's (every trap switches to
/// it). Also ignores SIGPIPE on the host: a write to a closed stdout pipe must come back as
/// `EPIPE` for the guest to handle, not kill the sandbox (the program's SIGPIPE is the guest
/// kernel's to deliver). And resets SIGSEGV and SIGBUS to their default (std's stack-overflow
/// handlers): a fault dies of its signal at once, and so does the sandbox when the guest's
/// process died of one (`guest`'s `die` sends it to itself); a handler of the host's would return
/// through libc's restorer, whose `rt_sigreturn` now traps.
///
/// Before lockdown (it makes host calls the filter doesn't allow). Each host thread also needs
/// [`set_altstack`].
///
/// # Safety
/// From then on SIGSYS runs the entry: the caller is ready for that (a SIGSYS before lockdown is
/// dispatched too). `dispatch` and `target` keep to their contracts.
pub unsafe fn install(dispatch: Dispatch, target: Target) -> Result<(), Errno> {
    DISPATCH.store(dispatch as usize, Ordering::Release);
    TARGET.store(target as usize, Ordering::Release);
    RUNTIME_FS.store(crate::context::read_fs(), Ordering::Release);
    let sys = X86Sigaction {
        handler: sigsys_entry as *const () as usize,
        flags: SA_SIGINFO | SA_ONSTACK | SA_NODEFER | SA_RESTORER,
        restorer: restorer as *const () as usize,
        mask: 0,
    };
    let pipe = X86Sigaction { handler: SIG_IGN, ..X86Sigaction::default() };
    let dfl = X86Sigaction { handler: SIG_DFL, ..X86Sigaction::default() };
    for (sig, act) in [(SIGSYS, &sys), (SIGPIPE, &pipe), (SIGSEGV, &dfl), (SIGBUS, &dfl)] {
        // Through the gate, which before lockdown is a plain syscall: rustix's rt_sigaction is
        // behind its unstable `runtime` feature. sigsetsize 8: the kernel's sigset_t.
        // SAFETY: the kernel reads `act` during the call.
        check(unsafe { gate(NR_RT_SIGACTION, sig, act as *const _ as usize, 0, 8, 0, 0) })?;
    }
    Ok(())
}

/// A host signal handler of the runtime's for `sig` (fork mode's SIGCHLD): `handler(sig, info,
/// uc)` on the thread's alternate stack, returning through the runtime's restorer (the gate's
/// `rt_sigreturn`), with `SA_RESTART` (an interrupted blocking read goes on) and `flags` more.
/// Before lockdown.
///
/// # Safety
/// `handler` is safe to run on any host thread at any point: it makes only gate calls and touches
/// no TLS.
pub unsafe fn install_handler(sig: usize, handler: unsafe extern "C" fn(i32, *mut Siginfo, *mut Ucontext), flags: u64) -> Result<(), Errno> {
    const SA_RESTART: u64 = 0x1000_0000;
    let act = X86Sigaction {
        handler: handler as *const () as usize,
        flags: SA_SIGINFO | SA_ONSTACK | SA_RESTORER | SA_RESTART | flags,
        restorer: restorer as *const () as usize,
        mask: 0,
    };
    // SAFETY: the kernel reads `act` during the call.
    check(unsafe { gate(NR_RT_SIGACTION, sig, &act as *const _ as usize, 0, 8, 0, 0) }).map(|_| ())
}

/// Make `base..base + len` the calling host thread's alternate signal stack (`sigaltstack`), where
/// SIGSYS is delivered. Once per host thread, before lockdown (or before the thread's first trap,
/// while `sigaltstack` is still allowed). [`ALTSTACK_SIZE`] is the size to use.
///
/// # Safety
/// The memory is writable and stays this thread's alone while it can take signals.
pub unsafe fn set_altstack(base: *mut u8, len: usize) -> Result<(), Errno> {
    let ss = StackT { sp: base as usize, flags: 0, size: len };
    // SAFETY: the kernel reads `ss` during the call.
    check(unsafe { gate(NR_SIGALTSTACK, &ss as *const StackT as usize, 0, 0, 0, 0, 0) }).map(|_| ())
}

/// Bytes from a delivered frame's start to its alternate stack's top: what the entry copies.
/// (For sizing a [`Target`]'s room; the hook sees the same ucontext.)
pub fn frame_size(uc: &Ucontext) -> usize {
    let uc_at = uc as *const Ucontext as usize;
    // The frame starts at the return address, 8 bytes below the ucontext (`struct rt_sigframe`).
    uc.stack.sp + uc.stack.size - (uc_at - 8)
}

// ------------------------------------------------------------------------------------------------
// The entry and exit.

/// Where a handler returns to: `rt_sigreturn`, made from the gate's `syscall` instruction, the
/// only place the filter allows it from (anywhere else it traps: the program's own `rt_sigreturn`
/// returns from a handler the runtime ran, and is the runtime's to serve). It reads the frame at
/// sp - 8, i.e. the (moved) frame whose return address the entry's `ret` just popped.
#[unsafe(naked)]
unsafe extern "C" fn restorer() -> ! {
    core::arch::naked_asm!("mov eax, 15", "jmp exobox_rt_gate_syscall", "ud2")
}

/// The SIGSYS handler as installed. The kernel enters with rdi = signo, rsi = &siginfo,
/// rdx = &ucontext, and rsp at the frame's start (its return address, the restorer), rsp % 16 == 8.
/// Everything the program had is in the frame, so every register is free to use here.
#[unsafe(naked)]
unsafe extern "C" fn sigsys_entry() {
    core::arch::naked_asm!(
        // rbx: the frame as delivered; r12: its ucontext; r13: the program's FS base. All three
        // are callee-saved, so they survive the calls below.
        "mov rbx, rsp",
        "mov r12, rdx",
        "rdfsbase r13",
        "mov rax, qword ptr [rip + {fs}]",
        "wrfsbase rax",
        // Below the frame on the stack it was delivered on, 16-aligned for the call.
        "and rsp, -16",
        "mov rdi, rbx",
        "mov rsi, r12",
        "call {relocate}",
        // rax: where the frame starts now. The ucontext moved by as much.
        "sub r12, rbx",
        "add r12, rax",
        "mov rsp, rax",
        "mov qword ptr [r12 + {fs_base}], r13",
        // rsp is the frame's start, % 16 == 8 as delivered: one slot down aligns it for the call.
        "sub rsp, 8",
        "mov rdi, r12",
        "call {dispatch}",
        "add rsp, 8",
        // The FS the program resumes with (the dispatcher may have changed it), then `ret` to the
        // restorer with rsp just past the return address, where `rt_sigreturn` expects the frame.
        "mov rax, qword ptr [r12 + {fs_base}]",
        "wrfsbase rax",
        "ret",
        fs = sym RUNTIME_FS,
        relocate = sym relocate,
        dispatch = sym dispatch,
        fs_base = const offset_of!(Ucontext, mcontext) + offset_of!(Mcontext, fs_base),
    )
}

/// Move the frame `entry..` (its ucontext at `uc`) off the alternate stack to below the target
/// hook's address, returning its new start (or `entry`, unmoved). Runs on the alternate stack:
/// no syscalls, no suspension.
unsafe extern "C" fn relocate(entry: usize, uc: *mut Ucontext) -> usize {
    // SAFETY: the kernel's frame.
    let u = unsafe { &*uc };
    let (lo, hi) = (u.stack.sp, u.stack.sp + u.stack.size);
    let sp = u.mcontext.rsp as usize;
    // Not delivered on the alternate stack (the thread has none), or the trap came from code that
    // was already on it (a frame below a live one: moving only this one is fine, but moving
    // `entry..hi` would take the live one along). Either way: leave it, the stack is not shared.
    if u.stack.size == 0 || !(lo..hi).contains(&entry) || (lo..hi).contains(&sp) {
        return entry;
    }
    // SAFETY: TARGET was stored by `install` from a `Target` before SIGSYS could run this.
    let target: Target = unsafe { core::mem::transmute(TARGET.load(Ordering::Acquire)) };
    let top = target(u);
    if top == 0 {
        return entry;
    }
    let n = hi - entry;
    // The same offset modulo 64 as delivered (xrstor's alignment), ending at or below `top`.
    let mut dst = ((top - n) & !63) | (entry & 63);
    if dst + n > top {
        dst -= 64;
    }
    // SAFETY: the hook vouched for dst..dst + n; `copy` in case it overlaps the frame (it
    // shouldn't).
    unsafe { core::ptr::copy(entry as *const u8, dst as *mut u8, n) };
    let delta = dst.wrapping_sub(entry);
    // SAFETY: the copy's ucontext.
    let moved = unsafe { &mut *((uc as usize).wrapping_add(delta) as *mut Ucontext) };
    if moved.mcontext.fpregs != 0 {
        moved.mcontext.fpregs = moved.mcontext.fpregs.wrapping_add(delta);
    }
    dst
}

/// The registered dispatcher, called from the entry (a Rust `fn` can't be called from asm).
unsafe extern "C" fn dispatch(uc: *mut Ucontext) {
    // SAFETY: DISPATCH was stored by `install` from a `Dispatch`.
    let d: Dispatch = unsafe { core::mem::transmute(DISPATCH.load(Ordering::Acquire)) };
    // SAFETY: the (moved) frame's ucontext, ours until the entry returns.
    d(unsafe { &mut *uc })
}

#[cfg(test)]
mod tests;
