//! Passthrough: host code's syscalls, trapped by the routing filter while no intercept guard is
//! alive (exobox's `Sandbox::intercept`), re-issued on the host through the gate (which the
//! routing filter allows everything from). Seccomp filters can't be removed, so after the first
//! guard every syscall of the process's routed threads traps; this makes the host code between
//! guards (and other threads' code while one is alive) behave as it would unrouted, until `run`.
//!
//! Most calls are re-issued as they are, from the dispatcher, and their raw result (`-errno`
//! included) is the trapped call's. What can't be, because the call's effect is on the state the
//! SIGSYS handler's own `rt_sigreturn` puts back (the registers, the signal mask, the alternate
//! stack, the FS base), or because it must continue from the trapping instruction rather than the
//! gate:
//!
//! - **`rt_sigreturn`**: a host signal handler's return (libc's restorer is not the gate). Made
//!   again from the gate at the trapped `rsp` ([`trap::sigreturn_at`]), abandoning the SIGSYS
//!   frame: the handler's frame is the whole state to return to.
//! - **`rt_sigprocmask`**: applied to the mask the SIGSYS frame restores (`uc_sigmask`), not the
//!   host's current one, which the handler's return would overwrite. SIGSYS itself is never
//!   blocked (the next trapped call would kill the process: a seccomp trap with SIGSYS blocked
//!   isn't deferred); the old mask reports it unblocked.
//! - **`sigaltstack`**: applied to the alternate stack the frame restores (`uc_stack`), with
//!   Linux's checks (EPERM on it, ENOMEM under `MINSIGSTKSZ`, EINVAL for unknown flags).
//! - **`arch_prctl(ARCH_SET_FS / ARCH_GET_FS)`**: the FS base the entry loads on the way out.
//! - **`rt_sigaction(SIGSYS, act)`**: EINVAL. SIGSYS is how routing works; a host handler for it
//!   would take every trap. Reading the action is re-issued.
//! - **`clone`**: without a new stack and without `CLONE_VM` (a fork: glibc's `fork()`) it is
//!   re-issued, and the child, a copy, returns from the dispatcher as the parent does, with 0.
//!   With a new stack (a thread, `posix_spawn`'s child) the child can't continue in the
//!   dispatcher on another stack: it starts from a frame of the trapped context
//!   ([`trap::clone_resume`]), `rax` 0, on its own stack, with the trapping thread's FS base
//!   (`CLONE_SETTLS` with it, unless the call set its own). A `CLONE_VM | CLONE_VFORK` child with
//!   no stack of its own (a vfork) would run on the parent's stack, over the dispatcher's frames:
//!   it is made without `CLONE_VM` (a copy, the parent still suspended until it execs or exits).
//!   `CLONE_VM` with no stack and no `CLONE_VFORK` (two threads on one stack) is EINVAL.
//! - **`vfork`**: as `clone(CLONE_VFORK | SIGCHLD)`, for the same reason.
//! - **`clone3`**: ENOSYS (its stack is in a struct; glibc and musl fall back to `clone`).
//! - **`execve`, `execveat`**: EPERM. The filters survive exec: the new program's syscalls would
//!   trap into a process with no handler, which kills it. Host programs are started before the
//!   first guard (or by a process that never made one).
//! - **`exit`, `exit_group`**: re-issued; they don't return.
//!
//! Signals arriving meanwhile are the host's (host code has its own handlers); one that
//! interrupts a re-issued call restarts it from the gate or fails it with EINTR, as Linux does.
//!
//! What can't be exact: a bad pointer to `rt_sigprocmask` or `sigaltstack` is EFAULT through
//! `process_vm_readv` on ourselves, as the kernel would; the FPU state of a clone's child starts
//! fresh (its registers are the parent's, as Linux's). The dispatcher runs with the runtime's FS
//! base, which is the boot thread's: nothing here touches thread-local storage, so it serves any
//! thread.

use crate::trap::{self, StackT, Ucontext};

const NR_RT_SIGACTION: usize = 13;
const NR_RT_SIGPROCMASK: usize = 14;
const NR_RT_SIGRETURN: usize = 15;
const NR_GETPID: usize = 39;
const NR_CLONE: usize = 56;
const NR_VFORK: usize = 58;
const NR_EXECVE: usize = 59;
const NR_SIGALTSTACK: usize = 131;
const NR_ARCH_PRCTL: usize = 158;
const NR_PROCESS_VM_READV: usize = 310;
const NR_PROCESS_VM_WRITEV: usize = 311;
const NR_EXECVEAT: usize = 322;
const NR_CLONE3: usize = 435;

const EPERM: isize = 1;
const ENOMEM: isize = 12;
const EFAULT: isize = 14;
const EINVAL: isize = 22;
const ENOSYS: isize = 38;

const SIGSYS: usize = 31;
const CLONE_VM: usize = 0x100;
const CLONE_VFORK: usize = 0x4000;
const CLONE_SETTLS: usize = 0x8_0000;
const SIGCHLD: usize = 17;
const SS_ONSTACK: i32 = 1;
const SS_DISABLE: i32 = 2;
const SS_AUTODISARM: i32 = 1 << 31;
/// x86-64's `MINSIGSTKSZ`, the floor sigaltstack checks a size against.
const MINSIGSTKSZ: usize = 2048;
const ARCH_SET_FS: usize = 0x1002;
const ARCH_GET_FS: usize = 0x1003;

fn gate(nr: usize, a: [usize; 6]) -> isize {
    // SAFETY: the trapped call, as host code made it; the routing filter allows it from the gate.
    unsafe { trap::gate(nr, a[0], a[1], a[2], a[3], a[4], a[5]) }
}

#[repr(C)]
struct Iovec {
    base: usize,
    len: usize,
}

/// `len` bytes between `local` and the process's own address `remote` (to it, with `write`), by
/// `process_vm_readv`/`writev` on ourselves: EFAULT for a bad `remote`, as a syscall's copy.
fn copy(local: usize, remote: usize, len: usize, write: bool) -> Result<(), isize> {
    // SAFETY: getpid.
    let pid = unsafe { trap::gate(NR_GETPID, 0, 0, 0, 0, 0, 0) } as usize;
    let l = Iovec { base: local, len };
    let r = Iovec { base: remote, len };
    let nr = if write { NR_PROCESS_VM_WRITEV } else { NR_PROCESS_VM_READV };
    let n = gate(nr, [pid, &l as *const Iovec as usize, 1, &r as *const Iovec as usize, 1, 0]);
    if n == len as isize { Ok(()) } else { Err(-EFAULT) }
}

fn read<T: Copy + Default>(p: usize) -> Result<T, isize> {
    let mut v = T::default();
    copy(&mut v as *mut T as usize, p, size_of::<T>(), false)?;
    Ok(v)
}

fn write<T: Copy>(p: usize, v: T) -> Result<(), isize> {
    copy(&v as *const T as usize, p, size_of::<T>(), true)
}

/// Serve a trapped host syscall on the host (see the module comment).
pub fn serve(uc: &mut Ucontext) {
    let (nr, a) = uc.syscall();
    let r = match nr {
        NR_RT_SIGRETURN => {
            // SAFETY: a trapped rt_sigreturn: its frame is at rsp - 8.
            unsafe { trap::sigreturn_at(uc.mcontext.rsp as usize, uc.mcontext.fs_base as usize) }
        }
        NR_RT_SIGPROCMASK => sigprocmask(uc, a).unwrap_or_else(|e| e),
        NR_SIGALTSTACK => sigaltstack(uc, a).unwrap_or_else(|e| e),
        NR_ARCH_PRCTL if a[0] == ARCH_SET_FS => {
            uc.mcontext.fs_base = a[1] as u64;
            0
        }
        NR_ARCH_PRCTL if a[0] == ARCH_GET_FS => write(a[1], uc.mcontext.fs_base).map_or_else(|e| e, |_| 0),
        NR_RT_SIGACTION if a[0] == SIGSYS && a[1] != 0 => -EINVAL,
        NR_CLONE => clone(uc, a),
        NR_VFORK => gate(NR_CLONE, [CLONE_VFORK | SIGCHLD, 0, 0, 0, 0, 0]),
        NR_CLONE3 => -ENOSYS,
        NR_EXECVE | NR_EXECVEAT => -EPERM,
        _ => gate(nr, a),
    };
    uc.set_return(r);
}

fn sigprocmask(uc: &mut Ucontext, a: [usize; 6]) -> Result<isize, isize> {
    let (how, set, old, size) = (a[0], a[1], a[2], a[3]);
    if size != 8 {
        return Err(-EINVAL);
    }
    let sigsys = 1u64 << (SIGSYS - 1);
    let cur = uc.sigmask;
    if set != 0 {
        let s: u64 = read(set)?;
        let new = match how {
            0 => cur | s,  // SIG_BLOCK
            1 => cur & !s, // SIG_UNBLOCK
            2 => s,        // SIG_SETMASK
            _ => return Err(-EINVAL),
        };
        // SIGKILL and SIGSTOP can't be blocked; SIGSYS mustn't be (module comment).
        let never = (1u64 << 8) | (1u64 << 18) | sigsys;
        if old != 0 {
            write(old, cur & !sigsys)?;
        }
        uc.sigmask = new & !never;
    } else if old != 0 {
        write(old, cur & !sigsys)?;
    }
    Ok(0)
}

fn sigaltstack(uc: &mut Ucontext, a: [usize; 6]) -> Result<isize, isize> {
    let (ss, oss) = (a[0], a[1]);
    let cur = uc.stack;
    let sp = uc.mcontext.rsp as usize;
    // As the kernel's sas_ss_flags: SS_DISABLE with none, SS_ONSTACK on it, plus autodisarm.
    let on = cur.size != 0 && sp > cur.sp && sp - cur.sp <= cur.size;
    let flags = if cur.size == 0 { SS_DISABLE } else if on { SS_ONSTACK } else { 0 } | (cur.flags & SS_AUTODISARM);
    let new = if ss != 0 {
        let n: StackT = read(ss)?;
        if on {
            return Err(-EPERM);
        }
        let mode = n.flags & !SS_AUTODISARM;
        if mode != 0 && mode != SS_DISABLE && mode != SS_ONSTACK {
            return Err(-EINVAL);
        }
        Some(if mode == SS_DISABLE {
            StackT { sp: 0, flags: SS_DISABLE, size: 0 }
        } else {
            if n.size < MINSIGSTKSZ {
                return Err(-ENOMEM);
            }
            StackT { sp: n.sp, flags: n.flags & SS_AUTODISARM, size: n.size }
        })
    } else {
        None
    };
    if oss != 0 {
        write(oss, StackT { sp: cur.sp, flags, size: cur.size })?;
    }
    if let Some(n) = new {
        uc.stack = n;
    }
    Ok(0)
}

fn clone(uc: &mut Ucontext, a: [usize; 6]) -> isize {
    let (mut flags, newsp, ptid, ctid, mut tls) = (a[0], a[1], a[2], a[3], a[4]);
    if newsp == 0 {
        if flags & CLONE_VM == 0 {
            return gate(NR_CLONE, a);
        }
        if flags & CLONE_VFORK == 0 {
            return -EINVAL;
        }
        return gate(NR_CLONE, [flags & !CLONE_VM, 0, ptid, ctid, tls, 0]);
    }
    if flags & CLONE_SETTLS == 0 {
        flags |= CLONE_SETTLS;
        tls = uc.mcontext.fs_base as usize;
    }
    let alt = if flags & CLONE_VM != 0 && flags & CLONE_VFORK == 0 {
        StackT { sp: 0, flags: SS_DISABLE, size: 0 }
    } else {
        uc.stack
    };
    // SAFETY: the trapped clone's own arguments; its new stack is the child's.
    unsafe { trap::clone_resume(flags, newsp, ptid, ctid, tls, uc, alt) }
}
