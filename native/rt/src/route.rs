//! The routing filter: which syscalls are the runtime's own (made from the gate, `trap::gate`) and
//! which are the program's (trapped, `SECCOMP_RET_TRAP`, and served in-process).
//!
//! **Not part of the TCB.** It decides where a call is served, not whether the host may make it:
//! it allows everything from the gate. Isolation is exobox's security filter (its `tcb`), stacked
//! on this one at lockdown. The kernel runs every installed filter and takes the strictest
//! answer, so a filter under the security filter can only take away: a bug here misroutes calls
//! (the program's served on the host, which the security filter then refuses, or the runtime's
//! trapped), it never lets the host make a call the security filter refuses. The security filter
//! makes its own gate test, which returns only TRAP or KILL, so it doesn't depend on this one.
//!
//! The program, thirteen instructions:
//! 1. arch is not x86-64, or the x32 bit is set: kill (a filter that only knows x86-64 numbers
//!    must not judge another ABI's);
//! 2. not from the gate (either half of the instruction pointer differs from [`trap::gate_ip`]):
//!    trap. The program's `rt_sigreturn` too: it returns from a handler the runtime ran;
//! 3. from the gate: allow.

use rustix::io::Errno;

use crate::trap;

/// One classic-BPF instruction (`struct sock_filter`, include/uapi/linux/filter.h).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SockFilter {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

const LD_W_ABS: u16 = 0x20;
const JEQ_K: u16 = 0x15;
const JGE_K: u16 = 0x35;
const RET_K: u16 = 0x06;
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;
const X32_SYSCALL_BIT: u32 = 0x4000_0000;
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_TRAP: u32 = 0x0003_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const NR_PRCTL: usize = 157;
const NR_SECCOMP: usize = 317;

/// The routing program for a gate whose `syscall` returns to `gate_ip`.
pub fn program(gate_ip: u64) -> [SockFilter; 13] {
    let i = |code, jt, jf, k| SockFilter { code, jt, jf, k };
    [
        i(LD_W_ABS, 0, 0, 4), // arch
        i(JEQ_K, 1, 0, AUDIT_ARCH_X86_64),
        i(RET_K, 0, 0, RET_KILL_PROCESS),
        i(LD_W_ABS, 0, 0, 0), // nr
        i(JGE_K, 0, 1, X32_SYSCALL_BIT),
        i(RET_K, 0, 0, RET_KILL_PROCESS),
        i(LD_W_ABS, 0, 0, 8), // instruction_pointer, low half
        i(JEQ_K, 1, 0, gate_ip as u32),
        i(RET_K, 0, 0, RET_TRAP),
        i(LD_W_ABS, 0, 0, 12), // high half
        i(JEQ_K, 1, 0, (gate_ip >> 32) as u32),
        i(RET_K, 0, 0, RET_TRAP),
        i(RET_K, 0, 0, RET_ALLOW),
    ]
}

/// `struct sock_fprog`.
#[repr(C)]
struct SockFprog {
    len: u16,
    filter: *const SockFilter,
}

/// Set no_new_privs and install `insns` on the calling thread, both through the gate (so it works
/// with a filter already in place, whose trap would otherwise serve the call in the guest).
/// `flags` are seccomp's `SECCOMP_FILTER_FLAG_*`. Returns seccomp's raw result: 0, or with TSYNC
/// the id of a thread that couldn't be synced.
pub fn install_insns(insns: &[SockFilter], flags: u32) -> Result<usize, Errno> {
    let check = |r: isize| if r < 0 { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) };
    // prctl(PR_SET_NO_NEW_PRIVS = 38, 1): unprivileged seccomp needs it (and no setuid gains).
    // SAFETY: sets a flag of the process.
    check(unsafe { trap::gate(NR_PRCTL, 38, 1, 0, 0, 0, 0) })?;
    let fprog = SockFprog { len: insns.len() as u16, filter: insns.as_ptr() };
    // SECCOMP_SET_MODE_FILTER = 1.
    // SAFETY: seccomp reads `fprog` and the instructions, both live for the call.
    check(unsafe { trap::gate(NR_SECCOMP, 1, flags as usize, &fprog as *const SockFprog as usize, 0, 0, 0) })
}

/// Install the routing filter on the calling thread (and the threads it makes from now on).
pub fn install() -> Result<(), Errno> {
    install_insns(&program(trap::gate_ip()), 0).map(drop)
}
