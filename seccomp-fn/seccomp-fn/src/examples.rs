//! Example policies: each construct of the subset, each proven (`cargo kani`) and checked
//! against the kernel (`tests/kernel.rs`).

#![allow(non_upper_case_globals)] // libc's names, as patterns

use crate::{Sample, Seccomp, SeccompData, seccomp, seccomp_expr};
pub use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP};

// A policy's constants are its own, from libc. Two aren't in libc for x86_64:
/// include/uapi/linux/audit.h: `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | 0x8000_0000 | 0x4000_0000;
/// `__X32_SYSCALL_BIT`, arch/x86/include/uapi/asm/unistd.h (libc has it for the x32 target only).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;
// `d.nr` is unsigned (BPF compares it so): libc's numbers as u32, for patterns.
pub const SYS_read: u32 = libc::SYS_read as u32;
pub const SYS_write: u32 = libc::SYS_write as u32;
pub const SYS_kill: u32 = libc::SYS_kill as u32;
pub const SYS_exit: u32 = libc::SYS_exit as u32;
pub const SYS_exit_group: u32 = libc::SYS_exit_group as u32;

// Errnos are 100 and up: the kernel test tells them from an allowed call's own errors.

/// A build-time choice of rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Level {
    Low,
    High,
}

impl Sample for Level {
    fn samples() -> Vec<Self> {
        vec![Level::Low, Level::High]
    }
}

/// Every comparison on a 64-bit argument and a 32-bit field, `&&`, `||`, `!`, guards, `let`.
#[seccomp]
pub fn compares(d: &SeccompData, lo: u64, hi: u64, strict: bool, level: Level) -> u32 {
    if d.arch != AUDIT_ARCH_X86_64 {
        return SECCOMP_RET_KILL_PROCESS;
    }
    let mid = lo / 2 + hi / 2;
    if d.args[0] == lo && !(d.args[1] != hi) {
        return SECCOMP_RET_ERRNO | (100 + 1);
    }
    if d.args[2] < lo || d.args[2] > hi {
        return SECCOMP_RET_ERRNO | (100 + 2);
    }
    if (strict && d.args[3] >= mid) || (!strict && mid <= d.args[3]) {
        return SECCOMP_RET_ERRNO | (100 + 3);
    }
    if level == Level::High && d.args[4] <= 7 {
        return SECCOMP_RET_ERRNO | (100 + 4);
    }
    if d.nr > 1000 && d.args[5] != 0 {
        return SECCOMP_RET_ERRNO | (100 + 5);
    }
    SECCOMP_RET_ALLOW
}

/// `match d.nr`, with `|` and `_`, nested in and around `if`.
#[seccomp]
pub fn table(d: &SeccompData, pid: u64, allow_exit: bool) -> u32 {
    match d.nr {
        SYS_read | SYS_write => SECCOMP_RET_ALLOW,
        SYS_kill => {
            if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 {
                return SECCOMP_RET_ALLOW;
            }
            SECCOMP_RET_ERRNO | (100 + 6)
        }
        SYS_exit | SYS_exit_group => {
            if allow_exit {
                return SECCOMP_RET_ALLOW;
            }
            SECCOMP_RET_ERRNO | (100 + 7)
        }
        1000 => if d.instruction_pointer == pid { SECCOMP_RET_ERRNO | (100 + 8) } else { SECCOMP_RET_ERRNO | (100 + 9) },
        _ => SECCOMP_RET_TRAP,
    }
}

/// Match guards: arms in order, a guard that fails going on to the next arm, a pattern repeated,
/// a build-time guard, guards on `_`.
#[seccomp]
pub fn guarded(d: &SeccompData, pid: u64, on: bool) -> u32 {
    match d.nr {
        SYS_kill if d.args[0] == pid && d.args[1] <= 64 => SECCOMP_RET_ERRNO | 111,
        SYS_kill if on && d.args[1] == 0 => SECCOMP_RET_ERRNO | 112,
        SYS_read | SYS_kill if d.args[2] > 5 => SECCOMP_RET_ERRNO | 113,
        SYS_kill => SECCOMP_RET_ERRNO | 114,
        1000 | 1001 if !(d.args[0] < 3) || on => SECCOMP_RET_ERRNO | 115,
        _ if d.args[5] == 7 => SECCOMP_RET_ERRNO | 116,
        _ => SECCOMP_RET_ALLOW,
    }
}

/// Each field's halves: `==`, `<` and `<=` on every 64-bit field against `v` (whose halves the
/// tests make differ), and on `nr` and `arch` against `w`. A layout error the macro and
/// `run_bpf` shared would agree with itself; the kernel test runs this to see it.
#[seccomp]
pub fn halves(d: &SeccompData, v: u64, w: u32) -> u32 {
    if d.instruction_pointer == v {
        return SECCOMP_RET_ERRNO | 100;
    }
    if d.instruction_pointer < v {
        return SECCOMP_RET_ERRNO | 101;
    }
    if d.instruction_pointer <= v ^ 1 {
        return SECCOMP_RET_ERRNO | 102;
    }
    if d.args[0] == v { return SECCOMP_RET_ERRNO | 110; }
    if d.args[0] < v { return SECCOMP_RET_ERRNO | 111; }
    if d.args[0] <= v ^ 1 { return SECCOMP_RET_ERRNO | 112; }
    if d.args[1] == v { return SECCOMP_RET_ERRNO | 120; }
    if d.args[1] < v { return SECCOMP_RET_ERRNO | 121; }
    if d.args[1] <= v ^ 1 { return SECCOMP_RET_ERRNO | 122; }
    if d.args[2] == v { return SECCOMP_RET_ERRNO | 130; }
    if d.args[2] < v { return SECCOMP_RET_ERRNO | 131; }
    if d.args[2] <= v ^ 1 { return SECCOMP_RET_ERRNO | 132; }
    if d.args[3] == v { return SECCOMP_RET_ERRNO | 140; }
    if d.args[3] < v { return SECCOMP_RET_ERRNO | 141; }
    if d.args[3] <= v ^ 1 { return SECCOMP_RET_ERRNO | 142; }
    if d.args[4] == v { return SECCOMP_RET_ERRNO | 150; }
    if d.args[4] < v { return SECCOMP_RET_ERRNO | 151; }
    if d.args[4] <= v ^ 1 { return SECCOMP_RET_ERRNO | 152; }
    if d.args[5] == v { return SECCOMP_RET_ERRNO | 160; }
    if d.args[5] < v { return SECCOMP_RET_ERRNO | 161; }
    if d.args[5] <= v ^ 1 { return SECCOMP_RET_ERRNO | 162; }
    if d.nr == w { return SECCOMP_RET_ERRNO | 170; }
    if d.nr < w { return SECCOMP_RET_ERRNO | 171; }
    if d.nr <= w ^ 2 { return SECCOMP_RET_ERRNO | 172; }
    if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
    if d.nr >= X32_SYSCALL_BIT { return SECCOMP_RET_KILL_PROCESS; }
    SECCOMP_RET_ALLOW
}

/// Another ABI and the x32 bit: KILL. Anything else: an errno.
#[seccomp]
pub fn abi(d: &SeccompData) -> u32 {
    if d.arch != AUDIT_ARCH_X86_64 || d.nr >= X32_SYSCALL_BIT {
        return SECCOMP_RET_KILL_PROCESS;
    }
    SECCOMP_RET_ERRNO | 101
}

/// README.md's example, as it is there: libc's `SYS_*` (`i64`), matched on `d.nr as i64`.
pub mod readme {
    use super::AUDIT_ARCH_X86_64;
    use crate::{SeccompData, seccomp};
    use libc::{SECCOMP_RET_ALLOW, SECCOMP_RET_KILL_PROCESS, SYS_kill, SYS_read, SYS_write};

    #[seccomp]
    pub fn policy(d: &SeccompData, pid: u64) -> u32 {
        if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
        match d.nr as i64 {
            SYS_read | SYS_write => SECCOMP_RET_ALLOW,
            SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}

/// `compares`, as a value (`seccomp_expr!`): its proofs are items nested in this function.
pub fn compares_expr() -> impl Seccomp<(u64, u64, bool, Level)> {
    seccomp_expr!(|d: &SeccompData, lo: u64, hi: u64, strict: bool, level: Level| -> u32 {
        if d.arch != AUDIT_ARCH_X86_64 {
            return SECCOMP_RET_KILL_PROCESS;
        }
        let mid = lo / 2 + hi / 2;
        if d.args[0] == lo && !(d.args[1] != hi) {
            return SECCOMP_RET_ERRNO | (100 + 1);
        }
        if d.args[2] < lo || d.args[2] > hi {
            return SECCOMP_RET_ERRNO | (100 + 2);
        }
        if (strict && d.args[3] >= mid) || (!strict && mid <= d.args[3]) {
            return SECCOMP_RET_ERRNO | (100 + 3);
        }
        if level == Level::High && d.args[4] <= 7 {
            return SECCOMP_RET_ERRNO | (100 + 4);
        }
        if d.nr > 1000 && d.args[5] != 0 {
            return SECCOMP_RET_ERRNO | (100 + 5);
        }
        SECCOMP_RET_ALLOW
    })
}

/// A value of the trait object, for a `static` (the type is unnameable: it is the block's own).
pub static LO: &(dyn Seccomp<(u64,)> + Sync) = &seccomp_expr!(|d: &SeccompData, lo: u64| -> u32 {
    if d.args[0] == lo { return SECCOMP_RET_ERRNO | 100; }
    SECCOMP_RET_ALLOW
});

#[cfg(test)]
mod expr_tests {
    use super::*;

    #[test]
    fn compares_expr_sampled() {
        compares_expr().check_sampled();
    }

    #[test]
    fn compares_expr_is_compares() {
        let p = compares_expr();
        let key = |p: Vec<crate::SockFilter>| p.iter().map(|i| (i.code, i.jt, i.jf, i.k)).collect::<Vec<_>>();
        assert_eq!(key(p.bpf((3, 90, true, Level::High))), key(compares_bpf(3, 90, true, Level::High)));
        assert_eq!(LO.bpf((7,)).len(), 6);
        let d = SeccompData { nr: 1, arch: AUDIT_ARCH_X86_64, instruction_pointer: 0, args: [3, 90, 0, 0, 0, 0] };
        assert_eq!(p.run(&d, (3, 90, true, Level::High)), compares(&d, 3, 90, true, Level::High));
    }
}
