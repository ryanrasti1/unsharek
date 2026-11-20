//! Example policies: each construct of the subset, compiled by `seccomp_fn::compile!` (each call
//! naming its module from the file's root: the file has a `policy` per module), each
//! with its Kani harness (`seccomp_fn_validate::policy!`). Shared by seccomp-fn's tests
//! (`tests/examples.rs`: sampled) and seccomp-fn-validate's (`tests/kernel.rs`: `run_bpf`
//! against Linux on their programs), each including this file.

#![allow(non_upper_case_globals, dead_code)]

pub use libc::{
    SECCOMP_RET_ALLOW, SECCOMP_RET_ERRNO, SECCOMP_RET_KILL_PROCESS, SECCOMP_RET_TRAP, SYS_exit, SYS_exit_group, SYS_kill, SYS_read,
    SYS_write, seccomp_data, sock_filter,
};

// Two constants aren't in libc for x86_64:
/// include/uapi/linux/audit.h: `EM_X86_64 | __AUDIT_ARCH_64BIT | __AUDIT_ARCH_LE`.
pub const AUDIT_ARCH_X86_64: u32 = libc::EM_X86_64 as u32 | 0x8000_0000 | 0x4000_0000;
/// `__X32_SYSCALL_BIT`, arch/x86/include/uapi/asm/unistd.h (libc has it for the x32 target only).
pub const X32_SYSCALL_BIT: u32 = 0x4000_0000;

// Errnos are 100 and up: the kernel test tells them from an allowed call's own errors.

/// README.md's.
pub mod readme {
    use super::*;

    pub fn policy(pid: u64) -> impl Fn(&seccomp_data) -> u32 {
        move |d| {
            if d.arch != AUDIT_ARCH_X86_64 {
                return SECCOMP_RET_KILL_PROCESS;
            }
            match d.nr as i64 {
                SYS_read | SYS_write => SECCOMP_RET_ALLOW,
                SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
                _ => SECCOMP_RET_KILL_PROCESS,
            }
        }
    }

    pub fn filter(pid: u64) -> Vec<sock_filter> {
        seccomp_fn::compile!(readme::policy(pid))
    }

    seccomp_fn_validate::policy!(policy, filter);
}

/// A build-time choice of rows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub enum Level {
    Low,
    High,
}

/// Every comparison on a 64-bit argument and a 32-bit field, `&&`, `||`, `!`, guards, `let`.
pub mod compares {
    use super::*;

    pub fn policy(lo: u64, hi: u64, strict: bool, level: Level) -> impl Fn(&seccomp_data) -> u32 {
        move |d| {
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
            if d.nr as u32 > 1000 && d.args[5] != 0 {
                return SECCOMP_RET_ERRNO | (100 + 5);
            }
            SECCOMP_RET_ALLOW
        }
    }

    pub fn filter(lo: u64, hi: u64, strict: bool, level: Level) -> Vec<sock_filter> {
        seccomp_fn::compile!(compares::policy(lo, hi, strict, level))
    }

    // A harness per shape: one with the bool and the enum symbolic ran over 35 minutes.
    seccomp_fn_validate::policy!(policy, filter, unwind = 100, (
        _, _, bool = [loose: false, strict: true], Level = [low: Low, high: High]
    ));
}

/// `match d.nr`, with `|` and `_`, nested in and around `if`.
pub mod table {
    use super::*;

    pub fn policy(pid: u64, allow_exit: bool) -> impl Fn(&seccomp_data) -> u32 {
        move |d| match d.nr as i64 {
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
            1000 => {
                if d.instruction_pointer == pid {
                    SECCOMP_RET_ERRNO | (100 + 8)
                } else {
                    SECCOMP_RET_ERRNO | (100 + 9)
                }
            }
            _ => SECCOMP_RET_TRAP,
        }
    }

    pub fn filter(pid: u64, allow_exit: bool) -> Vec<sock_filter> {
        seccomp_fn::compile!(table::policy(pid, allow_exit))
    }

    // A harness per value of the bool (with it symbolic: over 400 s).
    seccomp_fn_validate::policy!(policy, filter, unwind = 100, (_, bool = [no_exit: false, exit: true]));
}

/// Match guards: arms in order, a guard that fails going on to the next arm, a pattern repeated,
/// a build-time guard, guards on `_`.
pub mod guarded {
    use super::*;

    pub fn policy(pid: u64, on: bool) -> impl Fn(&seccomp_data) -> u32 {
        move |d| match d.nr as i64 {
            SYS_kill if d.args[0] == pid && d.args[1] <= 64 => SECCOMP_RET_ERRNO | 111,
            SYS_kill if on && d.args[1] == 0 => SECCOMP_RET_ERRNO | 112,
            SYS_read | SYS_kill if d.args[2] > 5 => SECCOMP_RET_ERRNO | 113,
            SYS_kill => SECCOMP_RET_ERRNO | 114,
            1000 | 1001 if !(d.args[0] < 3) || on => SECCOMP_RET_ERRNO | 115,
            _ if d.args[5] == 7 => SECCOMP_RET_ERRNO | 116,
            _ => SECCOMP_RET_ALLOW,
        }
    }

    pub fn filter(pid: u64, on: bool) -> Vec<sock_filter> {
        seccomp_fn::compile!(guarded::policy(pid, on))
    }

    // A harness per value of the bool (with it symbolic: over 400 s).
    seccomp_fn_validate::policy!(policy, filter, unwind = 100, (_, bool = [off: false, on: true]));
}

/// Each field's halves: `==`, `<` and `<=` on every 64-bit field against `v` (whose halves the
/// tests make differ), and on `nr` and `arch` against `w`. A layout error the compiler and
/// `run_bpf` shared would agree with itself; the kernel test runs this to see it.
pub mod halves {
    use super::*;

    #[rustfmt::skip]
    pub fn policy(v: u64, w: u32) -> impl Fn(&seccomp_data) -> u32 {
        move |d| {
            if d.instruction_pointer == v { return SECCOMP_RET_ERRNO | 100; }
            if d.instruction_pointer < v { return SECCOMP_RET_ERRNO | 101; }
            if d.instruction_pointer <= v ^ 1 { return SECCOMP_RET_ERRNO | 102; }
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
            if d.nr as u32 == w { return SECCOMP_RET_ERRNO | 170; }
            if (d.nr as u32) < w { return SECCOMP_RET_ERRNO | 171; }
            if d.nr as u32 <= w ^ 2 { return SECCOMP_RET_ERRNO | 172; }
            if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
            if d.nr as u32 >= X32_SYSCALL_BIT { return SECCOMP_RET_KILL_PROCESS; }
            SECCOMP_RET_ALLOW
        }
    }

    pub fn filter(v: u64, w: u32) -> Vec<sock_filter> {
        seccomp_fn::compile!(halves::policy(v, w))
    }

    // (its program: over 100 instructions, the default bound)
    seccomp_fn_validate::policy!(policy, filter, unwind = 160);
}

/// Another ABI and the x32 bit: KILL. Anything else: an errno.
pub mod abi {
    use super::*;

    pub fn policy() -> impl Fn(&seccomp_data) -> u32 {
        move |d| {
            if d.arch != AUDIT_ARCH_X86_64 || d.nr as u32 >= X32_SYSCALL_BIT {
                return SECCOMP_RET_KILL_PROCESS;
            }
            SECCOMP_RET_ERRNO | 101
        }
    }

    pub fn filter() -> Vec<sock_filter> {
        seccomp_fn::compile!(abi::policy())
    }

    seccomp_fn_validate::policy!(policy, filter);
}

/// Long enough that its jumps go through JA: a row per number, all to one shared verdict. No
/// harness: its proof takes more than ten minutes (the proof's cost grows about quadratically
/// with the program's length); it is sampled and checked against the kernel.
pub mod long {
    use super::*;

    #[rustfmt::skip]
    pub fn policy(k: u64) -> impl Fn(&seccomp_data) -> u32 {
        move |d| {
            if d.nr as u32 == 2000 || d.args[0] == k || d.args[1] == k || d.args[2] == k || d.args[3] == k
                || d.args[4] == k || d.args[5] == k || d.instruction_pointer == k
                || d.args[0] == 1 || d.args[1] == 1 || d.args[2] == 1 || d.args[3] == 1 || d.args[4] == 1 || d.args[5] == 1
                || d.args[0] == 2 || d.args[1] == 2 || d.args[2] == 2 || d.args[3] == 2 || d.args[4] == 2 || d.args[5] == 2
                || d.args[0] == 3 || d.args[1] == 3 || d.args[2] == 3 || d.args[3] == 3 || d.args[4] == 3 || d.args[5] == 3
                || d.args[0] == 4 || d.args[1] == 4 || d.args[2] == 4 || d.args[3] == 4 || d.args[4] == 4 || d.args[5] == 4
                || d.args[0] == 5 || d.args[1] == 5 || d.args[2] == 5 || d.args[3] == 5 || d.args[4] == 5 || d.args[5] == 5
                || d.args[0] == 6 || d.args[1] == 6 || d.args[2] == 6 || d.args[3] == 6 || d.args[4] == 6 || d.args[5] == 6
                || d.args[0] == 7 || d.args[1] == 7 || d.args[2] == 7 || d.args[3] == 7 || d.args[4] == 7 || d.args[5] == 7
                || d.args[0] == 8 || d.args[1] == 8 || d.args[2] == 8 || d.args[3] == 8 || d.args[4] == 8 || d.args[5] == 8
                || d.args[0] == 9 || d.args[1] == 9 || d.args[2] == 9 || d.args[3] == 9 || d.args[4] == 9 || d.args[5] == 9
                || d.args[0] < 10 || d.args[1] > 10 || d.args[2] <= 10 || d.args[3] >= 10 || d.args[4] != 10
            {
                return SECCOMP_RET_ERRNO | (100 + 10);
            }
            SECCOMP_RET_ALLOW
        }
    }

    pub fn filter(k: u64) -> Vec<sock_filter> {
        seccomp_fn::compile!(long::policy(k))
    }
}
