//! The security filter, checked three ways: an interpreter for classic BPF run over every
//! syscall number and every rule's argument edges; the same verdicts as the filter it replaced
//! (`old`, the hand-written compiler), for every number, every argument edge of either, from the
//! gate and elsewhere; and real installs in forked children.

use super::*;
use old::{Cond as OldCond, Params, Policy, Rule as OldRule};

const GATE: u64 = 0x0000_7f12_3456_7890;
const TOKENS: (RawFd, RawFd) = (256, 384);
const PID: u32 = 4242;
const EPERM_RET: u32 = RET_ERRNO | libc::EPERM as u32;
const MODES: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];
const NR_READ: u32 = 0;
const NR_WRITE: u32 = 1;
const NR_RT_SIGRETURN: u32 = 15;
const NR_MADVISE: u32 = 28;
const NR_CLONE: u32 = 56;
const NR_EXIT: u32 = 60;
const NR_KILL: u32 = 62;
const NR_EXIT_GROUP: u32 = 231;
const NR_PPOLL: u32 = 271;
const SIGCHLD: u64 = 17;
const SIBLING: u64 = 0x8000 | SIGCHLD;

#[derive(Clone, Copy, Debug)]
struct Data {
    nr: u32,
    arch: u32,
    ip: u64,
    args: [u64; 6],
}

fn gate(nr: u32, args: [u64; 6]) -> Data {
    Data { nr, arch: AUDIT_ARCH_X86_64, ip: GATE, args }
}

/// Classic BPF over `struct seccomp_data`: the opcodes the old compiler and seccompiler emit
/// (loads, jumps, returns, and AND for seccompiler's masks); anything else panics, as does a
/// jump out of the program.
fn run(prog: &[SockFilter], d: &Data) -> u32 {
    let word = |off: u32| -> u32 {
        match off {
            0 => d.nr,
            4 => d.arch,
            8 => d.ip as u32,
            12 => (d.ip >> 32) as u32,
            16..=63 if off.is_multiple_of(4) => {
                let a = d.args[(off as usize - 16) / 8];
                if off.is_multiple_of(8) { a as u32 } else { (a >> 32) as u32 }
            }
            _ => panic!("load from {off}"),
        }
    };
    let (mut pc, mut a) = (0usize, 0u32);
    loop {
        let ins = prog[pc];
        let jump = |taken: bool| pc + 1 + if taken { ins.jt } else { ins.jf } as usize;
        pc = match ins.code {
            0x20 => {
                a = word(ins.k);
                pc + 1
            }
            0x54 => {
                a &= ins.k; // BPF_ALU | BPF_AND | BPF_K
                pc + 1
            }
            0x05 => pc + 1 + ins.k as usize, // BPF_JMP | BPF_JA
            0x15 => jump(a == ins.k),
            0x25 => jump(a > ins.k),
            0x35 => jump(a >= ins.k),
            0x45 => jump(a & ins.k != 0),
            0x06 => return ins.k,
            c => panic!("opcode {c:#x}"),
        };
        assert!(pc < prog.len(), "jump past the end");
    }
}

fn pins(fds: &[RawFd]) -> Pins {
    Pins { pid: PID, tokens: Some(TOKENS), fds: fds.to_vec() }
}

fn build_with(mode: Mode, deny: Deny, fds: &[RawFd]) -> Vec<SockFilter> {
    let mut p = pins(fds);
    if mode == Mode::Coroutine {
        p.tokens = None;
    }
    security(mode, deny, &p, GATE).unwrap()
}

fn build(mode: Mode, deny: Deny) -> Vec<SockFilter> {
    build_with(mode, deny, &[])
}

fn check(prog: &[SockFilter], d: Data) -> u32 {
    run(prog, &d)
}

/// Values around each range's edges, in both halves, plus the extremes.
fn probes(ranges: &[(u64, u64)]) -> Vec<u64> {
    let mut v = vec![0, 1, u64::MAX, u64::MAX - 1, 1 << 32, (1 << 32) - 1, 1 << 63, u32::MAX as u64];
    for &(lo, hi) in ranges {
        for x in [lo, hi] {
            for d in [0, 1, 2, 1 << 32] {
                v.push(x.wrapping_add(d));
                v.push(x.wrapping_sub(d));
            }
            v.push(x ^ (1 << 32)); // differs only in the high half
            v.push(x ^ (1 << 63));
            v.push(x | 0xffff_ffff_0000_0000);
            v.push(x & 0xffff_ffff); // the low half alone
            v.push(x.rotate_left(32)); // halves swapped
        }
    }
    v
}

/// Arg `arg` of `nr` from the gate, with the others at `base`: allowed exactly within `allowed`.
fn edges(mode: Mode, nr: u32, base: [u64; 6], arg: usize, allowed: &[(u64, u64)]) {
    let prog = build(mode, Deny::Errno);
    for v in probes(allowed) {
        let mut args = base;
        args[arg] = v;
        let want = if allowed.iter().any(|&(lo, hi)| lo <= v && v <= hi) { RET_ALLOW } else { EPERM_RET };
        assert_eq!(check(&prog, gate(nr, args)), want, "{mode:?} nr {nr} arg{arg} = {v:#x}");
    }
}

fn tok() -> (u64, u64) {
    (TOKENS.0 as u64, TOKENS.1 as u64)
}

/// The prologue's verdicts are KILL and TRAP only: whatever it decides, nothing it passes on is
/// allowed but by the allowlist after it.
#[test]
fn prologue_never_allows() {
    for ins in prologue(GATE) {
        if ins.code == RET_K {
            assert!(ins.k == RET_KILL_PROCESS || ins.k == RET_TRAP, "{ins:?}");
        }
    }
}

#[test]
fn not_from_the_gate_traps() {
    for mode in MODES {
        for deny in [Deny::Kill, Deny::Errno] {
            let prog = build(mode, deny);
            for nr in 0..=500 {
                // Off by one, off only in the high half, off only in the low half, and nowhere.
                for ip in [GATE + 2, GATE - 2, GATE ^ (1 << 40), GATE ^ 1, 0, u64::MAX] {
                    let d = Data { nr, arch: AUDIT_ARCH_X86_64, ip, args: [0; 6] };
                    assert_eq!(check(&prog, d), RET_TRAP, "{mode:?} nr {nr} ip {ip:#x}");
                }
            }
        }
    }
}

#[test]
fn from_the_gate_zero_args() {
    // Which rules match all-zero arguments: read(0), exit_group, ppoll(nfds 0, no mask) in
    // every mode, and exit(0) where threads exist. write(0), madvise (never), clone(0) and the
    // token fds don't.
    let all = [NR_RT_SIGRETURN, NR_READ, NR_EXIT_GROUP, NR_PPOLL];
    for mode in MODES {
        let prog = build(mode, Deny::Errno);
        let mut allowed = all.to_vec();
        if mode != Mode::Coroutine {
            allowed.push(NR_EXIT);
        }
        for nr in 0..=500 {
            let want = if allowed.contains(&nr) { RET_ALLOW } else { EPERM_RET };
            assert_eq!(check(&prog, gate(nr, [0; 6])), want, "{mode:?} nr {nr}");
        }
    }
}

#[test]
fn stdio_and_tokens() {
    let t = tok();
    for mode in MODES {
        let threads = mode != Mode::Coroutine;
        let w: &[(u64, u64)] = if threads { &[(1, 2), t] } else { &[(1, 2)] };
        let r: &[(u64, u64)] = if threads { &[(0, 0), t] } else { &[(0, 0)] };
        edges(mode, NR_WRITE, [0; 6], 0, w);
        edges(mode, NR_READ, [0; 6], 0, r);
        // Only arg0 is checked: the buffer and length are anything.
        edges(mode, NR_WRITE, [1, 0, 0, 0, 0, 0], 1, &[(0, u64::MAX)]);
        edges(mode, NR_READ, [0; 6], 2, &[(0, u64::MAX)]);
        if threads {
            edges(mode, NR_WRITE, [TOKENS.1 as u64, 0, 0, 0, 0, 0], 2, &[(0, u64::MAX)]);
        }
    }
}

/// Passed and held fds: read and write on exactly each, nothing next to them.
#[test]
fn passed_fds() {
    for mode in MODES {
        let prog = build_with(mode, Deny::Errno, &[7, 1000]);
        for nr in [NR_READ, NR_WRITE] {
            for fd in [7u64, 1000] {
                assert_eq!(check(&prog, gate(nr, [fd, 0, 0, 0, 0, 0])), RET_ALLOW, "{mode:?} {nr} fd {fd}");
            }
            for fd in [6u64, 8, 999, 1001, 7 | 1 << 32, 1000 | 1 << 63] {
                assert_eq!(check(&prog, gate(nr, [fd, 0, 0, 0, 0, 0])), EPERM_RET, "{mode:?} {nr} fd {fd:#x}");
            }
        }
        // Other calls on them: refused.
        for nr in [3 /* close */, 72 /* fcntl */, 16 /* ioctl */, 44 /* sendto */] {
            assert_eq!(check(&prog, gate(nr, [7, 0, 0, 0, 0, 0])), EPERM_RET);
        }
    }
}

#[test]
fn ppoll() {
    for mode in MODES {
        // Up to eight pollfds (the idle wait over several held fds), never nine.
        edges(mode, NR_PPOLL, [0; 6], 1, &[(0, PPOLL_FDS)]);
        edges(mode, NR_PPOLL, [0, 1, 0, 0, 0, 0], 3, &[(0, 0)]);
        // The pollfd pointer, the timeout and sigsetsize are anything.
        for arg in [0, 2, 4, 5] {
            edges(mode, NR_PPOLL, [0, 1, 0, 0, 0, 0], arg, &[(0, u64::MAX)]);
        }
        let prog = build(mode, Deny::Errno);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 8, 0, 0, 0, 0])), RET_ALLOW);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 9, 0, 0, 0, 0])), EPERM_RET);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 8, 0, 1, 0, 0])), EPERM_RET);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 1, 0, 1 << 32, 0, 0])), EPERM_RET);
    }
}

/// `kill` from the gate: the sandbox's own pid and a signal number.
#[test]
fn kill_self() {
    let ok = [PID as u64, 6, 0, 0, 0, 0];
    for mode in MODES {
        edges(mode, NR_KILL, ok, 0, &[(PID as u64, PID as u64)]);
        edges(mode, NR_KILL, ok, 1, &[(1, 64)]);
        edges(mode, NR_KILL, ok, 2, &[(0, u64::MAX)]);
    }
}

/// No madvise (or any memory call) from the gate in any mode.
#[test]
fn no_memory_calls() {
    for mode in MODES {
        let prog = build(mode, Deny::Errno);
        for nr in [9 /* mmap */, 10 /* mprotect */, 11 /* munmap */, 25 /* mremap */, NR_MADVISE] {
            for addr in [0, 0x20_0000, 0x7f00_0000_0000, u64::MAX] {
                for advice in [0, 4, 8] {
                    assert_eq!(check(&prog, gate(nr, [addr, 4096, advice, 0, 0, 0])), EPERM_RET, "{mode:?} {nr}");
                }
            }
        }
    }
}

#[test]
fn clone_and_exit() {
    for mode in [Mode::Threaded, Mode::Fork] {
        let fork = mode == Mode::Fork;
        let t = CLONE_THREAD_FLAGS;
        let clone0: &[(u64, u64)] =
            if fork { &[(t, t), (SIGCHLD, SIGCHLD), (SIBLING, SIBLING)] } else { &[(t, t)] };
        edges(mode, NR_CLONE, [0; 6], 0, clone0);
        edges(mode, NR_EXIT, [0; 6], 0, &[(0, 0)]);
        let prog = build(mode, Deny::Errno);
        for bit in 0..64 {
            let flags = t ^ (1 << bit);
            assert_eq!(check(&prog, gate(NR_CLONE, [flags, 0, 0, 0, 0, 0])), EPERM_RET, "bit {bit}");
            for base in [SIGCHLD, SIBLING] {
                let flags = base ^ (1 << bit);
                if !(fork && (flags == SIGCHLD || flags == SIBLING)) {
                    assert_eq!(check(&prog, gate(NR_CLONE, [flags, 0, 0, 0, 0, 0])), EPERM_RET, "{base:#x} bit {bit}");
                }
            }
        }
        // The thread clone takes any stack; the fork clone only no stack.
        edges(mode, NR_CLONE, [t, 0, 0, 0, 0, 0], 1, &[(0, u64::MAX)]);
        let fork_stack: &[(u64, u64)] = if fork { &[(0, 0)] } else { &[] };
        edges(mode, NR_CLONE, [SIGCHLD, 0, 0, 0, 0, 0], 1, fork_stack);
        edges(mode, NR_CLONE, [SIBLING, 0, 0, 0, 0, 0], 1, fork_stack);
        assert_eq!(check(&prog, gate(NR_EXIT, [1, 0, 0, 0, 0, 0])), EPERM_RET);
    }
    let prog = build(Mode::Coroutine, Deny::Errno);
    for args in [[CLONE_THREAD_FLAGS, 0, 0, 0, 0, 0], [SIGCHLD, 0, 0, 0, 0, 0]] {
        assert_eq!(check(&prog, gate(NR_CLONE, args)), EPERM_RET);
    }
}

/// The runtime makes its threads with the flags the filter pins (a mismatch would be a sandbox
/// killed at its first thread, never a wider filter: this says which to fix).
#[test]
fn the_runtimes_shapes() {
    assert_eq!(CLONE_THREAD_FLAGS, exobox_rt::trap::CLONE_HOST_THREAD);
    assert_eq!(PPOLL_FDS, exobox_rt::trap::PPOLL_FDS);
}

#[test]
fn exit_group_any() {
    for mode in MODES {
        let prog = build(mode, Deny::Kill);
        for v in probes(&[]) {
            assert_eq!(check(&prog, gate(NR_EXIT_GROUP, [v; 6])), RET_ALLOW);
        }
    }
}

#[test]
fn arch_and_x32_kill() {
    for mode in MODES {
        let prog = build(mode, Deny::Errno);
        for arch in [0, 0x4000_0003 /* AUDIT_ARCH_I386 */, AUDIT_ARCH_X86_64 ^ 1] {
            for ip in [GATE, 0] {
                for nr in [NR_WRITE, NR_RT_SIGRETURN, NR_EXIT_GROUP] {
                    let d = Data { nr, arch, ip, args: [1, 0, 0, 0, 0, 0] };
                    assert_eq!(check(&prog, d), RET_KILL_PROCESS);
                }
            }
        }
        for nr in [X32_SYSCALL_BIT, X32_SYSCALL_BIT | NR_WRITE, X32_SYSCALL_BIT | NR_RT_SIGRETURN, u32::MAX] {
            for ip in [GATE, 0] {
                let d = Data { nr, arch: AUDIT_ARCH_X86_64, ip, args: [1, 0, 0, 0, 0, 0] };
                assert_eq!(check(&prog, d), RET_KILL_PROCESS, "nr {nr:#x}");
            }
        }
        assert_eq!(check(&prog, gate(X32_SYSCALL_BIT - 1, [0; 6])), EPERM_RET);
    }
}

#[test]
fn deny_kill_or_errno() {
    for mode in MODES {
        let kill = build(mode, Deny::Kill);
        let errno = build(mode, Deny::Errno);
        for (nr, args) in [(110 /* getppid */, [0; 6]), (NR_WRITE, [3, 0, 0, 0, 0, 0])] {
            assert_eq!(check(&kill, gate(nr, args)), RET_KILL_PROCESS);
            assert_eq!(check(&errno, gate(nr, args)), EPERM_RET);
        }
        assert_eq!(check(&kill, gate(NR_WRITE, [1, 0, 0, 0, 0, 0])), RET_ALLOW);
    }
}

#[test]
fn restriction_prologue_jumps_to_the_program() {
    let user = [SockFilter { code: 0x06, jt: 0, jf: 0, k: 0 }];
    let p = restriction(&user, 0x1234_5678_9abc);
    // Every not-taken branch of the prologue lands on the caller's first instruction.
    let start = p.len() - 1;
    assert_eq!(2 + 1 + p[2].jf as usize, start);
    assert_eq!(4 + 1 + p[4].jf as usize, start);
    assert_eq!(6 + 1 + p[6].jf as usize, start);
    assert_eq!(1 + 1 + p[1].jt as usize, 3);
}

// ------------------------------------------------------------------------------------------------
// The same verdicts as the filter this one replaced.

fn old_program(mode: Mode, deny: Deny, p: &Pins) -> Vec<SockFilter> {
    let conds: Vec<[OldCond; 1]> = p.fds.iter().map(|&fd| [OldCond { arg: 0, lo: fd as u64, hi: fd as u64 }]).collect();
    let extra: Vec<OldRule> = conds
        .iter()
        .flat_map(|c| [OldRule { nr: old::NR_READ, conds: c }, OldRule { nr: old::NR_WRITE, conds: c }])
        .collect();
    let tokens = p.tokens.map_or((0, 0), |(lo, hi)| (lo as u32, hi as u32));
    let params = Params {
        policy: Policy::Mode(match mode {
            Mode::Coroutine => old::Mode::Coroutine,
            Mode::Threaded => old::Mode::Threaded,
            Mode::Fork => old::Mode::Fork,
        }),
        deny: match deny {
            Deny::Kill => old::Deny::Kill,
            Deny::Errno => old::Deny::Errno,
        },
        gate_ip: GATE,
        token_fds: tokens,
        pid: p.pid,
        extra: &extra,
    };
    let mut prog = old::Program::new();
    old::compile(&params, &mut prog).unwrap();
    prog.as_slice().iter().map(|f| SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }).collect()
}

/// Both filters, for every syscall number (and the x32 and out-of-range ones), from the gate
/// and not, under every arch, with each argument at every edge of every constant either filter
/// knows (one at a time, the others zero or at an allowed value), and the pairs of arguments the
/// multi-condition rules test: the same verdict, every time. The old filter's tests covered its
/// compiler's 64-bit range logic; this carries that to seccompiler's.
#[test]
fn same_as_the_old_filter() {
    let pin_sets = [
        Pins { pid: PID, tokens: Some(TOKENS), fds: vec![] },
        Pins { pid: 1, tokens: Some((300, 428)), fds: vec![3, 1000, 255, 385] },
        Pins { pid: 0x7fff_fffe, tokens: Some((256, 256)), fds: vec![0x7fff_ffff] },
    ];
    let mut checked = 0u64;
    for mode in MODES {
        for deny in [Deny::Kill, Deny::Errno] {
            for p in &pin_sets {
                let mut p = p.clone();
                if mode == Mode::Coroutine {
                    p.tokens = None;
                }
                let new = security(mode, deny, &p, GATE).unwrap();
                let old = old_program(mode, deny, &p);
                let (lo, hi) = p.tokens.unwrap_or((0, 0));
                let mut ranges = vec![
                    (0, 2),
                    (1, 64),
                    (0, PPOLL_FDS),
                    (p.pid as u64, p.pid as u64),
                    (lo as u64, hi as u64),
                    (CLONE_THREAD_FLAGS, CLONE_THREAD_FLAGS),
                    (SIGCHLD, SIBLING),
                ];
                ranges.extend(p.fds.iter().map(|&f| (f as u64, f as u64)));
                let vals = probes(&ranges);
                let small: Vec<u64> = ranges
                    .iter()
                    .flat_map(|&(lo, hi)| [lo, hi])
                    .flat_map(|x| [x.wrapping_sub(1), x, x.wrapping_add(1), x ^ (1 << 32)])
                    .chain([u64::MAX])
                    .collect();
                let mut nrs: Vec<u32> = (0..=460).collect();
                nrs.extend([X32_SYSCALL_BIT - 1, X32_SYSCALL_BIT, X32_SYSCALL_BIT | 1, u32::MAX, 0x8000_0000]);
                let mut same = |d: Data| {
                    checked += 1;
                    assert_eq!(run(&new, &d), run(&old, &d), "{mode:?} {deny:?} {p:?}: {d:x?}");
                };
                // Every number, a few argument patterns: a number neither filter has a rule for is
                // decided before any argument is loaded.
                for &nr in &nrs {
                    for arch in [AUDIT_ARCH_X86_64, 0x4000_0003] {
                        for ip in [GATE, GATE + 2, GATE ^ (1 << 40), 0] {
                            for args in [[0; 6], [u64::MAX; 6], [1, 2, 3, 4, 5, 6], [lo as u64; 6], [p.pid as u64; 6]] {
                                same(Data { nr, arch, ip, args });
                            }
                        }
                    }
                }
                // The numbers with rules (and their neighbours), every argument at every edge.
                let ruled = [
                    NR_READ, NR_WRITE, 2, 14, NR_RT_SIGRETURN, 16, NR_MADVISE, 55, NR_CLONE, 57, 59, NR_EXIT, 61, NR_KILL, 63,
                    230, NR_EXIT_GROUP, 232, 270, NR_PPOLL, 272,
                ];
                // Each argument at each edge, the others zero, then at an allowed value.
                let allowed_base: &[(u32, [u64; 6])] = &[
                    (NR_KILL, [p.pid as u64, 9, 0, 0, 0, 0]),
                    (NR_PPOLL, [0, 1, 0, 0, 8, 0]),
                    (NR_CLONE, [SIGCHLD, 0, 0, 0, 0, 0]),
                    (NR_CLONE, [SIBLING, 0, 0, 0, 0, 0]),
                    (NR_CLONE, [CLONE_THREAD_FLAGS, 0, 0, 0, 0, 0]),
                    (NR_WRITE, [1, 0, 0, 0, 0, 0]),
                    (NR_READ, [lo as u64, 0, 0, 0, 0, 0]),
                ];
                for nr in ruled {
                    for arg in 0..6 {
                        for &v in &vals {
                            let mut args = [0; 6];
                            args[arg] = v;
                            same(gate(nr, args));
                        }
                    }
                }
                for &(nr, base) in allowed_base {
                    for arg in 0..6 {
                        for &v in &vals {
                            let mut args = base;
                            args[arg] = v;
                            same(gate(nr, args));
                        }
                    }
                    // Pairs: kill's pid and signal, ppoll's count and mask, clone's flags and stack.
                    for &a in &small {
                        for &b in &small {
                            for (i, j) in [(0, 1), (1, 3)] {
                                let mut args = base;
                                args[i] = a;
                                args[j] = b;
                                same(gate(nr, args));
                            }
                        }
                    }
                }
            }
        }
    }
    eprintln!("{checked} cases, the same verdict each");
}

/// The routing filter (exobox-rt's, hand-written) against the old compiler's routing-only one.
#[test]
fn routing_same_as_the_old() {
    let params = Params { policy: Policy::RouteOnly, deny: old::Deny::Kill, gate_ip: GATE, token_fds: (0, 0), pid: 0, extra: &[] };
    let mut prog = old::Program::new();
    old::compile(&params, &mut prog).unwrap();
    let old: Vec<SockFilter> = prog.as_slice().iter().map(|f| SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }).collect();
    let new: Vec<SockFilter> =
        exobox_rt::route::program(GATE).iter().map(|f| SockFilter { code: f.code, jt: f.jt, jf: f.jf, k: f.k }).collect();
    for nr in (0..=500).chain([X32_SYSCALL_BIT, u32::MAX]) {
        for arch in [AUDIT_ARCH_X86_64, 0x4000_0003] {
            for ip in [GATE, GATE + 2, GATE ^ (1 << 40), 0] {
                for args in [[0; 6], [u64::MAX; 6]] {
                    let d = Data { nr, arch, ip, args };
                    assert_eq!(run(&new, &d), run(&old, &d), "{d:x?}");
                }
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The real kernel.

/// Each mode's filter (deny = errno), stacked on the routing one as the sandbox does, in a forked
/// child: through the gate a permitted write succeeds, getppid and a write to fd 3 are EPERM, and
/// with TSYNC the install covers the thread made before it. The child makes no syscall outside
/// the gate after the routing filter (it has no SIGSYS handler) and reports through its status.
#[test]
fn installs_in_the_kernel() {
    let gate_ip = exobox_rt::trap::gate_ip();
    for mode in MODES {
        let mut p = pins(&[]);
        // SAFETY: getpid.
        p.pid = unsafe { libc::getpid() } as u32;
        if mode == Mode::Coroutine {
            p.tokens = None;
        }
        let prog = security(mode, Deny::Errno, &p, gate_ip).unwrap();
        let g = |nr: u32, a0: usize| unsafe { exobox_rt::trap::gate(nr as usize, a0, b"".as_ptr() as usize, 0, 0, 0, 0) };
        // SAFETY: the child only installs and calls the gate, then exits through it.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = if exobox_rt::route::install().is_err() {
                10
            } else if super::super::lockdown::install(&prog, true).is_err() {
                11
            } else if g(NR_WRITE, 1) != 0 {
                12
            } else if g(110, 0) != -1 {
                13 // getppid: -EPERM
            } else if g(NR_WRITE, 3) != -1 {
                14
            } else {
                0
            };
            g(NR_EXIT_GROUP, status);
            unreachable!();
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "{mode:?}: child status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "{mode:?}");
    }
}
