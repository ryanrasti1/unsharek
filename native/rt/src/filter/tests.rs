//! The filter, checked two ways: an interpreter for the opcodes `compile` emits, run over every
//! syscall number and every rule's argument edges (seconds); and one real install in a forked
//! child, through a real gate.

use super::*;

const GATE: u64 = 0x0000_7f12_3456_7890;
/// Two arenas: an ordinary one, and one spanning 2^32 (lo and hi differ in the high half).
const ARENA: [(u64, u64); 2] = [(0x7f00_0000_0000, 0x7f00_4000_0000), (0xffff_0000, 0x1_0001_0000)];
const TOKENS: (u32, u32) = (1100, 1356);
const PID: u32 = 4242;
const DENY: u32 = SECCOMP_RET_ERRNO | EPERM;
const ALLOW: u32 = SECCOMP_RET_ALLOW;
const MODES: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];

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

/// Classic BPF, only what `compile` emits; anything else (or a jump out of the program) panics.
fn run(prog: &[SockFilter], d: &Data) -> u32 {
    let word = |off: u32| -> u32 {
        match off {
            OFF_NR => d.nr,
            OFF_ARCH => d.arch,
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
            LD_W_ABS => {
                a = word(ins.k);
                pc + 1
            }
            JEQ_K => jump(a == ins.k),
            JGT_K => jump(a > ins.k),
            JGE_K => jump(a >= ins.k),
            RET_K => return ins.k,
            c => panic!("opcode {c:#x}"),
        };
        assert!(pc < prog.len(), "jump past the end");
    }
}

fn build(mode: Mode, deny: Deny, extra: &[Rule]) -> Program {
    let mut p = Program::new();
    let params = Params { policy: Policy::Mode(mode), deny, gate_ip: GATE, arena: &ARENA, token_fds: TOKENS, pid: PID, extra };
    compile(&params, &mut p).unwrap();
    p
}

fn check(prog: &Program, d: Data) -> u32 {
    run(prog.as_slice(), &d)
}

/// Values around each range's edges, in both halves, plus the extremes.
fn probes(ranges: &[(u64, u64)]) -> Vec<u64> {
    let mut v =
        vec![0, 1, u64::MAX, u64::MAX - 1, 1 << 32, (1 << 32) - 1, 1 << 63, u32::MAX as u64];
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
    let prog = build(mode, Deny::Errno, &[]);
    for v in probes(allowed) {
        let mut args = base;
        args[arg] = v;
        let want = if allowed.iter().any(|&(lo, hi)| lo <= v && v <= hi) { ALLOW } else { DENY };
        assert_eq!(check(&prog, gate(nr, args)), want, "{mode:?} nr {nr} arg{arg} = {v:#x}");
    }
}

fn tok() -> (u64, u64) {
    (TOKENS.0 as u64, TOKENS.1 as u64)
}

#[test]
fn not_from_the_gate_traps() {
    for mode in MODES {
        for deny in [Deny::Kill, Deny::Errno] {
            let prog = build(mode, deny, &[]);
            for nr in 0..=500 {
                // Off by one, off only in the high half, off only in the low half, and nowhere.
                for ip in [GATE + 2, GATE - 2, GATE ^ (1 << 40), GATE ^ 1, 0, u64::MAX] {
                    let d = Data { nr, arch: AUDIT_ARCH_X86_64, ip, args: [0; 6] };
                    assert_eq!(check(&prog, d), SECCOMP_RET_TRAP, "{mode:?} nr {nr} ip {ip:#x}");
                }
            }
        }
    }
}

/// The routing-only filter: arch and x32 killed, everything not from the gate trapped and everything from it allowed, whatever the other parameters say.
#[test]
fn route_only() {
    let mut prog = Program::new();
    let extra = [Rule { nr: 39, conds: &[] }];
    let params = Params {
        policy: Policy::RouteOnly,
        deny: Deny::Kill,
        gate_ip: GATE,
        arena: &ARENA,
        token_fds: TOKENS,
        pid: PID,
        extra: &extra,
    };
    compile(&params, &mut prog).unwrap();
    for nr in 0..=500 {
        for args in [[0; 6], [u64::MAX; 6], [1, 2, 3, 4, 5, 6]] {
            assert_eq!(check(&prog, gate(nr, args)), ALLOW, "nr {nr} from the gate");
            let d = Data { nr, arch: AUDIT_ARCH_X86_64, ip: GATE + 2, args };
            assert_eq!(check(&prog, d), SECCOMP_RET_TRAP, "nr {nr} elsewhere");
        }
    }
    let other = Data { arch: 0x4000_0003, ..gate(1, [0; 6]) };
    assert_eq!(check(&prog, other), SECCOMP_RET_KILL_PROCESS);
    assert_eq!(check(&prog, gate(X32_SYSCALL_BIT | 1, [0; 6])), SECCOMP_RET_KILL_PROCESS);
}

#[test]
fn from_the_gate_zero_args() {
    // Which rules match all-zero arguments: read(0), exit_group, ppoll(nfds 0, no mask) in
    // every mode, and exit(0) where threads exist. write(0), madvise(0) (not an arena), clone(0)
    // and the token fds don't.
    let all = [NR_RT_SIGRETURN, NR_READ, NR_EXIT_GROUP, NR_PPOLL];
    for mode in MODES {
        let prog = build(mode, Deny::Errno, &[]);
        let mut allowed = all.to_vec();
        if mode != Mode::Coroutine {
            allowed.push(NR_EXIT);
        }
        for nr in 0..=500 {
            let want = if allowed.contains(&nr) { ALLOW } else { DENY };
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

#[test]
fn ppoll() {
    for mode in MODES {
        edges(mode, NR_PPOLL, [0; 6], 1, &[(0, 1)]);
        edges(mode, NR_PPOLL, [0, 1, 0, 0, 0, 0], 3, &[(0, 0)]);
        // The pollfd pointer, the timeout and sigsetsize are anything.
        for arg in [0, 2, 4, 5] {
            edges(mode, NR_PPOLL, [0, 1, 0, 0, 0, 0], arg, &[(0, u64::MAX)]);
        }
        let prog = build(mode, Deny::Errno, &[]);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 2, 0, 0, 0, 0])), DENY);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 1, 0, 1, 0, 0])), DENY);
        assert_eq!(check(&prog, gate(NR_PPOLL, [0, 1, 0, 1 << 32, 0, 0])), DENY);
    }
}

/// `kill` from the gate: the sandbox's own pid and a signal number, in coroutine and threaded mode
/// only (a fork mode process's pid isn't the one pinned).
#[test]
fn kill_self() {
    let ok = [PID as u64, 6, 0, 0, 0, 0];
    for mode in [Mode::Coroutine, Mode::Threaded] {
        edges(mode, NR_KILL, ok, 0, &[(PID as u64, PID as u64)]);
        edges(mode, NR_KILL, ok, 1, &[(1, 64)]);
        // The rest are anything (kill has two arguments).
        edges(mode, NR_KILL, ok, 2, &[(0, u64::MAX)]);
    }
    let prog = build(Mode::Fork, Deny::Errno, &[]);
    assert_eq!(check(&prog, gate(NR_KILL, ok)), DENY);
}

#[test]
fn madvise() {
    let ok = [ARENA[0].0, 0, MADV_DONTNEED, 0, 0, 0];
    for mode in [Mode::Coroutine] {
        edges(mode, NR_MADVISE, ok, 0, &ARENA);
        edges(mode, NR_MADVISE, ok, 1, &[(0, MADV_CHUNK)]);
        edges(mode, NR_MADVISE, ok, 2, &[(MADV_DONTNEED, MADV_DONTNEED)]);
        // The second arena too, at both ends.
        let prog = build(mode, Deny::Errno, &[]);
        for addr in [ARENA[1].0, ARENA[1].1, 1 << 32] {
            assert_eq!(check(&prog, gate(NR_MADVISE, [addr, MADV_CHUNK, 4, 0, 0, 0])), ALLOW);
        }
        assert_eq!(check(&prog, gate(NR_MADVISE, [ARENA[1].1, MADV_CHUNK + 1, 4, 0, 0, 0])), DENY);
        for advice in (0..=100).filter(|&a| a != MADV_DONTNEED) {
            assert_eq!(check(&prog, gate(NR_MADVISE, [ARENA[0].0, 4096, advice, 0, 0, 0])), DENY);
        }
    }
    // Never where there are host threads, not even inside the arena.
    for mode in [Mode::Threaded, Mode::Fork] {
        let prog = build(mode, Deny::Errno, &[]);
        for &(lo, hi) in &ARENA {
            for addr in [lo, hi] {
                assert_eq!(check(&prog, gate(NR_MADVISE, [addr, 4096, 4, 0, 0, 0])), DENY);
            }
        }
    }
    // No arena: no madvise at all.
    let mut p = Program::new();
    let params = Params {
        policy: Policy::Mode(Mode::Coroutine),
        deny: Deny::Errno,
        gate_ip: GATE,
        arena: &[],
        token_fds: TOKENS,
        pid: PID,
        extra: &[],
    };
    compile(&params, &mut p).unwrap();
    assert_eq!(check(&p, gate(NR_MADVISE, [0, 0, 4, 0, 0, 0])), DENY);
}

#[test]
fn clone_and_exit() {
    for mode in [Mode::Threaded, Mode::Fork] {
        let fork = mode == Mode::Fork;
        let clone0: &[(u64, u64)] = if fork {
            &[(CLONE_HOST_THREAD, CLONE_HOST_THREAD), (SIGCHLD, SIGCHLD)]
        } else {
            &[(CLONE_HOST_THREAD, CLONE_HOST_THREAD)]
        };
        edges(mode, NR_CLONE, [0; 6], 0, clone0);
        edges(mode, NR_EXIT, [0; 6], 0, &[(0, 0)]);
        let prog = build(mode, Deny::Errno, &[]);
        // Each flag bit added or removed: refused (in fork mode, none of these is SIGCHLD).
        for bit in 0..64 {
            let flags = CLONE_HOST_THREAD ^ (1 << bit);
            assert_eq!(check(&prog, gate(NR_CLONE, [flags, 0, 0, 0, 0, 0])), DENY, "bit {bit}");
            let flags = SIGCHLD ^ (1 << bit);
            assert_eq!(check(&prog, gate(NR_CLONE, [flags, 0, 0, 0, 0, 0])), DENY, "bit {bit}");
        }
        // The thread clone takes any stack, tid pointers and TLS argument (the flags make TLS
        // unused); the fork clone only no stack.
        edges(mode, NR_CLONE, [CLONE_HOST_THREAD, 0, 0, 0, 0, 0], 1, &[(0, u64::MAX)]);
        let fork_stack: &[(u64, u64)] = if fork { &[(0, 0)] } else { &[] };
        edges(mode, NR_CLONE, [SIGCHLD, 0, 0, 0, 0, 0], 1, fork_stack);
        assert_eq!(check(&prog, gate(NR_EXIT, [1, 0, 0, 0, 0, 0])), DENY);
    }
    let prog = build(Mode::Coroutine, Deny::Errno, &[]);
    for args in [[CLONE_HOST_THREAD, 0, 0, 0, 0, 0], [SIGCHLD, 0, 0, 0, 0, 0]] {
        assert_eq!(check(&prog, gate(NR_CLONE, args)), DENY);
    }
}

#[test]
fn exit_group_any() {
    for mode in MODES {
        let prog = build(mode, Deny::Kill, &[]);
        for v in probes(&[]) {
            assert_eq!(check(&prog, gate(NR_EXIT_GROUP, [v; 6])), ALLOW);
        }
    }
}

#[test]
fn arch_and_x32_kill() {
    for mode in MODES {
        let prog = build(mode, Deny::Errno, &[]);
        for arch in [0, 0x4000_0003 /* AUDIT_ARCH_I386 */, AUDIT_ARCH_X86_64 ^ 1] {
            for ip in [GATE, 0] {
                for nr in [NR_WRITE, NR_RT_SIGRETURN, NR_EXIT_GROUP] {
                    let d = Data { nr, arch, ip, args: [1, 0, 0, 0, 0, 0] };
                    assert_eq!(check(&prog, d), SECCOMP_RET_KILL_PROCESS);
                }
            }
        }
        for nr in [
            X32_SYSCALL_BIT,
            X32_SYSCALL_BIT | NR_WRITE,
            X32_SYSCALL_BIT | NR_RT_SIGRETURN,
            u32::MAX,
        ] {
            for ip in [GATE, 0] {
                let d = Data { nr, arch: AUDIT_ARCH_X86_64, ip, args: [1, 0, 0, 0, 0, 0] };
                assert_eq!(check(&prog, d), SECCOMP_RET_KILL_PROCESS, "nr {nr:#x}");
            }
        }
        // Just below the x32 bit: an ordinary (unknown) number.
        assert_eq!(check(&prog, gate(X32_SYSCALL_BIT - 1, [0; 6])), DENY);
    }
}

#[test]
fn deny_kill_or_errno() {
    for mode in MODES {
        let kill = build(mode, Deny::Kill, &[]);
        let errno = build(mode, Deny::Errno, &[]);
        for (nr, args) in [(110 /* getppid */, [0; 6]), (NR_WRITE, [3, 0, 0, 0, 0, 0])] {
            assert_eq!(check(&kill, gate(nr, args)), SECCOMP_RET_KILL_PROCESS);
            assert_eq!(check(&errno, gate(nr, args)), SECCOMP_RET_ERRNO | 1);
        }
        assert_eq!(check(&kill, gate(NR_WRITE, [1, 0, 0, 0, 0, 0])), ALLOW);
    }
}

#[test]
fn extra_rules() {
    const GETPPID: u32 = 110;
    const IOCTL: u32 = 16;
    let span = [Cond { arg: 2, lo: 0xffff_fff0, hi: 0x1_0000_0010 }];
    let multi = [
        Cond { arg: 0, lo: 5, hi: 5 },
        Cond { arg: 1, lo: 0x5400, hi: 0x54ff },
        Cond { arg: 5, lo: 1 << 40, hi: (1 << 41) + 5 },
    ];
    let extra = [
        Rule { nr: GETPPID, conds: &span },
        Rule { nr: IOCTL, conds: &multi },
        Rule { nr: 39 /* getpid */, conds: &[] },
    ];
    for mode in MODES {
        let prog = build(mode, Deny::Errno, &extra);
        for v in probes(&[(0xffff_fff0, 0x1_0000_0010)]) {
            let want = if (0xffff_fff0..=0x1_0000_0010).contains(&v) { ALLOW } else { DENY };
            assert_eq!(check(&prog, gate(GETPPID, [0, 0, v, 0, 0, 0])), want, "{v:#x}");
        }
        let ok = [5, 0x5400, 0, 0, 0, 1 << 40];
        assert_eq!(check(&prog, gate(IOCTL, ok)), ALLOW);
        assert_eq!(check(&prog, gate(IOCTL, [5, 0x54ff, 7, 7, 7, (1 << 41) + 5])), ALLOW);
        // Each condition failing alone refuses.
        for (arg, bad) in [
            (0, 4),
            (0, 5 | 1 << 32),
            (1, 0x5500),
            (1, 0x53ff),
            (5, (1 << 40) - 1),
            (5, (1 << 41) + 6),
        ] {
            let mut a = ok;
            a[arg] = bad;
            assert_eq!(check(&prog, gate(IOCTL, a)), DENY, "arg{arg} = {bad:#x}");
        }
        for v in probes(&[]) {
            assert_eq!(check(&prog, gate(39, [v; 6])), ALLOW);
        }
        // Rules don't leak into each other: ioctl's conditions don't allow getppid.
        assert_eq!(check(&prog, gate(GETPPID, ok)), DENY);
    }
}

/// `lo <= x <= hi` as the compiled program decides it, against Rust's, for one range.
fn range_matches_oracle(lo: u64, hi: u64, extra_probes: &[u64]) {
    let cond = [Cond { arg: 3, lo, hi }];
    let prog = build(Mode::Coroutine, Deny::Errno, &[Rule { nr: 110, conds: &cond }]);
    let mut vals = probes(&[(lo, hi)]);
    vals.extend_from_slice(extra_probes);
    for v in vals {
        let want = if lo <= v && v <= hi { ALLOW } else { DENY };
        let got = check(&prog, gate(110, [0, 0, 0, v, 0, 0]));
        assert_eq!(got, want, "{lo:#x}..={hi:#x}: {v:#x}");
    }
}

/// Halves at their edges: every case the emitter distinguishes (lo == hi, same high half, lo 0,
/// hi max, a low half of 0, 1, max - 1 or max at either end), every range of these, every value.
const HALF_EDGES: [u32; 6] = [0, 1, 0x7fff_ffff, 0x8000_0000, 0xffff_fffe, 0xffff_ffff];

#[test]
fn ranges_on_half_edges() {
    let vals: Vec<u64> = HALF_EDGES
        .iter()
        .flat_map(|&h| HALF_EDGES.iter().map(move |&l| (h as u64) << 32 | l as u64))
        .collect();
    for &lo in &vals {
        for &hi in vals.iter().filter(|&&hi| hi >= lo) {
            range_matches_oracle(lo, hi, &vals);
        }
    }
}

/// And random ranges built from random and edge halves, for what the edges miss.
#[test]
fn ranges_at_random() {
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let half = |r: u64| match r % 3 {
        0 => HALF_EDGES[(r >> 8) as usize % HALF_EDGES.len()],
        1 => (r >> 32) as u32 & 0xff,
        _ => (r >> 32) as u32,
    };
    let pick = |rand: &mut dyn FnMut() -> u64| (half(rand()) as u64) << 32 | half(rand()) as u64;
    for _ in 0..2000 {
        let (a, mut b) = (pick(&mut rand), pick(&mut rand));
        if rand() % 4 == 0 {
            b = a & 0xffff_ffff_0000_0000 | b & 0xffff_ffff; // the same high half
        }
        let extra: Vec<u64> = (0..8).map(|_| pick(&mut rand)).collect();
        range_matches_oracle(a.min(b), a.max(b), &extra);
    }
}

#[test]
fn errors() {
    let mut p = Program::new();
    let with = |extra: &[Rule], token_fds, arena: &[(u64, u64)], p: &mut Program| {
        let params = Params {
            policy: Policy::Mode(Mode::Threaded),
            deny: Deny::Kill,
            gate_ip: GATE,
            arena,
            token_fds,
            pid: PID,
            extra,
        };
        compile(&params, p)
    };
    let c = |arg, lo, hi| Cond { arg, lo, hi };
    assert_eq!(
        with(&[Rule { nr: 1, conds: &[c(0, 2, 1)] }], TOKENS, &ARENA, &mut p),
        Err(Error::EmptyRange)
    );
    assert_eq!(
        with(&[Rule { nr: 1, conds: &[c(6, 0, 1)] }], TOKENS, &ARENA, &mut p),
        Err(Error::NoSuchArg)
    );
    assert_eq!(
        with(&[Rule { nr: 1, conds: &[c(0, 0, 1); 7] }], TOKENS, &ARENA, &mut p),
        Err(Error::TooManyConds)
    );
    assert_eq!(with(&[], (5, 4), &ARENA, &mut p), Err(Error::EmptyRange));
    assert_eq!(with(&[], TOKENS, &[(5, 4)], &mut p), Err(Error::EmptyRange));
    // The longest rules (six general 64-bit ranges), more than fit.
    let conds: Vec<Cond> = (0..6).map(|i| c(i, 0x1_0000_0001, 0x2_0000_0000)).collect();
    let rules: Vec<Rule> = (0..100).map(|nr| Rule { nr, conds: &conds }).collect();
    assert_eq!(with(&rules, TOKENS, &ARENA, &mut p), Err(Error::TooLong));
    // As many as fit is fine, and every jump stays inside one rule's reach.
    assert_eq!(with(&rules[..60], TOKENS, &ARENA, &mut p), Ok(()));
    assert!(p.as_slice().len() <= MAX_INSNS);
}

/// Structure the kernel's checker requires: forward jumps in bounds, ending in RET.
#[test]
fn well_formed() {
    for mode in MODES {
        let prog = build(mode, Deny::Kill, &[]);
        let s = prog.as_slice();
        assert_eq!(s.last().unwrap().code, RET_K);
        for (i, ins) in s.iter().enumerate() {
            if matches!(ins.code, JEQ_K | JGT_K | JGE_K) {
                assert!(i + 1 + (ins.jt.max(ins.jf) as usize) < s.len(), "{mode:?} insn {i}");
            }
        }
        eprintln!("{mode:?}: {} instructions", s.len());
    }
}

// The real kernel: a gate of our own (`syscall; ret`) whose post-syscall address is gate_ip.
core::arch::global_asm!(
    ".globl exobox_rt_filter_test_gate",
    ".globl exobox_rt_filter_test_gate_ret",
    "exobox_rt_filter_test_gate:",
    "mov rax, rdi",
    "mov rdi, rsi",
    "mov rsi, rdx",
    "mov rdx, rcx",
    "syscall",
    "exobox_rt_filter_test_gate_ret:",
    "ret",
);

unsafe extern "C" {
    fn exobox_rt_filter_test_gate(nr: usize, a0: usize, a1: usize, a2: usize) -> isize;
    static exobox_rt_filter_test_gate_ret: u8;
}

/// Install each mode's filter (deny = errno) in a forked child: through the gate, a permitted
/// write succeeds and getppid is EPERM. The child makes no syscall outside the gate after
/// install (it has no SIGSYS handler) and reports through exit_group's status.
#[test]
fn installs_in_the_kernel() {
    let gate_ip = &raw const exobox_rt_filter_test_gate_ret as u64;
    for mode in MODES {
        let mut prog = Program::new();
        let params = Params {
            policy: Policy::Mode(mode),
            deny: Deny::Errno,
            gate_ip,
            arena: &ARENA,
            token_fds: TOKENS,
        pid: PID,
            extra: &[],
        };
        compile(&params, &mut prog).unwrap();
        // SAFETY: the child only calls install and the gate, then exits through the gate.
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let status = match install(&prog, 0) {
                Err(_) => 10,
                Ok(()) => unsafe {
                    let empty = b"";
                    if exobox_rt_filter_test_gate(NR_WRITE as usize, 1, empty.as_ptr() as usize, 0)
                        != 0
                    {
                        11
                    } else if exobox_rt_filter_test_gate(110, 0, 0, 0) != -1 {
                        12 // getppid: -EPERM
                    } else if exobox_rt_filter_test_gate(
                        NR_WRITE as usize,
                        3,
                        empty.as_ptr() as usize,
                        0,
                    ) != -1
                    {
                        13
                    } else {
                        0
                    }
                },
            };
            unsafe { exobox_rt_filter_test_gate(NR_EXIT_GROUP as usize, status, 0, 0) };
            unreachable!();
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status), "{mode:?}: child status {status:#x}");
        assert_eq!(libc::WEXITSTATUS(status), 0, "{mode:?}");
    }
}

/// The two filters stacked, as the sandbox installs them (the module comment): with the routing one
/// alone a gate call outside every mode list (getppid) is allowed; once the coroutine mode's filter
/// is stacked on it, the same call is refused (deny = errno) while the mode's own calls still pass.
/// Through `trap::gate`, which `install` itself uses, so the second install passes the first filter.
#[test]
fn stacked_filters_in_the_kernel() {
    let gate_ip = crate::trap::gate_ip();
    let params = |policy| Params { policy, deny: Deny::Errno, gate_ip, arena: &ARENA, token_fds: TOKENS, pid: PID, extra: &[] };
    let (mut route, mut mode) = (Program::new(), Program::new());
    compile(&params(Policy::RouteOnly), &mut route).unwrap();
    compile(&params(Policy::Mode(Mode::Coroutine)), &mut mode).unwrap();
    let g = |nr: u32, a0: usize| unsafe { crate::trap::gate(nr as usize, a0, b"".as_ptr() as usize, 0, 0, 0, 0) };
    // SAFETY: the child only calls install and the gate, then exits through the gate.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        let status = if install(&route, 0).is_err() {
            10
        } else if g(110, 0) <= 0 {
            11 // getppid allowed: the parent's pid
        } else if install(&mode, 0).is_err() {
            12
        } else if g(110, 0) != -1 {
            13 // now EPERM
        } else if g(NR_WRITE, 1) != 0 {
            14
        } else {
            0
        };
        g(NR_EXIT_GROUP, status);
        unreachable!();
    }
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
    assert!(libc::WIFEXITED(status), "child status {status:#x}");
    assert_eq!(libc::WEXITSTATUS(status), 0);
}
