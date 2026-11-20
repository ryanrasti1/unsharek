//! Classic BPF as the kernel's seccomp runs it: `seccomp_data`'s layout (libc's), the opcodes
//! (libc's), [`run_bpf`] and the checks the kernel makes before it takes a program. The proof
//! trusts this file; `tests/kernel.rs` checks it against Linux.

use core::mem::{offset_of, size_of};
use libc::{seccomp_data as SeccompData, sock_filter as SockFilter};

/// Offsets in `seccomp_data`, libc's: of a 64-bit field's low and high halves, as the target's
/// byte order puts them.
const fn halves(off: usize) -> (u32, u32) {
    let (lo, hi) = if cfg!(target_endian = "little") { (off, off + 4) } else { (off + 4, off) };
    (lo as u32, hi as u32)
}
const OFF_NR: u32 = offset_of!(libc::seccomp_data, nr) as u32;
const OFF_ARCH: u32 = offset_of!(libc::seccomp_data, arch) as u32;
const OFF_IP: (u32, u32) = halves(offset_of!(libc::seccomp_data, instruction_pointer));
const fn off_arg(i: usize) -> (u32, u32) {
    halves(offset_of!(libc::seccomp_data, args) + i * size_of::<u64>())
}
const DATA_LEN: u32 = size_of::<libc::seccomp_data>() as u32;

// Classic BPF's opcodes, libc's (include/uapi/linux/bpf_common.h, filter.h), combined as the
// kernel's macros combine them. The masks are bpf_common.h's BPF_CLASS, BPF_MODE, BPF_OP,
// BPF_SRC, BPF_RVAL and BPF_MISCOP, which libc doesn't have.
const CLASS: u16 = 0x07;
const MODE: u16 = 0xe0;
const OP: u16 = 0xf0;
const SRC: u16 = 0x08;
const RVAL: u16 = 0x18;
const MISCOP: u16 = 0xf8;
use libc::{
    BPF_A, BPF_ABS, BPF_ADD, BPF_ALU, BPF_AND, BPF_DIV, BPF_IMM, BPF_JA, BPF_JEQ, BPF_JGE, BPF_JGT, BPF_JMP, BPF_JSET,
    BPF_K, BPF_LD, BPF_LDX, BPF_LEN, BPF_LSH, BPF_MEM, BPF_MISC, BPF_MUL, BPF_NEG, BPF_OR, BPF_RET, BPF_RSH, BPF_ST,
    BPF_STX, BPF_SUB, BPF_TAX, BPF_TXA, BPF_W, BPF_X, BPF_XOR,
};
const fn op(c: u32) -> u16 {
    c as u16
}
const fn alu(o: u32, src: u32) -> u16 {
    op(BPF_ALU | o | src)
}
const fn jmp(o: u32, src: u32) -> u16 {
    op(BPF_JMP | o | src)
}
const LD: u16 = op(BPF_LD);
const LDX: u16 = op(BPF_LDX);
const ST: u16 = op(BPF_ST);
const STX: u16 = op(BPF_STX);
const ALU: u16 = op(BPF_ALU);
const JMP: u16 = op(BPF_JMP);
const RET: u16 = op(BPF_RET);
const X: u16 = op(BPF_X);
const A: u16 = op(BPF_A);
const LD_W_ABS: u16 = op(BPF_LD | BPF_W | BPF_ABS);
const LD_W_IMM: u16 = op(BPF_LD | BPF_W | BPF_IMM);
const LDX_W_IMM: u16 = op(BPF_LDX | BPF_W | BPF_IMM);
const LD_W_LEN: u16 = op(BPF_LD | BPF_W | BPF_LEN);
const LDX_W_LEN: u16 = op(BPF_LDX | BPF_W | BPF_LEN);
const LD_MEM: u16 = op(BPF_LD | BPF_W | BPF_MEM);
const LDX_MEM: u16 = op(BPF_LDX | BPF_W | BPF_MEM);
// ALU by K or X; JEQ JGT JGE JSET by K or X. (Named one by one: `check` matches them without a
// loop, which keeps Kani's model of it small.)
const ADD_K: u16 = alu(BPF_ADD, BPF_K);
const SUB_K: u16 = alu(BPF_SUB, BPF_K);
const MUL_K: u16 = alu(BPF_MUL, BPF_K);
const OR_K: u16 = alu(BPF_OR, BPF_K);
const AND_K: u16 = alu(BPF_AND, BPF_K);
const XOR_K: u16 = alu(BPF_XOR, BPF_K);
const DIV_K: u16 = alu(BPF_DIV, BPF_K);
const LSH_K: u16 = alu(BPF_LSH, BPF_K);
const RSH_K: u16 = alu(BPF_RSH, BPF_K);
const ADD_X: u16 = alu(BPF_ADD, BPF_X);
const SUB_X: u16 = alu(BPF_SUB, BPF_X);
const MUL_X: u16 = alu(BPF_MUL, BPF_X);
const OR_X: u16 = alu(BPF_OR, BPF_X);
const AND_X: u16 = alu(BPF_AND, BPF_X);
const XOR_X: u16 = alu(BPF_XOR, BPF_X);
const DIV_X: u16 = alu(BPF_DIV, BPF_X);
const LSH_X: u16 = alu(BPF_LSH, BPF_X);
const RSH_X: u16 = alu(BPF_RSH, BPF_X);
const NEG: u16 = op(BPF_ALU | BPF_NEG);
const JA: u16 = op(BPF_JMP | BPF_JA);
const JEQ_K: u16 = jmp(BPF_JEQ, BPF_K);
const JGT_K: u16 = jmp(BPF_JGT, BPF_K);
const JGE_K: u16 = jmp(BPF_JGE, BPF_K);
const JSET_K: u16 = jmp(BPF_JSET, BPF_K);
const JEQ_X: u16 = jmp(BPF_JEQ, BPF_X);
const JGT_X: u16 = jmp(BPF_JGT, BPF_X);
const JGE_X: u16 = jmp(BPF_JGE, BPF_X);
const JSET_X: u16 = jmp(BPF_JSET, BPF_X);
const RET_K: u16 = op(BPF_RET | BPF_K);
const RET_A: u16 = op(BPF_RET | BPF_A);
const TAX: u16 = op(BPF_MISC | BPF_TAX);
const TXA: u16 = op(BPF_MISC | BPF_TXA);
/// Scratch memory's words (BPF_MEMWORDS).
const MEMWORDS: usize = libc::BPF_MEMWORDS as usize;
/// The kernel's limit on a program's length (BPF_MAXINSNS).
pub const MAX_INSNS: usize = libc::BPF_MAXINSNS as usize;

/// `prog`'s verdict on `d`, as seccomp computes it: classic BPF (Documentation/networking/
/// filter.rst) with seccomp's restrictions (kernel/seccomp.c `seccomp_check_filter`: loads are
/// 32-bit words of `seccomp_data`, at aligned offsets; no packet loads; LEN is its size).
///
/// A program the kernel would refuse to install panics: empty or too long, an opcode seccomp
/// doesn't take, a jump out of the program, a load out of `seccomp_data`, a division by a
/// constant 0 or a shift by 32 or more, a scratch slot past the last, or a last instruction that
/// isn't a return (net/core/filter.c `bpf_check_classic`). So a proof that calls this also
/// proves the kernel takes the program.
pub fn run_bpf(prog: &[SockFilter], d: &SeccompData) -> u32 {
    check(prog);
    run(prog, d)
}

/// [`run_bpf`] of a program already checked. Seccomp's jumps go only forward, so one pass over
/// the instructions, in order, runs it: an instruction runs if it is where control is (`pc`),
/// and is passed over if a jump went past it. (A model checker then sees each instruction at a
/// known index, and one machine state, which keeps the proof small.)
fn run(prog: &[SockFilter], d: &SeccompData) -> u32 {
    let (mut pc, mut s) = (0, State { a: 0, x: 0, mem: [0; MEMWORDS] });
    for (i, &ins) in prog.iter().enumerate() {
        if pc != i {
            continue;
        }
        match step(&mut s, ins, d) {
            Step::Next(skip) => pc = i + 1 + skip,
            Step::Return(v) => return v,
        }
    }
    unreachable!("check(): the last instruction is a return")
}

/// Classic BPF's machine: the accumulator, the index register, scratch memory.
#[derive(Clone, Copy)]
struct State {
    a: u32,
    x: u32,
    mem: [u32; MEMWORDS],
}

/// What an instruction does: on to the next one but `skip`, or the program's verdict.
enum Step {
    Next(usize),
    Return(u32),
}

/// One instruction, run on `s`.
fn step(s: &mut State, SockFilter { code, jt, jf, k }: SockFilter, d: &SeccompData) -> Step {
    // the 32-bit word at `off`, by libc's layout (`check` allows only aligned words inside it,
    // each a field's or a half of one's)
    let word = |off: u32| -> u32 {
        let (v, (lo, _)) = match off {
            OFF_NR => return d.nr as u32,
            OFF_ARCH => return d.arch,
            _ if off == OFF_IP.0 || off == OFF_IP.1 => (d.instruction_pointer, OFF_IP),
            _ => {
                let i = ((off - off_arg(0).0.min(off_arg(0).1)) / 8) as usize;
                (d.args[i], off_arg(i))
            }
        };
        if off == lo { v as u32 } else { (v >> 32) as u32 }
    };
    let src = if code & SRC == X { s.x } else { k };
    match code & CLASS {
        LD | LDX => {
            let v = match (code & MODE) as u32 {
                BPF_IMM => k,
                BPF_ABS => word(k),
                BPF_MEM => s.mem[k as usize],
                _ => DATA_LEN, // BPF_LEN: sizeof(struct seccomp_data)
            };
            if code & CLASS == LD { s.a = v } else { s.x = v }
        }
        ST => s.mem[k as usize] = s.a,
        STX => s.mem[k as usize] = s.x,
        ALU => {
            s.a = match (code & OP) as u32 {
                BPF_ADD => s.a.wrapping_add(src),
                BPF_SUB => s.a.wrapping_sub(src),
                BPF_MUL => s.a.wrapping_mul(src),
                // a division by X == 0 ends the program with 0 (net/core/filter.c)
                BPF_DIV if src == 0 => return Step::Return(0),
                BPF_DIV => s.a / src,
                BPF_OR => s.a | src,
                BPF_AND => s.a & src,
                // a shift by X of 32 or more: x86's, modulo 32 (a constant one is refused)
                BPF_LSH => s.a.wrapping_shl(src),
                BPF_RSH => s.a.wrapping_shr(src),
                BPF_NEG => s.a.wrapping_neg(),
                _ => s.a ^ src, // BPF_XOR
            }
        }
        JMP => {
            let skip = match (code & OP) as u32 {
                BPF_JA => k as usize,
                o => {
                    let taken = match o {
                        BPF_JEQ => s.a == src,
                        BPF_JGT => s.a > src,
                        BPF_JGE => s.a >= src,
                        _ => s.a & src != 0, // BPF_JSET
                    };
                    (if taken { jt } else { jf }) as usize
                }
            };
            return Step::Next(skip);
        }
        RET => return Step::Return(if code & RVAL == A { s.a } else { k }),
        _ => if (code & MISCOP) as u32 == BPF_TAX { s.x = s.a } else { s.a = s.x },
    }
    Step::Next(0)
}

/// The checks the kernel makes before it takes a program (`bpf_check_classic`,
/// `seccomp_check_filter`'s list of opcodes): panics on the first it fails.
fn check(prog: &[SockFilter]) {
    assert!(!prog.is_empty() && prog.len() <= MAX_INSNS, "{} instructions", prog.len());
    for (pc, &SockFilter { code, jt, jf, k }) in prog.iter().enumerate() {
        let left = prog.len() - pc - 1;
        let mem = (k as usize) < MEMWORDS;
        let ok = match code {
            // seccomp_check_filter: inside seccomp_data, aligned (every such word is a field's)
            LD_W_ABS => k % 4 == 0 && k < DATA_LEN,
            LD_W_IMM | LDX_W_IMM | LD_W_LEN | LDX_W_LEN => true,
            LD_MEM | LDX_MEM => mem,
            _ if code == ST || code == STX => mem,
            ADD_K | SUB_K | MUL_K | OR_K | AND_K | XOR_K | NEG => true,
            ADD_X | SUB_X | MUL_X | OR_X | AND_X | XOR_X | DIV_X | LSH_X | RSH_X => true,
            DIV_K => k != 0,
            LSH_K | RSH_K => k < 32,
            JA => (k as usize) < left,
            JEQ_K | JGT_K | JGE_K | JSET_K | JEQ_X | JGT_X | JGE_X | JSET_X => (jt as usize) < left && (jf as usize) < left,
            RET_K | RET_A | TAX | TXA => true,
            _ => false,
        };
        assert!(ok, "instruction {pc} the kernel refuses: {code:#x}");
    }
    let last = prog[prog.len() - 1].code;
    assert!(last == RET_K || last == RET_A, "the last instruction isn't a return");
}

