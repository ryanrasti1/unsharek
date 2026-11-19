//! A seccomp filter written as a plain Rust function, compiled to classic BPF by `#[seccomp]`,
//! and proven by Kani to give the function's verdict on every input.
//!
//! See README.md: the claim, the subset, the review checklist.
//!
//! What is trusted: [`run_bpf`] (classic BPF as the kernel runs it, short enough to read, and
//! checked against the kernel by `tests/kernel.rs`), Kani, and rustc. The macro and [`Builder`]
//! are not: the proof the macro emits (`<name>_is_its_bpf`, under `cfg(kani)`) checks what they
//! built, for every `SeccompData` and every parameter.

pub use seccomp_fn_macros::seccomp;

// The macro's code names `::seccomp_fn`, here too.
extern crate self as seccomp_fn;

pub mod examples;

/// Outside the subset: each a compile error naming the construct.
///
/// A call on `d`:
/// ```compile_fail
/// # use seccomp_fn::*;
/// #[seccomp]
/// fn f(d: &SeccompData) -> u32 { if [0u64, 1].contains(&d.args[0]) { return 1; } 0 }
/// ```
/// A call on `d` in a match guard:
/// ```compile_fail
/// # use seccomp_fn::*;
/// #[seccomp]
/// fn f(d: &SeccompData) -> u32 { match d.nr { 1 if d.args.iter().any(|&a| a == 0) => 1, _ => 0 } }
/// ```
/// A signed param (BPF compares unsigned):
/// ```compile_fail
/// # use seccomp_fn::*;
/// #[seccomp]
/// fn f(d: &SeccompData, x: i64) -> u32 { if d.args[0] == x as u64 { return 1; } 0 }
/// ```
/// A signed value compared with a field:
/// ```compile_fail
/// # use seccomp_fn::*;
/// const X: i64 = 5;
/// #[seccomp]
/// fn f(d: &SeccompData) -> u32 { if d.args[0] == X as u64 && d.args[1] == X { return 1; } 0 }
/// ```
/// A loop:
/// ```compile_fail
/// # use seccomp_fn::*;
/// #[seccomp]
/// fn f(d: &SeccompData) -> u32 { for i in 0..6 { if d.args[i] == 0 { return 1; } } 0 }
/// ```
/// And the same function within the subset compiles:
/// ```
/// # use seccomp_fn::*;
/// #[seccomp]
/// fn f(d: &SeccompData, x: u64) -> u32 { match d.nr { 1 if d.args[0] == x => 1, _ => 0 } }
/// ```
pub mod subset {}

/// `struct seccomp_data` (include/uapi/linux/seccomp.h): what a filter sees of a syscall. libc's
/// `seccomp_data`'s layout, checked below; not libc's type itself, because BPF reads `nr` as an
/// unsigned word (libc's is `c_int`: a policy's `match d.nr` would compare signed), and Kani
/// needs an `Arbitrary` for it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[cfg_attr(kani, derive(kani::Arbitrary))]
pub struct SeccompData {
    pub nr: u32,
    pub arch: u32,
    pub instruction_pointer: u64,
    pub args: [u64; 6],
}

use core::mem::{offset_of, size_of};
const _: () = {
    assert!(size_of::<SeccompData>() == size_of::<libc::seccomp_data>());
    assert!(offset_of!(SeccompData, nr) == offset_of!(libc::seccomp_data, nr));
    assert!(offset_of!(SeccompData, arch) == offset_of!(libc::seccomp_data, arch));
    assert!(offset_of!(SeccompData, instruction_pointer) == offset_of!(libc::seccomp_data, instruction_pointer));
    assert!(offset_of!(SeccompData, args) == offset_of!(libc::seccomp_data, args));
};

/// One classic-BPF instruction: libc's `struct sock_filter` (include/uapi/linux/filter.h).
pub type SockFilter = libc::sock_filter;

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

/// [`run_bpf`] of a program already checked.
fn run(prog: &[SockFilter], d: &SeccompData) -> u32 {
    // the 32-bit word at `off`, by libc's layout (`check` allows only aligned words inside it,
    // each a field's or a half of one's)
    let word = |off: u32| -> u32 {
        let (v, (lo, _)) = match off {
            OFF_NR => return d.nr,
            OFF_ARCH => return d.arch,
            _ if off == OFF_IP.0 || off == OFF_IP.1 => (d.instruction_pointer, OFF_IP),
            _ => {
                let i = ((off - off_arg(0).0.min(off_arg(0).1)) / 8) as usize;
                (d.args[i], off_arg(i))
            }
        };
        if off == lo { v as u32 } else { (v >> 32) as u32 }
    };
    let (mut a, mut x, mut mem) = (0u32, 0u32, [0u32; MEMWORDS]);
    let mut pc = 0usize;
    loop {
        let SockFilter { code, jt, jf, k } = prog[pc];
        pc += 1;
        let src = if code & SRC == X { x } else { k };
        match code & CLASS {
            LD | LDX => {
                let v = match (code & MODE) as u32 {
                    BPF_IMM => k,
                    BPF_ABS => word(k),
                    BPF_MEM => mem[k as usize],
                    _ => DATA_LEN, // BPF_LEN: sizeof(struct seccomp_data)
                };
                if code & CLASS == LD { a = v } else { x = v }
            }
            ST => mem[k as usize] = a,
            STX => mem[k as usize] = x,
            ALU => {
                a = match (code & OP) as u32 {
                    BPF_ADD => a.wrapping_add(src),
                    BPF_SUB => a.wrapping_sub(src),
                    BPF_MUL => a.wrapping_mul(src),
                    // a division by X == 0 ends the program with 0 (net/core/filter.c)
                    BPF_DIV if src == 0 => return 0,
                    BPF_DIV => a / src,
                    BPF_OR => a | src,
                    BPF_AND => a & src,
                    // a shift by X of 32 or more: x86's, modulo 32 (a constant one is refused)
                    BPF_LSH => a.wrapping_shl(src),
                    BPF_RSH => a.wrapping_shr(src),
                    BPF_NEG => a.wrapping_neg(),
                    _ => a ^ src, // BPF_XOR
                }
            }
            JMP => {
                pc += match (code & OP) as u32 {
                    BPF_JA => k as usize,
                    o => {
                        let taken = match o {
                            BPF_JEQ => a == src,
                            BPF_JGT => a > src,
                            BPF_JGE => a >= src,
                            _ => a & src != 0, // BPF_JSET
                        };
                        (if taken { jt } else { jf }) as usize
                    }
                }
            }
            RET => return if code & RVAL == A { a } else { k },
            _ => if (code & MISCOP) as u32 == BPF_TAX { x = a } else { a = x },
        }
    }
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

/// Why [`install`] failed.
#[derive(Debug)]
pub enum InstallError {
    /// More than the kernel takes.
    TooLong(usize),
    /// `seccomp(2)` failed.
    Os(std::io::Error),
    /// With TSYNC: a thread that couldn't be synced (its tid).
    Thread(i32),
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InstallError::TooLong(n) => write!(f, "{n} instructions, more than the kernel takes"),
            InstallError::Os(e) => write!(f, "seccomp: {e}"),
            InstallError::Thread(t) => write!(f, "thread {t} couldn't be synced to the filter"),
        }
    }
}

impl std::error::Error for InstallError {}

/// `prog` installed on the calling thread (`SECCOMP_SET_MODE_FILTER`), or with `tsync` on every
/// thread of the process. Unprivileged, the thread needs `no_new_privs` first.
pub fn install(prog: &[SockFilter], tsync: bool) -> Result<(), InstallError> {
    let len = u16::try_from(prog.len()).map_err(|_| InstallError::TooLong(prog.len()))?;
    // the kernel only reads the instructions
    let fprog = libc::sock_fprog { len, filter: prog.as_ptr() as *mut SockFilter };
    let flags = if tsync { libc::SECCOMP_FILTER_FLAG_TSYNC } else { 0 };
    // SAFETY: seccomp reads `fprog` and the instructions, both live for the call.
    let r = unsafe { libc::syscall(libc::SYS_seccomp, libc::SECCOMP_SET_MODE_FILTER, flags, &fprog as *const libc::sock_fprog) };
    if r < 0 {
        return Err(InstallError::Os(std::io::Error::last_os_error()));
    }
    // With TSYNC, a positive result is the id of a thread that couldn't be synced.
    if r != 0 {
        return Err(InstallError::Thread(r as i32));
    }
    Ok(())
}

/// A field of [`SeccompData`] a program compares.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Field {
    Nr,
    Arch,
    InstructionPointer,
    Arg(usize),
}

impl Field {
    /// Its words' offsets in `seccomp_data`, libc's: (low, high); a 32-bit field's are the same.
    fn offsets(self) -> (u32, u32) {
        match self {
            Field::Nr => (OFF_NR, OFF_NR),
            Field::Arch => (OFF_ARCH, OFF_ARCH),
            Field::InstructionPointer => OFF_IP,
            Field::Arg(i) => off_arg(i),
        }
    }

    pub fn wide(self) -> bool {
        matches!(self, Field::InstructionPointer | Field::Arg(_))
    }

    pub fn set(self, d: &mut SeccompData, v: u64) {
        match self {
            Field::Nr => d.nr = v as u32,
            Field::Arch => d.arch = v as u32,
            Field::InstructionPointer => d.instruction_pointer = v,
            Field::Arg(i) => d.args[i] = v,
        }
    }
}

/// A comparison of a field with a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cmp {
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
}

/// Where a jump goes: an instruction already emitted, counted from the program's end.
pub type Label = usize;

/// The macro's code generator. A program is emitted backwards, from its last instruction: every
/// jump is forward, so its targets are already emitted and its offsets known as it is written.
/// One fixed template per construct, no optimisation. Not trusted: the proof checks its output.
#[derive(Default)]
pub struct Builder {
    rev: Vec<SockFilter>,
    /// Every comparison's field and value, for the sampled check ([`samples`]); not kept under
    /// Kani, which needn't them.
    pub constants: Vec<(Field, u64)>,
}

impl Builder {
    /// A builder for a program of at most `n` instructions (the macro's bound): its storage
    /// is never reallocated, which keeps Kani's model of it small.
    pub fn with_capacity(n: usize) -> Self {
        Builder { rev: Vec::with_capacity(n), constants: Vec::new() }
    }

    fn push(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> Label {
        self.rev.push(SockFilter { code, jt, jf, k });
        self.rev.len()
    }

    /// `return k`.
    pub fn ret(&mut self, k: u32) -> Label {
        self.push(RET_K, 0, 0, k)
    }

    /// The offset of a jump written next to `to`.
    fn dist(&self, to: Label) -> usize {
        self.rev.len() - to
    }

    /// A conditional jump on A: a target over 255 instructions away is reached through a JA.
    fn jump(&mut self, op: u32, k: u32, t: Label, f: Label) -> Label {
        let t = if self.dist(t) > 255 { self.push(JA, 0, 0, self.dist(t) as u32) } else { t };
        let f = if self.dist(f) > 255 { self.push(JA, 0, 0, self.dist(f) as u32) } else { f };
        self.push(jmp(op, BPF_K), self.dist(t) as u8, self.dist(f) as u8, k)
    }

    fn load(&mut self, off: u32) -> Label {
        self.push(LD_W_ABS, 0, 0, off)
    }

    /// `field <cmp> v`: to `t` if it holds, else `f`. A 64-bit field compares its high half,
    /// then its low half.
    pub fn cmp(&mut self, field: Field, cmp: Cmp, v: u64, t: Label, f: Label) -> Label {
        #[cfg(not(kani))]
        self.constants.push((field, v));
        // Ne, Lt and Le are Eq, Ge and Gt with the targets swapped.
        let (op, t, f) = match cmp {
            Cmp::Eq => (BPF_JEQ, t, f),
            Cmp::Ne => (BPF_JEQ, f, t),
            Cmp::Gt => (BPF_JGT, t, f),
            Cmp::Le => (BPF_JGT, f, t),
            Cmp::Ge => (BPF_JGE, t, f),
            Cmp::Lt => (BPF_JGE, f, t),
        };
        let (off_lo, off_hi) = field.offsets();
        if !field.wide() {
            self.jump(op, v as u32, t, f);
            return self.load(off_lo);
        }
        let (hi, lo) = ((v >> 32) as u32, v as u32);
        self.jump(op, lo, t, f);
        let low = self.load(off_lo);
        if op == BPF_JEQ {
            // the high halves differ: not equal
            self.jump(BPF_JEQ, hi, low, f);
        } else {
            // high above: holds; high below: doesn't; equal: the low halves decide
            let eq = self.jump(BPF_JEQ, hi, low, f);
            self.jump(BPF_JGT, hi, t, eq);
        }
        self.load(off_hi)
    }

    /// `nr` one of `nrs`: one load, then a JEQ per number, in order; to `t` on the first that
    /// matches, else `f`.
    pub fn nr_in(&mut self, nrs: &[u32], t: Label, f: Label) -> Label {
        let mut next = f;
        for &nr in nrs.iter().rev() {
            #[cfg(not(kani))]
            self.constants.push((Field::Nr, nr as u64));
            next = self.jump(BPF_JEQ, nr, t, next);
        }
        let _ = next;
        self.load(OFF_NR)
    }

    /// The program, first instruction first.
    pub fn finish(mut self) -> Vec<SockFilter> {
        self.rev.reverse();
        self.rev
    }
}

/// Values around each constant a field is compared with: the constant, one either side, and,
/// for a 64-bit field, the constant with its high half changed or its halves swapped; and each
/// field's extremes.
pub fn samples(constants: &[(Field, u64)]) -> Vec<(Field, Vec<u64>, Vec<u64>)> {
    let mut fields = vec![Field::Nr, Field::Arch, Field::InstructionPointer];
    fields.extend((0..6).map(Field::Arg));
    fields
        .into_iter()
        .map(|f| {
            let exact: Vec<u64> = constants.iter().filter(|c| c.0 == f).map(|c| c.1).collect();
            let mut near = vec![0, u64::MAX, 1 << 32, 1 << 63, u32::MAX as u64];
            for &c in &exact {
                near.extend([c, c.wrapping_add(1), c.wrapping_sub(1)]);
                if f.wide() {
                    near.extend([c ^ (1 << 32), c ^ (1 << 63), c.rotate_left(32), c | 0xffff_ffff_0000_0000]);
                }
            }
            let narrow = |v: &mut Vec<u64>| {
                if !f.wide() {
                    v.iter_mut().for_each(|x| *x &= 0xffff_ffff);
                }
                v.sort_unstable();
                v.dedup();
            };
            let mut exact = exact;
            narrow(&mut exact);
            narrow(&mut near);
            (f, exact, near)
        })
        .collect()
}

/// What a value compared with a field of `d` may be: BPF compares unsigned, so an unsigned
/// integer, widened to 64 bits.
#[diagnostic::on_unimplemented(message = "BPF compares unsigned: `{Self}` can't be compared with a field of `d`")]
pub trait Unsigned {
    fn widen(self) -> u64;
}

impl Unsigned for u64 {
    fn widen(self) -> u64 {
        self
    }
}

impl Unsigned for u32 {
    fn widen(self) -> u64 {
        self as u64
    }
}

impl Unsigned for u16 {
    fn widen(self) -> u64 {
        self as u64
    }
}

impl Unsigned for u8 {
    fn widen(self) -> u64 {
        self as u64
    }
}

/// The values of a param the macro's sampled test (`<name>_matches_its_bpf_sampled`) builds the
/// program for: each bool both ways, each variant of an enum (which implements this, listing
/// them), and integers at 0, 1, their extremes and (u64) 2^32.
pub trait Sample: Sized + Copy {
    fn samples() -> Vec<Self>;
}

impl Sample for bool {
    fn samples() -> Vec<Self> {
        vec![false, true]
    }
}

impl Sample for u64 {
    fn samples() -> Vec<Self> {
        vec![0, 1, 1 << 32, u64::MAX]
    }
}

impl Sample for u32 {
    fn samples() -> Vec<Self> {
        vec![0, 1, u32::MAX]
    }
}

/// The sampled test's inputs per program: about 300,000 calls in all (a second or two, debug), at
/// least 100 each.
pub fn sampled_budget(programs: usize) -> usize {
    (300_000 / programs.max(1)).clamp(100, 20_000)
}

/// The fast check, the proof's assertion over `n` inputs instead of all of them: each field
/// drawn from [`samples`] of `constants` (half the time one of the field's exact constants, so
/// that deep paths are reached). Panics on the first input where `prog` and `f` differ.
pub fn check_sampled(prog: &[SockFilter], constants: &[(Field, u64)], n: usize, f: impl Fn(&SeccompData) -> u32) {
    check(prog);
    let s = samples(constants);
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..n {
        let mut d = SeccompData::default();
        for (field, exact, near) in &s {
            let r = rand();
            let pool = if r & 1 == 0 && !exact.is_empty() { exact } else { near };
            field.set(&mut d, pool[(r >> 1) as usize % pool.len()]);
        }
        assert_eq!(run(prog, &d), f(&d), "{d:x?}");
    }
}
