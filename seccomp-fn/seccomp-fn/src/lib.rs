//! A seccomp filter written as a plain Rust function, compiled to classic BPF by `#[seccomp]`,
//! and proven by Kani to give the function's verdict on every input.
//!
//! See README.md: the claim, the subset, the review checklist.
//!
//! What is trusted: [`run_bpf`] (classic BPF as the kernel runs it, short enough to read, and
//! checked against the kernel by `tests/kernel.rs`), Kani, and rustc. The macro and [`Builder`]
//! are not: the proof the macro emits (`<name>_is_its_bpf`, under `cfg(kani)`) checks what they
//! built, for every `SeccompData` and every parameter.

pub use seccomp_fn_macros::{seccomp, seccomp_expr};

/// What `seccomp_expr!` makes: a filter function `run` and its program `bpf`, for params `P`
/// (a tuple of the closure's typed arguments after `d`).
pub trait Seccomp<P> {
    /// The function itself: its verdict on `d`.
    fn run(&self, d: &SeccompData, params: P) -> u32;
    /// The function as a classic-BPF program, for these params.
    fn bpf(&self, params: P) -> Vec<SockFilter>;
    /// Every comparison the program makes for these params: its field and value.
    fn constants(&self, params: P) -> Vec<(Field, u64)>;
    /// The proof's assertion, sampled, for every combination of the params' `Sample` values:
    /// call it from a `#[test]` (a `#[test]` nested in the expression would never run).
    fn check_sampled(&self);
}

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

/// One classic-BPF instruction: libc's `struct sock_filter` (include/uapi/linux/filter.h).
pub type SockFilter = libc::sock_filter;

mod bpf;
pub use bpf::{MAX_INSNS, SeccompData, run_bpf};
use bpf::*;

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
///
/// The instructions go into an array of the macro's bound, `N`, from its end: the program is the
/// array's last `len`, first instruction first. (Not a `Vec`: through a heap allocation Kani
/// loses track of which opcode each instruction is, and its proof grows tenfold.)
pub struct Builder<const N: usize> {
    insns: [SockFilter; N],
    len: usize,
    /// Every comparison's field and value, for the sampled check ([`samples`]); not kept under
    /// Kani, which needn't them.
    pub constants: Vec<(Field, u64)>,
}

impl<const N: usize> Default for Builder<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Builder<N> {
    /// A builder for a program of at most `N` instructions (the macro's bound).
    pub fn new() -> Self {
        Builder { insns: [SockFilter { code: 0, jt: 0, jf: 0, k: 0 }; N], len: 0, constants: Vec::new() }
    }

    fn push(&mut self, code: u16, jt: u8, jf: u8, k: u32) -> Label {
        assert!(self.len < N, "#[seccomp]: more instructions than the macro's bound, {N}");
        self.insns[N - 1 - self.len] = SockFilter { code, jt, jf, k };
        self.len += 1;
        self.len
    }

    /// `return k`.
    pub fn ret(&mut self, k: u32) -> Label {
        self.push(RET_K, 0, 0, k)
    }

    /// The offset of a jump written next to `to`.
    fn dist(&self, to: Label) -> usize {
        self.len - to
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
    /// A number outside u32's range matches no call: it has no test.
    pub fn nr_in(&mut self, nrs: &[i128], t: Label, f: Label) -> Label {
        let mut next = f;
        for nr in nrs.iter().rev().filter_map(|&n| u32::try_from(n).ok()) {
            #[cfg(not(kani))]
            self.constants.push((Field::Nr, nr as u64));
            next = self.jump(BPF_JEQ, nr, t, next);
        }
        let _ = next;
        self.load(OFF_NR)
    }

    /// The program, first instruction first.
    pub fn finish(self) -> Vec<SockFilter> {
        self.program().to_vec()
    }

    /// The program, in place: what the proof runs.
    pub fn program(&self) -> &[SockFilter] {
        &self.insns[N - self.len..]
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
