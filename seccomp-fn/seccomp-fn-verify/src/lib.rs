//! seccomp-fn-verify: the proof that a seccomp filter's program is its policy. This crate is
//! the trusted part of seccomp-fn, and the only part to review (README.md).
//!
//! A policy is a plain Rust function of its params returning the verdict function, and the
//! filter its program, from any compiler (`seccomp_fn::compile!`, not trusted):
//!
//! ```ignore
//! pub fn policy(pid: u64, strict: bool) -> impl Fn(&libc::seccomp_data) -> u32 { move |d| { … } }
//! pub fn filter(pid: u64, strict: bool) -> Vec<libc::sock_filter> { seccomp_fn::compile!(policy(pid, strict)) }
//! seccomp_fn_verify::policy!(policy, filter);
//! ```
//!
//! [`policy!`] emits the Kani harness ([`prove`]): for every value of every param and every
//! `seccomp_data`, `run_bpf(&filter(params), &d) == policy(params)(&d)`. [`check_sampled`] is
//! the same assertion on sampled inputs, for a `#[test]`.
//!
//! # The rule
//!
//! Nothing here relies on a trait, type or item the compiler could emit or implement. The
//! policy and the filter are taken as plain functions through this crate's own blanket impls
//! ([`Policy`], [`Filter`]: over std's `Fn`, which nothing else can implement for a function
//! item), the inputs are made here (`kani::any()` for each param and each field of libc's
//! `seccomp_data`, no `kani::assume`), the program is run here ([`run_bpf`]), and the sampled
//! check finds the constants to sample around in the program itself. A compiler that emits
//! anything at all can only make the proof fail.

mod bpf;
pub use bpf::{MAX_INSNS, run_bpf};
pub use libc::{seccomp_data, sock_filter};

/// A policy: a function of its params (as a tuple, `Args`) returning its verdict function.
pub trait Policy<Args> {
    fn verdict(&self, args: Args, d: &seccomp_data) -> u32;
}

/// A filter: a function of the same params returning the program.
pub trait Filter<Args> {
    fn program(&self, args: Args) -> Vec<sock_filter>;
}

macro_rules! arity {
    ($($a:ident),*) => {
        impl<Func, Ret, $($a),*> Policy<($($a,)*)> for Func
        where
            Func: Fn($($a),*) -> Ret,
            Ret: Fn(&seccomp_data) -> u32,
        {
            #[allow(non_snake_case)]
            fn verdict(&self, ($($a,)*): ($($a,)*), d: &seccomp_data) -> u32 {
                self($($a),*)(d)
            }
        }
        impl<Func, $($a),*> Filter<($($a,)*)> for Func
        where
            Func: Fn($($a),*) -> Vec<sock_filter>,
        {
            #[allow(non_snake_case)]
            fn program(&self, ($($a,)*): ($($a,)*)) -> Vec<sock_filter> {
                self($($a),*)
            }
        }
    };
}
arity!();
arity!(A);
arity!(A, B);
arity!(A, B, C);
arity!(A, B, C, D);
arity!(A, B, C, D, E);
arity!(A, B, C, D, E, G);

/// The proof's assertion, for every input: params and `seccomp_data` symbolic, each param a
/// `kani::any()` (its type's `Arbitrary`: all its values), the program run by [`run_bpf`] (which
/// also asserts the kernel would take it).
#[cfg(kani)]
pub fn prove<Args: Copy + kani::Arbitrary>(policy: impl Policy<Args>, filter: impl Filter<Args>) {
    prove_at(policy, filter, kani::any())
}

/// [`prove`] for params `args` (some of them concrete: `policy!`'s list of values).
#[cfg(kani)]
pub fn prove_at<Args: Copy>(policy: impl Policy<Args>, filter: impl Filter<Args>, args: Args) {
    let d = seccomp_data { nr: kani::any(), arch: kani::any(), instruction_pointer: kani::any(), args: kani::any() };
    assert_eq!(run_bpf(&filter.program(args), &d), policy.verdict(args, &d));
}

/// The Kani harness for `policy` and `filter` (functions of the same params), in a module of its
/// own here: `<module>::policy_proof::policy_is_filter` (one per module), every param
/// `kani::any()`. `unwind` bounds the program's length (default 100).
///
/// `(…)` instead gives each param in order: `_` (`kani::any()`), or a fieldless enum's or a
/// bool's values, each named: `Mode = [coroutine: Coroutine, fork: Fork]`, `bool = [off: false,
/// on: true]`. A harness is proved for each combination of the listed values
/// (`policy_proof::coroutine::off::proof`), and each list is a `match` with no wildcard, so a
/// value left out (a variant added later) doesn't compile: the list covers the type.
#[macro_export]
macro_rules! policy {
    ($policy:ident, $filter:ident) => {
        $crate::policy!($policy, $filter, unwind = 100);
    };
    ($policy:ident, $filter:ident, unwind = $u:literal) => {
        #[cfg(kani)]
        mod policy_proof {
            #[kani::proof]
            #[kani::unwind($u)]
            fn policy_is_filter() {
                $crate::prove(super::$policy, super::$filter)
            }
        }
    };
    ($policy:ident, $filter:ident, unwind = $u:literal, ($($spec:tt)*)) => {
        #[cfg(kani)]
        #[allow(non_snake_case, unused_imports)]
        mod policy_proof {
            use super::*;
            use super::{$filter as __filter, $policy as __policy};
            $crate::__policy_cases!($u [] $($spec)*);
        }
    };
}

/// `policy!`'s params, one at a time: `$u [args so far] params left…`.
#[doc(hidden)]
#[macro_export]
macro_rules! __policy_cases {
    ($u:tt [$($done:expr,)*]) => {
        #[kani::proof]
        #[kani::unwind($u)]
        fn proof() {
            $crate::prove_at(__policy, __filter, ($($done,)*))
        }
    };
    ($u:tt [$($done:expr,)*] _ $(, $($rest:tt)*)?) => {
        $crate::__policy_cases!($u [$($done,)* kani::any(),] $($($rest)*)?);
    };
    ($u:tt [$($done:expr,)*] bool = [$($n:ident : $v:literal),* $(,)?] $(, $($rest:tt)*)?) => {
        fn __covers(x: bool) {
            match x {
                $($v)|* => {}
            }
        }
        $crate::__policy_values!($u [$($done,)*] [$($n: $v,)*] [$($($rest)*)?]);
    };
    ($u:tt [$($done:expr,)*] $t:ident = [$($n:ident : $v:ident),* $(,)?] $(, $($rest:tt)*)?) => {
        fn __covers(x: $t) {
            match x {
                $($t::$v)|* => {}
            }
        }
        $crate::__policy_values!($u [$($done,)*] [$($n: $t::$v,)*] [$($($rest)*)?]);
    };
}

/// A module per listed value: `$u [args so far] [name: value, …] [params left]`.
#[doc(hidden)]
#[macro_export]
macro_rules! __policy_values {
    ($u:tt $done:tt [] $rest:tt) => {};
    ($u:tt [$($done:expr,)*] [$n:ident : $v:expr, $($more:tt)*] [$($rest:tt)*]) => {
        mod $n {
            use super::*;
            $crate::__policy_cases!($u [$($done,)* $v,] $($rest)*);
        }
        $crate::__policy_values!($u [$($done,)*] [$($more)*] [$($rest)*]);
    };
}

/// The proof's assertion on `n` sampled `seccomp_data`s, for params `args`: each 32-bit word of
/// `seccomp_data` drawn from the constants the program compares that word with (found in the
/// program: the word last loaded, and each jump's `k`), one either side, and extremes. Panics on
/// the first input where the program and the policy differ. For a `#[test]`, in seconds.
pub fn check_sampled<Args: Copy + std::fmt::Debug>(policy: impl Policy<Args>, filter: impl Filter<Args>, args: Args, n: usize) {
    let prog = filter.program(args);
    // the constants per word (16 words of seccomp_data)
    let mut exact: Vec<Vec<u32>> = vec![vec![]; 16];
    let mut word = 0;
    for i in &prog {
        match i.code {
            0x20 => word = (i.k / 4) as usize % 16,
            0x15 | 0x25 | 0x35 | 0x45 => exact[word].push(i.k),
            _ => {}
        }
    }
    let near: Vec<Vec<u32>> = exact
        .iter()
        .map(|e| {
            let mut v = vec![0, 1, u32::MAX, 1 << 31];
            for &k in e {
                v.extend([k, k.wrapping_add(1), k.wrapping_sub(1)]);
            }
            v
        })
        .collect();
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    let mut rand = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..n {
        let mut w = [0u32; 16];
        for (i, x) in w.iter_mut().enumerate() {
            let r = rand();
            let pool = if r & 1 == 0 && !exact[i].is_empty() { &exact[i] } else { &near[i] };
            *x = pool[(r >> 1) as usize % pool.len()];
        }
        // the words as libc's seccomp_data lays them out (little-endian halves: x86-64)
        let wide = |lo: usize| w[lo] as u64 | (w[lo + 1] as u64) << 32;
        let d = seccomp_data {
            nr: w[0] as i32,
            arch: w[1],
            instruction_pointer: wide(2),
            args: [wide(4), wide(6), wide(8), wide(10), wide(12), wide(14)],
        };
        assert_eq!(
            run_bpf(&prog, &d),
            policy.verdict(args, &d),
            "params {args:?}, nr {} arch {:#x} ip {:#x} args {:x?}",
            d.nr,
            d.arch,
            d.instruction_pointer,
            d.args
        );
    }
}
