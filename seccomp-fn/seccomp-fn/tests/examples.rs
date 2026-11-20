//! The examples (`examples/policies.rs`), sampled: each one's program against its function, for
//! some params (`seccomp_fn_verify::check_sampled`). Their proofs: `cargo kani --tests`.

#[path = "../../examples/policies.rs"]
mod policies;
use policies::*;
use seccomp_fn_verify::check_sampled;

#[test]
fn readme_sampled() {
    for pid in [0, 1, 4242, u64::MAX, 1 << 32] {
        check_sampled(readme::policy, readme::filter, (pid,), 20_000);
    }
}

#[test]
fn compares_sampled() {
    for (lo, hi) in [(0, 0), (3, 90), (1 << 32, u64::MAX), (u64::MAX, 1)] {
        for strict in [false, true] {
            for level in [Level::Low, Level::High] {
                check_sampled(compares::policy, compares::filter, (lo, hi, strict, level), 5_000);
            }
        }
    }
}

#[test]
fn table_sampled() {
    for pid in [0, 7, u64::MAX] {
        for allow_exit in [false, true] {
            check_sampled(table::policy, table::filter, (pid, allow_exit), 10_000);
        }
    }
}

#[test]
fn guarded_sampled() {
    for pid in [0, 7, u64::MAX] {
        for on in [false, true] {
            check_sampled(guarded::policy, guarded::filter, (pid, on), 10_000);
        }
    }
}

#[test]
fn halves_sampled() {
    for v in [0, 0xaaaa_aaaa_0000_0005, 0x0000_0005_aaaa_aaaa, u64::MAX] {
        for w in [0, 999, u32::MAX] {
            check_sampled(halves::policy, halves::filter, (v, w), 5_000);
        }
    }
}

#[test]
fn abi_sampled() {
    check_sampled(abi::policy, abi::filter, (), 20_000);
}

#[test]
fn long_sampled() {
    for k in [0, 11, u64::MAX] {
        check_sampled(long::policy, long::filter, (k,), 5_000);
    }
}

/// Over 255 instructions: its far jumps go through JA.
#[test]
fn long_needs_ja() {
    let prog = long::filter(11);
    assert!(prog.len() > 256, "{} instructions", prog.len());
    assert!(prog.iter().any(|i| i.code == 0x05), "no JA");
}
