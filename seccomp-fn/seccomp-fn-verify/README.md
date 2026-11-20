# seccomp-fn-verify
The trusted part of seccomp-fn: the proof that a seccomp filter's program is its policy, a plain Rust function. The compiler (`seccomp-fn`'s `compile!`) is not trusted; this crate checks whatever it emits. About 420 lines of source including comments (`src/lib.rs`, `src/bpf.rs`), one dependency, `libc`.

## Claim & Guarantees
For a policy `policy(params…) -> impl Fn(&libc::seccomp_data) -> u32` and a filter `filter(params…) -> Vec<libc::sock_filter>` (the same params), `seccomp_fn_verify::policy!(policy, filter)` emits a Kani harness proving

  `run_bpf(&filter(params), &d) == policy(params)(&d)`

  (a) for every `d`: every field of libc's `seccomp_data` (syscall number, arch, instruction pointer, the six arguments) `kani::any()`
  (b) for every value of every param: each param `kani::any()` (its type's `kani::Arbitrary`: an integer's every value, a `bool` both, a fieldless enum's every variant)

and, as `run_bpf` asserts the kernel's checks first, that the kernel takes the program. No `kani::assume`: no input is excluded.

```rust
pub fn policy(pid: u64) -> impl Fn(&seccomp_data) -> u32 {
    move |d| {
        if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
        match d.nr as i64 {
            SYS_read | SYS_write => SECCOMP_RET_ALLOW,
            SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}
pub fn filter(pid: u64) -> Vec<sock_filter> { seccomp_fn::compile!(policy(pid)) }
seccomp_fn_verify::policy!(policy, filter);
```

`check_sampled(policy, filter, params, n)` is the same assertion on `n` sampled `seccomp_data`s, for a `#[test]`: fast feedback, not the guarantee.

The claim then rests on:
- `run_bpf` (`src/bpf.rs`) being classic BPF as the kernel's seccomp runs it: checked against Linux by installing programs in forked children and comparing verdicts (`tests/kernel.rs`), with argument values whose 32-bit halves differ; and its refusals being the kernel's (`tests/sampled.rs`)
- the harness (`prove`, `policy!` in `src/lib.rs`): every input `kani::any()`, the policy called as written; the unwind bound an upper bound on the program's length (Kani fails an unwinding assertion rather than pass a short bound)
- each param type's `kani::Arbitrary` being all its values (derived, for an enum)
- a param given by its values (`Mode = [coroutine: Coroutine, …]`, `bool = [off: false, on: true]`) having them all: not trusted to the list's author, but enforced by rustc's exhaustiveness check, as `policy!` makes each list a `match` with no wildcard, so a missing value (a variant added later) doesn't compile
- Toolchain correctness: `rustc`; Kani and CBMC; `libc` (opcodes, `seccomp_data`'s layout)

## The rule
Nothing here relies on a trait, type or item the compiler could emit or implement. The policy and the filter are taken as plain functions, through this crate's own blanket impls (`Policy`, `Filter`, over std's `Fn`: nothing else can implement them for a function item); the inputs are made here; the program is run here; the sampled check finds the constants it samples around in the program itself, not in anything the compiler says. A compiler that emits anything at all can only make the proof fail.

## Not guaranteed
- **The policy is right**: the proof says the program is the function, not that the function is the policy you want.
- **Your reading of the ABI**: whether the kernel reads an argument as 32 or 64 bits, signed or not.
- **Installing it**: passing the program to `seccomp(2)`, and when, is the caller's.

# Design
1. `policy!(policy, filter)`: a `macro_rules` (no proc macro, no syn) emitting `mod policy_proof { #[kani::proof] fn policy_is_filter() { prove(super::policy, super::filter) } }`. With `unwind = N` it bounds the program's length (default 100); with `(…)` each param in order, `_` (`kani::any()`) or its named values (`Mode = [coroutine: Coroutine, fork: Fork]`, `bool = [off: false, on: true]`): a harness per combination of values (`policy_proof::coroutine::off::proof`), each list also a wildcard-free `match` over its type.
2. `prove`: `kani::any()` params and `seccomp_data`, the assertion above.
3. `run_bpf`: one forward pass over the program (seccomp's jumps only go forward), after the kernel's checks (`bpf_check_classic`, `seccomp_check_filter`).

## Review checklist
| Claim | Where | Verify |
|---|---|---|
| BPF semantics | `src/bpf.rs` `run_bpf` | the kernel's: loads from `seccomp_data`'s offsets, unsigned jumps, forward only; and `tests/kernel.rs` agrees |
| harness | `src/lib.rs` `prove`, `policy!` | every param and every field of `d` `kani::any()`, no `assume`; calls the policy as written |
| the rule | `src/lib.rs` | nothing used comes from the compiler: `Policy`/`Filter` are blanket impls over `Fn` |
| proof runs | the caller's `cargo kani` (`lib.kaniCheck` in the flake) | fails the build when a proof fails |
