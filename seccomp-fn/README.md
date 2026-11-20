# seccomp-fn
A seccomp filter written as a plain Rust function, compiled to classic BPF, and proven equal to it. The policy is ordinary Rust you can read, test and run; the compiler is not trusted: every program it emits is checked against the function it came from.

## Claim & Guarantees
For every `#[seccomp]` function `f(d: &SeccompData, params…) -> u32`, the program `f_bpf(params…)` returns `f`'s verdict:
  (a) for every call `d` (every syscall number, arch, instruction pointer and argument)
  (b) for every value of `params` (the integer params symbolic; one proof per combination of the bool and enum params)

This is proven by [Kani](https://github.com/model-checking/kani): `#[seccomp]` emits the harnesses, which assert `run_bpf(&f_bpf(params), &d) == f(&d, params)` with `d` and the integer params from `kani::any()`, one harness per combination of the bool and enum params' values (each param's `Sample` list, itself proven complete).

```rust
// seccomp-fn/src/examples.rs, `readme::policy`
#[seccomp]
fn policy(d: &SeccompData, pid: u64) -> u32 {
    if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
    match d.nr as i64 {
        SYS_read | SYS_write => SECCOMP_RET_ALLOW,
        SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
        _ => SECCOMP_RET_KILL_PROCESS,
    }
}
```

The function is kept as written: the proof is about it, not a copy. Constants are the policy's, from `libc`.

The claim then rests on:
- `run_bpf` (`src/bpf.rs`) being classic BPF as the kernel's seccomp runs it: checked against Linux, by installing programs in forked children and comparing verdicts (`tests/kernel.rs`), with argument values whose 32-bit halves differ
- the harnesses: `d` and the integer params symbolic, every bool and enum value covered; the unwind bound an upper bound on the program's length (Kani fails an unwinding assertion rather than pass a short bound)
- Toolchain correctness:
  - `rustc`
  - Kani and CBMC
  - `libc` (opcodes, `seccomp_data`'s layout)

## The subset (v0)
- `if`/`else`, early `return`, `match` on `d.nr` (or `d.nr as i64`, so libc's `SYS_*` are patterns as they are; `|` patterns, guards, `_`), `let` of param-only values
- `==`, `!=`, `<`, `<=`, `>`, `>=` between a field of `d` and a value not involving `d`; `&&`, `||`, `!`
- params: unsigned integers, `bool`, fieldless enums; comparisons are full-width and unsigned (BPF's)

Anything else is a compile error naming it.

## Not guaranteed
- **The policy is right**: the proof says the program is the function, not that the function is the policy you want.
- **Your reading of the ABI**: whether the kernel reads an argument as 32 or 64 bits, signed or not. Full 64-bit equality is the stricter choice.
- **Installing it**: the crate only compiles; passing the program to `seccomp(2)`, and when, is yours.

# Design
1. `#[seccomp]` keeps the function, and emits:
   - `f_bpf(params…) -> Vec<SockFilter>`: one fixed template per construct, no optimisation (a 64-bit comparison is two 32-bit loads and compares; `&&`, `||` and guards are jumps; long jumps go through `JA`). Forward jumps only, in bounds, ending in a return.
   - `f_constants(params…)`: every constant `f` compares against
   - the Kani harness, and a sampled test (`#[cfg(test)]`): `f` and `run_bpf(f_bpf(..))` over the constants' boundaries, in `cargo test`, in seconds
2. Checking, in three layers:
   - the Kani proof: the guarantee (`cargo kani`; `lib.kaniCheck` in the flake, for your crate)
   - the sampled test: fast feedback, on the build that ships
   - `run_bpf` against Linux: the one modelled part, checked

## Review checklist
| Claim | Where | Verify |
|---|---|---|
| BPF semantics | `src/bpf.rs` `run_bpf` | the kernel's: loads from `seccomp_data`'s offsets, unsigned jumps, forward only; and `tests/kernel.rs` agrees |
| harness | the macro's harness emission | every input and param `kani::any()`; calls the function as written |
| the function as written | the macro's output item | the input item, unchanged |
| proof runs | `flake.nix` `lib.kaniCheck` | fails the build when a proof fails |
