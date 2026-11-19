# seccomp-fn
A seccomp filter written as a plain Rust function, compiled to classic BPF by `#[seccomp]`, and proven equal to it by Kani. Two crates: `seccomp-fn` (the library: `SeccompData`, `run_bpf`, `install`, the builder the macro's code calls, the sampled check) and `seccomp-fn-macros` (the macro). Dependencies: `libc` (the library), `syn`, `quote`, `proc-macro2` (the macro).

```rust
#[seccomp]
fn policy(d: &SeccompData, pid: u64, threads: bool) -> u32 {
    if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
    match d.nr {
        SYS_read | SYS_write => SECCOMP_RET_ALLOW,
        SYS_kill if d.args[0] == pid => SECCOMP_RET_ALLOW,
        SYS_exit if threads && d.args[0] == 0 => SECCOMP_RET_ALLOW,
        _ => SECCOMP_RET_KILL_PROCESS,
    }
}
// policy(&d, pid, threads): the verdict, as Rust. policy_bpf(pid, threads): the program, for install().
```

## The claim
For every `#[seccomp]` function, the program `name_bpf(params)` builds is proven by Kani equal to the function: `run_bpf(&name_bpf(p), &d) == name(&d, p)` for every `d` and every value of every param. The proof also shows the kernel takes the program (`run_bpf` refuses what the kernel's checker refuses).

Three layers:
- **The Kani proof**, the guarantee: `name_is_its_bpf_<i>`, emitted under `cfg(kani)`, one harness per combination of the bool and enum params (each harness's program has one length), with `d` and the integer params symbolic; and `name_samples_are_complete`, that those combinations are all of them.
- **The sampled test**, fast feedback on the build that ships: `name_matches_its_bpf_sampled`, emitted under `cfg(test)`, the same assertion over calls around every constant the function compares with, for each param's `Sample` values. Seconds, in plain `cargo test`.
- **`run_bpf` against Linux**, the modelled part checked: `tests/kernel.rs` installs programs in forked children and compares the kernel's verdicts with `run_bpf`'s, with values whose halves differ in every field, another ABI, and the x32 bit.

## What it rests on
- `run_bpf` matching the kernel's seccomp (`src/lib.rs`, about 100 lines from Documentation/networking/filter.rst and kernel/seccomp.c), tested against it as above;
- the harness wiring: the macro's harness asserts `run_bpf(&name_bpf(params), &d) == name(&d, params)`, calls the function as written, and covers every value (`kani::any()`, and `Sample`'s completeness proven);
- `SeccompData`'s layout: libc's `seccomp_data`, asserted at compile time, and the offsets `offset_of!` on libc's;
- rustc and Kani.

The macro and the builder are not trusted: the proof checks their output.

## The v0 subset
Anything else is a compile error naming the construct.
- `fn name(d: &SeccompData, <params>) -> u32`, params `u64`, `u32`, `u16`, `u8`, `bool` or a fieldless enum (implementing `Sample` and, for Kani, `kani::Arbitrary`).
- `if`/`else`, `return`, `let` of an expression without `d`, blocks.
- `match d.nr` with literal or const patterns, `|`, `_` and guards (`pat if cond`): arms in order, a failed guard goes on to the next arm.
- Conditions: `&&`, `||`, `!`, parentheses, and comparisons `== != < <= > >=` of a field (`d.nr`, `d.arch`, `d.instruction_pointer`, `d.args[i]`, a literal `i`) with an expression without `d`. An expression without `d` is a build-time guard; a guard's leading such conjuncts decide whether its arm is emitted at all.
- The verdicts returned are expressions without `d`.
- No calls on `d`, no loops.

Comparisons are full-width and unsigned, as BPF compares: a policy wanting the kernel's own reading of a 32-bit or signed argument spells it out, and full 64-bit equality is the stricter choice. Constants are the policy's, from libc (libc's `SYS_*` as `u32` consts for patterns, since `d.nr` is unsigned).

Codegen: one fixed template per construct, no optimisation. A 64-bit comparison loads and compares the high half, then the low; `&&` and `||` are short-circuit jumps; a match arm is a load of `nr` and a JEQ per pattern; a jump over 255 instructions goes through a JA.

## Review checklist
| What | Where | Verify |
|---|---|---|
| `run_bpf` | `seccomp-fn/src/lib.rs` | each opcode as filter.rst says; `check` refuses what `bpf_check_classic` and `seccomp_check_filter` refuse |
| layout | `seccomp-fn/src/lib.rs` | `SeccompData` asserted equal to libc's; offsets by `offset_of!` |
| the harness | `seccomp-fn-macros/src/lib.rs`, `expand` | asserts the program's verdict is the function's; every param `kani::any()` or every `Sample` value, and the samples proven complete |
| against Linux | `seccomp-fn/tests/kernel.rs` | distinct halves in every field; another arch and the x32 bit killed |

## Running the proof
`cargo kani -p seccomp-fn` (this repository's examples), or `cargo kani -p <crate>` on a crate with `#[seccomp]` functions. Kani comes from this flake: `nix develop` (Rust and Kani), `nix build .#kani`. For a consumer's release, `lib.kaniCheck { name, src, cargoLock, runs }` is a derivation that runs `cargo kani` (each of `runs` an argument list) without network and fails if any proof fails. `nix flake check` runs the tests and the examples' proofs.
