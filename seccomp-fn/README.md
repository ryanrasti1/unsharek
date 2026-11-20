# seccomp-fn
A seccomp filter written as a plain Rust function, compiled to classic BPF, and proven equal to it. The policy is ordinary Rust you can read, test and run; the compiler is not trusted: every program it emits is checked against the function it came from.

Two crates:
- **`seccomp-fn-validate`**: the proof, the only part to review ([its README](seccomp-fn-validate/README.md): the claim, what it rests on, the review checklist). `run_bpf`, its test against Linux, and `policy!`, which emits the Kani harness.
- **`seccomp-fn`**: the compiler, `compile!`, and nothing else. Not trusted.

```rust
pub fn policy(pid: u64) -> impl Fn(&libc::seccomp_data) -> u32 {
    move |d| {
        if d.arch != AUDIT_ARCH_X86_64 { return SECCOMP_RET_KILL_PROCESS; }
        match d.nr as i64 {
            SYS_read | SYS_write => SECCOMP_RET_ALLOW,
            SYS_kill if d.args[0] == pid && d.args[1] >= 1 && d.args[1] <= 64 => SECCOMP_RET_ALLOW,
            _ => SECCOMP_RET_KILL_PROCESS,
        }
    }
}
seccomp_fn_validate::policy!(policy, filter);   // the Kani harness
pub fn filter(pid: u64) -> Vec<libc::sock_filter> {
    seccomp_fn::compile!(policy(pid))
}
```

No macro touches `policy`: rustc compiles it as written, and the proof is about it. Types and constants are libc's.

## The subset (v0)
- `if`/`else`, early `return`, `match` on `d.nr as i64` (libc's `SYS_*` as patterns; `|`, guards, `_`), `let` of param-only values
- `==`, `!=`, `<`, `<=`, `>`, `>=` between a field of `d` (`d.nr` for `==`/`!=`, `d.nr as u32`, `d.arch`, `d.instruction_pointer`, `d.args[i]`) and a value not involving `d`; `&&`, `||`, `!`
- params: unsigned integers, `bool`, fieldless enums; comparisons are full-width and unsigned (BPF's)

Anything else is a compile error naming it.

# Design (the compiler)
`compile!(policy(args…))` reads its call's own file (`Span::local_file`), finds `fn policy` in the call's module there, and compiles the closure it returns, its params bound to the call's arguments. Each condition without `d` (`if threads`, a guard's `fork && …`) is decided when the program is built: one shape per combination of their values, each a constant instruction array whose `k` fields are computed from the params. One fixed template per construct, no optimisation (a 64-bit comparison is two 32-bit loads and compares; `&&`, `||` and guards are jumps; long jumps go through `JA`).

Examples, each proven and sampled: `examples/policies.rs` (`tests/examples.rs`, and `seccomp-fn-validate`'s `tests/kernel.rs` against Linux).
