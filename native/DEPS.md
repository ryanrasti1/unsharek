# Dependencies and what they cost

For the analysis once the runtime works: each dependency, why it's here, and what it costs. Sizes
are the release `exobox` binary (x86_64, glibc, Rust 1.99.1), unstripped / stripped.

## Baseline (2026-11-18): the CLI and config only, no runtime yet
1,213,408 / 918,520 bytes; 28 crates in the normal dependency tree; cold release build ~4 s.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| clap 4 (derive) | the CLI's arguments | binary | most of the baseline's size (to measure alone once the runtime is in) |
| syscalls 0.6 | syscall names and numbers (`--allow` rules, the audit's table) | library | a name table |
| thiserror 2 | the library's error type | library | none at run time (a derive) |
| cc 1 | finds the C compiler for the test programs | fixtures' build.rs | test-only |
| libtest-mimic 0.8 | the suite's table of trials, nextest-compatible | test | test-only |
| tempfile 3 | the escape tests' secret file | test | test-only |
| libc 0.2 | `wait4`: a run's CPU time and its timeout | test | test-only |

Tools in the devshell (not linked): cargo-nextest (per-test processes and timeouts), erofs-utils
(store images for programs outside the store).
