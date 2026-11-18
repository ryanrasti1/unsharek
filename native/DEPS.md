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

## exobox-erofs (2026-11-18): the store image builder (native/erofs)
1,216,864 / 922,576 bytes (release `exobox-erofs`); 25 crates in the normal dependency tree; cold
release build ~3.4 s. Nearly all of it is clap; object's code in the binary is ~3 KB of symbols
(`program_headers` for both ELF classes and its `ReadCache`, by `nm --size-sort`).

| Crate | For | Where | Cost noted |
|---|---|---|---|
| object 0.40 (read_core, elf, std) | ELF program headers: each ELF's slot (its memory image) | library | ~3 KB; pulls memchr |
| clap 4 (derive) | the CLI's arguments | binary | most of the size, as in exobox |
| thiserror 2 | the library's error type | library | none at run time (a derive) |
| tempfile 3 | scratch trees and images | test | test-only |

Tools in the devshell (not linked): cargo-nextest (per-test processes and timeouts), erofs-utils
(store images for programs outside the store; `fsck.erofs`/`dump.erofs` are the test oracle for
native/erofs).

## exobox-rt arena tests (2026-11-18): property tests of the arena (native/rt/src/arena)
Test-only: nothing reaches the runtime or the binary. The rt crate's test build goes from rustix
alone to 17 crates; cold `cargo build -p exobox-rt --tests` 4.4 s, of which proptest and its
dependencies are ~3.5 s (zerocopy 1.9 s via rand_chacha's ppv-lite86, proptest 1.5 s,
regex-syntax 1.1 s, in parallel). Warm, nothing.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| proptest 1 (default-features off, std) | random sequences of mmap/munmap/mremap/mprotect against a model, shrunk to a minimal failing sequence | rt tests | test-only; without `fork`/`timeout` (no rusty-fork, tempfile, wait-timeout); `failure_persistence` off, so no files written |
| libc 0.2 | a real `MAP_NORESERVE` reservation, `madvise` as the release hook, `mincore` to see what the host holds | rt tests | test-only (already the suite's) |
