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

## exobox-rt (2026-11-18): the syscall table (native/rt: sysmap, xabi)
No new runtime dependency; the table is ~7.5 KB of routes plus its names.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| libc 0.2 | x86-64 struct layouts (`stat`, `statfs`, `epoll_event`, `utsname`) and constants the translations are checked against | test | test-only (already in the tree for the suite) |

Tools in the devshell (not linked): cargo-nextest (per-test processes and timeouts), erofs-utils
(store images for programs outside the store; `fsck.erofs`/`dump.erofs` are the test oracle for
native/erofs).

## exobox-rt (2026-11-18): the in-sandbox runtime (native/rt)
no_std, no allocation. Its size is measured once it's linked into `exobox`.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| rustix 1 (`thread`) | raw Linux syscalls; `thread` for prctl(PR_SET_NO_NEW_PRIVS) before the filter's install (`filter.rs`; seccomp itself is one inline `syscall`, as rustix has no wrapper) | library | `thread` adds linux-raw-sys's prctl constants only |
| libc 0.2 | fork and waitpid: the filter's real-kernel test | test | test-only (already in the workspace) |
