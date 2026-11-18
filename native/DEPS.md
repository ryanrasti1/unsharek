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

## exobox-rt (2026-11-18): the in-sandbox runtime (native/rt)
Not linked into a binary yet, so no size to measure. 3 crates in the normal dependency tree; cold
release build ~2.9 s (nearly all rustix and linux-raw-sys). The syscall table (sysmap) is ~7.5 KB
of routes plus its names.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| rustix 1 (no default features; thread, mm) | raw Linux syscalls, no libc: no_new_privs before the filter's install (seccomp itself is one inline `syscall`: rustix has no wrapper), `mprotect` for the coroutine stacks' guard pages | library | only the calls used are linked; pulls bitflags and linux-raw-sys (constants) |
| libc 0.2 | x86-64 struct layouts and constants the translations are checked against; fork/waitpid for the filter's kernel test | test | test-only (already in the tree for the suite) |

Tools in the devshell (not linked): cargo-nextest (per-test processes and timeouts), erofs-utils
(store images for programs outside the store; `fsck.erofs`/`dump.erofs` are the test oracle for
native/erofs).

## The kernel and lkl-sys (2026-11-18): LKL linked in (native/lkl-sys, lkl/)
Measured on stock LKL (`d0f76a77e`, Linux 6.12) with `lkl/defconfig`, GCC 16.2, 24 cores.

- **Kernel object** (`liblkl-kernel.a`, tools/lkl's `lib/lkl.o`): 3.48 MB text, 2.42 MB data,
  0.26 MB bss: ~5.9 MB added to any binary that links it. The largest pieces of data:
  `irq_desc`, 0.97 MB (NR_IRQS = 4096 descriptors of 248 bytes, static: the series' item 14 makes
  it a knob), and printk's static ring (0.35 MB).
  It needs nothing from libc: only `lkl_printf` and `lkl_bug`, which lkl-sys's shim.c defines
  (vsnprintf into a stack buffer, handed to the binary's `exobox_lkl_print`/`exobox_lkl_panic`).
  Built with `-Wa,-mrelax-relocations=no` (no relaxable GOT relocations: the tier A mis-relaxed GOT
  push can't happen, and binaries need no `--no-relax`) and given back its `.note.GNU-stack`, so
  no link flags are needed. A change to the kernel's flags rebuilds it all (~45 s under load).
- **Cold kernel build**: ~20 s wall (3.5 min CPU), by make or through cargo (build.rs passes cargo's
  jobserver). **No-op make**: ~3.5 s (kbuild walking its tree); build.rs only runs it when lkl/,
  wrapper.h or the kernel's source changed, so a warm `./test` doesn't pay it (a no-op
  `cargo build` stays ~0.1 s, the source tree's mtimes scanned by cargo).
- `./test -E 'package(lkl-sys)'` warm: ~0.7 s (the boot to halt takes ~35 ms; objdump of the test
  binary ~0.5 s; readelf of lkl.o's relocations, the shim's test: fractions of that).

| Crate | For | Where | Cost noted |
|---|---|---|---|
| cc 1 | compiles shim.c (`lkl_printf`, `lkl_bug`) | lkl-sys's build.rs | ~1 KB of code; already in the tree (fixtures) |
| bindgen 0.73 (runtime only: no logging, no prettyplease) | Rust declarations from lkl.h: the host-operations table, the entry points, `__lkl__NR_*` | lkl-sys's build.rs | none at run time. Build: ~4.5 s of its dependency chain (syn, clang-sys, regex, nom, cexpr) on a cold build, in parallel with the rest; ~0.3 s to generate the bindings each time build.rs runs. Needs libclang at build time (devshell: `rustPlatform.bindgenHook`) |

Tools in the devshell (not linked): libclang via `rustPlatform.bindgenHook` (sets `LIBCLANG_PATH` and
`BINDGEN_EXTRA_CLANG_ARGS`; changing flake.nix refreshes devshell.sh's cached environment by
itself); objdump (binutils, already in the stdenv) for the `addr32 call` check.

## exobox-rt arena tests (2026-11-18): property tests of the arena (native/rt/src/arena)
Test-only: nothing reaches the runtime or the binary. The rt crate's test build goes from rustix
alone to 17 crates; cold `cargo build -p exobox-rt --tests` 4.4 s, of which proptest and its
dependencies are ~3.5 s (zerocopy 1.9 s via rand_chacha's ppv-lite86, proptest 1.5 s,
regex-syntax 1.1 s, in parallel). Warm, nothing.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| proptest 1 (default-features off, std) | random sequences of mmap/munmap/mremap/mprotect against a model, shrunk to a minimal failing sequence | rt tests | test-only; without `fork`/`timeout` (no rusty-fork, tempfile, wait-timeout); `failure_persistence` off, so no files written |
| libc 0.2 | a real `MAP_NORESERVE` reservation, `madvise` as the release hook, `mincore` to see what the host holds | rt tests | test-only (already the suite's) |
