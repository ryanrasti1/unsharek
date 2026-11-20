# Dependencies and what they cost

For the analysis once the runtime works: each dependency, why it's here, and what it costs. Sizes
are the release `unsharek` binary (x86_64, glibc, Rust 1.99.1), unstripped / stripped.

## Baseline (2026-11-18): the CLI and config only, no runtime yet
1,213,408 / 918,520 bytes; 28 crates in the normal dependency tree; cold release build ~4 s.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| clap 4 (derive) | the CLI's arguments | binary | most of the baseline's size (to measure alone once the runtime is in) |
| syscalls 0.6 | syscall names and numbers (the audit's table; `--allow` rules until the library API's reshape) | test (library until the reshape) | a name table |
| thiserror 2 | the library's error type | library | none at run time (a derive) |
| cc 1 | finds the C compiler for the test programs | fixtures' build.rs | test-only |
| libtest-mimic 0.8 | the suite's table of trials, nextest-compatible | test | test-only |
| tempfile 3 | the escape tests' secret file | test | test-only |
| libc 0.2 | `wait4`: a run's CPU time and its timeout | test | test-only |

## unsharek-erofs (2026-11-18): the store image builder (crates/unsharek-erofs)
1,216,864 / 922,576 bytes (release `unsharek-erofs`); 25 crates in the normal dependency tree; cold
release build ~3.4 s. Nearly all of it is clap; object's code in the binary is ~3 KB of symbols
(`program_headers` for both ELF classes and its `ReadCache`, by `nm --size-sort`).

| Crate | For | Where | Cost noted |
|---|---|---|---|
| object 0.40 (read_core, elf, std) | ELF program headers: each ELF's slot (its memory image) | library | ~3 KB; pulls memchr |
| clap 4 (derive) | the CLI's arguments | binary | most of the size, as in unsharek |
| thiserror 2 | the library's error type | library | none at run time (a derive) |
| tempfile 3 | scratch trees and images | test | test-only |

## unsharek-rt (2026-11-18): the in-sandbox runtime (crates/unsharek-rt)
Not linked into a binary yet, so no size to measure. 3 crates in the normal dependency tree; cold
release build ~2.9 s (nearly all rustix and linux-raw-sys). The syscall table (sysmap) is ~7.5 KB
of routes plus its names.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| rustix 1 (no default features; thread, mm) | raw Linux syscalls, no libc: no_new_privs before the filter's install (seccomp itself is one inline `syscall`: rustix has no wrapper), `mprotect` for the coroutine stacks' guard pages. Not its `runtime` feature (unstable API): `rt_sigaction` and `sigaltstack` go through the gate before lockdown | library | only the calls used are linked; pulls bitflags and linux-raw-sys (constants) |
| libc 0.2 | x86-64 struct layouts and constants the translations (and the trap's ucontext/siginfo) are checked against; fork/waitpid for the kernel tests (filter, trap) | test | test-only (already in the tree for the suite) |

Tools in the devshell (not linked): cargo-nextest (per-test processes and timeouts; its
experimental wrapper scripts run the in-guest tests, `.config/nextest.toml`), erofs-utils
(store images for programs outside the store; `fsck.erofs`/`dump.erofs` are the test oracle for
crates/unsharek-erofs).

## The kernel and lkl-sys (2026-11-18): LKL linked in (crates/lkl-sys, lkl/)
Measured on stock LKL (`d0f76a77e`, Linux 6.12) with `crates/lkl-sys/defconfig`, GCC 16.2, 24 cores.

- **Kernel object** (`liblkl-kernel.a`, tools/lkl's `lib/lkl.o`): 3.48 MB text, 2.42 MB data,
  0.26 MB bss: ~5.9 MB added to any binary that links it. The largest pieces of data:
  `irq_desc`, 0.97 MB (NR_IRQS = 4096 descriptors of 248 bytes, static: the series' item 14 makes
  it a knob), and printk's static ring (0.35 MB).
  It needs nothing from libc: only `lkl_printf` and `lkl_bug`, which lkl-sys's shim.c defines
  (vsnprintf into a stack buffer, handed to the binary's `unsharek_lkl_print`/`unsharek_lkl_panic`).
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

## unsharek-rt arena tests (2026-11-18): property tests of the arena (crates/unsharek-rt/src/arena)
Test-only: nothing reaches the runtime or the binary. The rt crate's test build goes from rustix
alone to 17 crates; cold `cargo build -p unsharek-rt --tests` 4.4 s, of which proptest and its
dependencies are ~3.5 s (zerocopy 1.9 s via rand_chacha's ppv-lite86, proptest 1.5 s,
regex-syntax 1.1 s, in parallel). Warm, nothing.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| proptest 1 (default-features off, std) | random sequences of mmap/munmap/mremap/mprotect against a model, shrunk to a minimal failing sequence | rt tests | test-only; without `fork`/`timeout` (no rusty-fork, tempfile, wait-timeout); `failure_persistence` off, so no files written |
| libc 0.2 | a real `MAP_NORESERVE` reservation, `madvise` as the release hook, `mincore` to see what the host holds | rt tests | test-only (already the suite's) |

## unsharek-rt's host operations (2026-11-18): LKL on the coroutine scheduler (crates/unsharek-rt/src/host.rs)
unsharek-rt now depends on lkl-sys (the kernel's bindings and object) and two more rustix features.
Nothing new from crates.io. What it costs:

- **Build**: building unsharek-rt now builds the kernel (lkl-sys's build.rs: ~20 s cold, nothing warm)
  and needs libclang for the bindings, as lkl-sys already did. Kept rather than a separate crate:
  the host ops need the scheduler's internals (`TlsKey`'s index) and the bindings' types, and one
  edge rt → lkl-sys is the simplest graph.
- **Binary**: the kernel object (~5.9 MB, see above) is linked only where `lkl_init` is referenced;
  the host ops themselves are a few KB of code plus static pools (tens of KB: 1024 semaphores, 8
  mutexes, 4 timers) and the 0.3 KB table.
- `./test -E 'package(unsharek-rt)'`: the boot test (`tests/lkl_boot.rs`) adds ~0.1 s (a forked child
  that boots, sleeps 50 ms, halts).

| Crate | For | Where | Cost noted |
|---|---|---|---|
| lkl-sys (path) | `lkl_host_operations` and its types, filled in by `host`; the kernel for the boot test | library | the kernel build at build time; ~5.9 MB in a binary that boots it |
| rustix 1, + `time`, `event` | `clock_gettime` (vDSO) for the scheduler's clocks; `ppoll` with no fds as the idle wait | library | a few hundred bytes of code |

## Host fd writes in pieces (2026-11-18): rustix `fs`, `termios` in unsharek-rt
No new crates. `host::note_host_fds` looks at the guest's host fds before lockdown (`fstat`,
`isatty`): a pipe's or a socket's writes go in pieces that can't block, a regular file's whole.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| rustix 1, + `fs`, `termios` | `fstat` and `isatty` of the host fds, once before lockdown | library | two small wrappers linked (only the calls used are); the features' modules add well under a second to a cold build |

## unsharek's store (2026-11-18): closures and the image cache (crates/unsharek/src/store.rs)
No new crates: unsharek now depends on unsharek-erofs (in the workspace; brings object and memchr,
already measured above, ~3 KB in a binary). `nix-store` (Nix itself, on the host) is run once per
start for the closure (~20 ms for bash's 7 paths). The CLI doesn't call the store yet, so the
binary's size is unchanged until it does.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| unsharek-erofs | building a store path's image on a cache miss | library | object's ELF reader, ~3 KB |

## unsharek-rt's loader (2026-11-18): exec inside the sandbox (crates/unsharek-rt/src/exec.rs)
Nothing new in Cargo.lock: object was already in the tree (unsharek-erofs). The rt crate's normal
tree gains object and memchr; object is built without std or alloc features (`read_core`, `elf`),
reading the headers in place from the loader's fixed buffers. Not linked into a binary yet; the
release rlib's non-generic exec code is ~3.2 KB (`nm --size-sort`: build_stack 1.9 KB), and the
generic part (header parsing, mapping) is instantiated where the runtime calls it. The loader's
working storage (`exec::Scratch`, ~19 KiB) is the caller's.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| object 0.40 (no default features; read_core, elf) | the ELF file and program headers: the header's checks (magic, class, version, byte order) and the field accessors | library | a few KB; pulls memchr (no std); `extern crate alloc` in object, but nothing on the loader's path allocates |
| unsharek-fixtures (path) | the programs the loader tests load and run (static_start, static_start_nopie, hello, hello_nopie) | rt tests | test-only; the fixtures' build (~1 s cold, cached) |

## unsharek on the runtime (2026-11-18): Guest, Sandbox, the dispatcher (crates/unsharek-rt/src/guest.rs)
Nothing new from crates.io: unsharek now depends on unsharek-rt and lkl-sys (the kernel) and has libc
as a normal dependency (it was the tests'). The release `unsharek` binary: 9,799,104 / 8,596,664
bytes (unstripped / stripped), from 1.2 / 0.9 MB: the kernel object (~5.9 MB) and the runtime.
The runtime's statics are bss, paid for as touched: the arena's extent table (2.5 MiB), the
loader's scratch and the guest execve's string buffer (1 MiB), the scheduler's and futexes' tables.
A sandbox running `idle` (release): PSS 19.3 MB (9.9 MB anonymous, 9.4 MB file-backed: the
binary's text). `hello` starts and ends in ~30 ms, of which ~19 ms is the store's `nix-store
--query` and the kernel's boot ~4 ms; native hello is ~1.5 ms.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| unsharek-rt (path) | the sandbox: boot on coroutines, the filters, the dispatcher, exec | library | the kernel and the runtime: ~8 MB of the binary |
| lkl-sys (path) | the kernel's syscall numbers for the guest's setup (generic `__lkl__NR_*`) | library | none beyond unsharek-rt's |
| libc 0.2 | host setup before the routing filter: reserving memory, mapping images, `getauxval`, `getrandom`, `setrlimit`; the setup closure's `mount(2)` | library | already in the tree; a few calls |

## The Nix package (2026-11-18): `nix build` (flake.nix's `mkUnsharek`, `unsharekKernel`)
Nothing new in Cargo.lock: `rustPlatform.buildRustPackage` vendors it offline (`cargoLock`). The
kernel is its own derivation (crates/lkl-sys/Makefile from the submodule crates/lkl-sys/linux; lkl-sys links it through
`UNSHAREK_LKL_PREBUILT`), so a change to the Rust code rebuilds only the Rust.

- **The package** (`unsharek`, `unsharek-erofs`): closure 57.3 MiB (`nix path-info -Sh ./result`),
  nearly all of it glibc (36.5 MiB with its libidn2) and gcc-lib (10.3 MiB, for libgcc_s); the
  package itself is 10.3 MiB. `bin/unsharek` is 9,765,712 bytes (Nix's `strip -S`: debug info only;
  `strip` of everything gives the 8.6 MB above), `bin/unsharek-erofs` 1,069,216.
- **The kernel derivation** (`nix build .#kernel`): 14.9 MiB (lkl.o and liblkl-kernel.a, 6.6 MiB
  each; liblkl-posix.a, the headers, .config). Not in the package's closure (linked statically);
  its own closure is 359 MiB, as liblkl-posix.a's debug info names gcc's and glibc's headers.
- **Build times** (24 cores, `--builders ''`): kernel and package together ~36 s cold (the kernel
  ~23 s, its source a tree of symlinks into the store rather than a 1.7 GB copy; the Rust package
  ~14 s: a 10 s release build, the tests' build, 0.5 s of tests). (The kernel was a flake input then; it is the submodule crates/lkl-sys/linux now: `nix build` copies its tree into the store once, ~1.3 GB.) A
  rebuild after a Rust change is the Rust package alone; with nothing changed, `nix build` is
  0.4 s. (A configured remote builder that is unreachable adds its SSH timeout to each build.)
- **checkPhase** (nextest): lkl-sys's tests (the kernel given boots on the posix host, answers
  syscalls and halts; lkl.o's relocations; the shim) and the unit tests of unsharek and
  unsharek-erofs, 20 tests. Not the suite, the store test, erofs's image tests or unsharek-rt's: they
  need the devshell's programs (`UNSHAREK_TEST_*`, `fsck.erofs`), the host's `nix-store`, or a kernel
  tree.

## Coroutine mode within its budgets (2026-11-18): memory per sandbox, startup
No new crates; unsharek gains a build script (`crates/unsharek/build.rs`: the binary linked non-PIE at
0x500000000000, with the compiler's PIE start files) and so `cc` as a build-dependency (already in
the tree). The release `unsharek` binary: 9,616,256 / 8,400,120 bytes (unstripped / stripped), from
9,799,104 / 8,596,664: its 17,861 relative relocations (`.rela.dyn`) are gone.

An idle sandbox (`ready_idle`, release): PSS 11.3 MB alone (3.1 MB anonymous), 4.2 MB each with 8
at once (from 19.3 MB and 9.9 MB anonymous; the debug build `./test --perf` measures: 11.5 MB to
4.5 MB at 8). Start to READY ~5 ms (from ~30 ms), the closure's `nix-store` query now cached.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| cc 1 | the C compiler's `-print-file-name` for the PIE start files (`Scrt1.o`, `crtbeginS.o`, ...) | unsharek's build.rs | build only; already in the tree |

## Pluggable networking (2026-11-18): the hooks, their executor and allocator (crates/unsharek/src/net.rs, alloc.rs; crates/unsharek-rt/src/tsi.rs, executor.rs, dns.rs)
The release `unsharek` binary: 9,724,816 / 8,491,168 bytes (unstripped / stripped), ~+90 KB stripped
over the last measurement (the kernel's tsi.c and host fd poll, the runtime's executor, resolver and
copy loop, the adapters; talc itself is ~2.7 KB of symbols). The three new crates build in ~0.4 s
cold (release), in parallel with the rest. The allocator's region (256 MiB, `MAP_NORESERVE`) costs
what the hooks touch after lockdown; the executor's coroutine is one of the sandbox's, started only
when a hook or a passed fd's poll first needs it.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| talc 5 (no default features) | the global allocator after lockdown: the hooks' and the executor's allocations, from a region reserved before (glibc's malloc can't grow then); its lock a spin lock of unsharek's (no futex) | library | ~2.7 KB; pulls lock_api and allocator-api2 (no std) |
| futures-io 0.3 | `AsyncRead`/`AsyncWrite`: the hooks' streams, `HeldFd`, `GuestSocket` | library | traits only |
| futures-core 0.3 | `Stream`: `on_listen`'s inbound connections | library | traits only |
| tokio 1 (optional, feature `tokio`, no default features) | tokio's `AsyncRead`/`AsyncWrite` for hooks' streams and `HeldFd`/`GuestSocket` (capnweb-rs's channel) | library | off by default; with it, tokio's io traits only (no runtime) |
| rustix (workspace) | `Errno`, the runtime's error type, in the adapters | library | already in the tree |

## The library's reshape (2026-11-18): builder, intercept guards, templates (crates/unsharek-build)
No new crates in the library. `syscalls` leaves it (its `--allow` rules are gone; the suite keeps
it as a dev-dependency for the audit's table). A new workspace crate, `unsharek-build`
(`crates/unsharek-build`), holds the fixed-address link that was `crates/unsharek/build.rs`'s, for any
embedder's build script: its one dependency is `cc` (already in the tree), and it is a
build-dependency only, of unsharek and of the examples. Seccompiler stayed the caller's
dependency, not unsharek's, until the TCB split below made it unsharek-tcb's own: the security filter
is compiled with it.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| unsharek-build (workspace) | the binary's fixed-address link (`link_fixed_address`), shared with embedders | unsharek's and the examples' build.rs | build only; pulls cc, already in the tree |

## The in-guest tests (2026-11-18): crates/guest-tests
No new crates: libc (the tests' syscalls) and cc (build.rs: c/longjmp.c), both already in the
tree. Four test binaries of ~3.3 MB each (debug), one library of the tests' bodies: cold ~0.6 s
with the dependencies built, ~0.25 s after a test's edit.

## The TCB split (2026-11-18): seccompiler in unsharek; unsharek-kit (crates/kit)
unsharek is now the trusted computing base (`src/tcb`, `crates/unsharek/TCB.md`) and a thin API.
The security filter's allowlist is compiled by seccompiler instead of unsharek-rt's hand-written
compiler (which stays as a test-only oracle). The batteries (setup, store, net, alloc) move to a
new workspace crate, unsharek-kit, which unsharek re-exports; unsharek no longer depends on lkl-sys,
talc, futures-io/-core or rustix directly (kit does, but lkl-sys, which only the runtime does).
The release `unsharek` binary: 10,123,384 / 8,863,272 bytes (unstripped / stripped), from
10,090,800 / 8,838,696 on main just before: +24 KB stripped, seccompiler's compiler (~13.5 KB of
symbols by `nm --size-sort`, its BTreeMap and Vec code with it) run once per sandbox start.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| seccompiler 0.5 (default features: no `json`) | the security filter's allowlist, rules with 64-bit argument conditions, to classic BPF (`crates/unsharek-tcb/filter.rs`); not its `apply_filter*`, which make libc syscalls the routing filter would trap: lockdown installs through the gate | library (the TCB) | ~24 KB stripped; ~0.3 s cold build (release); depends only on libc, already in the tree |
| unsharek-kit (workspace) | the batteries, re-exported as `unsharek::{setup, store, net, alloc}` | library | none: code moved from unsharek |

## unsharek-tcb (2026-11-19): seccompiler moves to the TCB's own crate; unsharek-kit is gone
The TCB is now `unsharek-tcb` (`crates/unsharek-tcb/`, to become its own repository): lockdown's checks and the one
seccomp filter. **seccompiler is unsharek-tcb's dependency** (with libc, its only other), no longer
unsharek's directly; the filter is compiled with it as before, at lockdown, in the sandbox's
process. unsharek-kit (`crates/kit`) is folded back into unsharek (`setup`, `store`, `net`, `alloc`,
`image` are its modules again), so unsharek depends on talc, futures-io/-core, rustix and tokio
(optional) directly once more. No crate is added or removed from the build: the costs below are
unchanged, only who depends on what.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| seccompiler 0.5 | the filter's allowlist, to classic BPF (`crates/unsharek-tcb/src/filter.rs`) | unsharek-tcb (the TCB) | as before: ~24 KB stripped, ~0.3 s cold build |
| unsharek-tcb (workspace, path) | lockdown and the filter | unsharek | none: code moved from unsharek's `src/tcb` |

## seccomp-fn (2026-11-19): the filter is a Rust function, proven; seccompiler is gone
unsharek-tcb's filter is one `#[seccomp]` function (`crates/unsharek-tcb/src/filter.rs`), compiled to classic BPF by
seccomp-fn (`seccomp-fn/`, its own workspace and repository to be; unsharek-tcb depends on it by
path) and proven equal to it by Kani (`./test --prove`; the release build requires the proof).
**seccompiler is removed**: unsharek-tcb's run-time dependencies are seccomp-fn and libc.
seccomp-fn's macro crate brings syn (with `full`), quote and proc-macro2, at build time only
(versions already in the lock). Kani itself is a Nix derivation (seccomp-fn/flake.nix: the
0.68.0 release bundle and its pinned nightly), in the devshell and the release's check, never in
the binary.

| Crate | For | Where | Cost noted |
|---|---|---|---|
| seccomp-fn (path) | `run_bpf`, `install`, the builder the generated code calls | unsharek-tcb (the TCB) | not measured here (the worktree has no release kernel build): its run-time code is the builder, `install` and `run_bpf`, a few KB, against seccompiler's ~24 KB |
| seccomp-fn-macros (path): syn 3 (`full`), quote, proc-macro2 | `#[seccomp]` | build time only | ~5.6 s cold release build of the pair (syn `full` most of it), under load |
| seccompiler 0.5 | removed | | -~24 KB stripped |

## rustix in unsharek-tcb (2026-11-19): lockdown's syscalls typed
unsharek-tcb's lockdown (`crates/unsharek-tcb/src/lockdown.rs`) makes its calls through rustix: getpid, gettid,
statfs, setrlimit, PR_SET_DUMPABLE, no_new_privs, the bounding and ambient sets, capget/capset.
`close_range` and `seccomp` stay `libc::syscall` (rustix wraps neither). rustix was in the build
already (unsharek, unsharek-rt); the tcb, its own repository, names it itself, not the workspace's.
`seccomp-fn`'s `install` moved into the tcb (it only compiles now).

| Crate | For | Where | Cost noted |
|---|---|---|---|
| rustix 1 (`std`, `thread`, `process`, `fs`) | lockdown's calls but two, without `unsafe` | unsharek-tcb (the TCB) | +2,048 B `.text`, +2.5 KB unstripped binary (release, x86_64-unknown-linux-gnu); stripped size unchanged (page rounding); no new crate in the build |
