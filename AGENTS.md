# Working on exobox

## Iterate in seconds
- `./test` builds incrementally and runs everything. Warm, it takes seconds; keep it that way. A
  change that makes it slower needs a reason in its commit message.
- Every run of anything is bounded: the suite gives each case a timeout of seconds (`timeout` in
  `native/exobox/tests/suite.rs`, 5 s by default), nextest kills a guest test at 5 s and
  backstops the rest (`.config/nextest.toml`), and commands run by hand get `timeout 10 …`. A hang is a failure, found in seconds, never a
  wait.
- Run the narrowest set while iterating (`./test -E 'test(/^idle::/)'`, `./test -E
  'package(guest-tests) & test(/^signals::/)'`), then all of it before a
  commit.
- Never wait on a long build to see a result. If a step takes minutes (the kernel's cold build),
  it runs once and is cached; the loop after it doesn't repeat it.

## Builds
- During development every build is incremental: cargo for Rust and the test programs (build.rs),
  make for the kernel. No `nix build` or `nix develop` in the loop: `./test` sources
  `devshell.sh`, which caches the devshell's environment keyed on flake.nix and flake.lock.
- One `nix build` makes the distributed binary at the end. It is not part of the loop.
- The kernel is the submodule `lkl/linux`. Kernel work happens there, on a branch of the kernel's
  repository; it lands in exobox as the submodule's new commit plus exobox's side of it, in one
  commit. A secondary worktree of this repository has no submodule checked out: build it with
  `EXOBOX_LKL_SRC=` pointing at a kernel checkout (or `git submodule update --init lkl/linux` in it,
  ~1.3 GB).

## Tests
- What a program observes inside the guest (files, threads, signals, sockets, /proc, exec, fork)
  is a Rust `#[test]` in `native/guest-tests/`: a function in its `src/`, listed in `all!`
  (lib.rs). nextest runs each test as a process of its own, natively (`guest_native`) and in a
  sandbox of its own in each mode (`guest_coroutine`, `guest_threaded`, `guest_fork`; the
  run-wrapper `native/guest-tests/run-in-guest`).
- What the host sees of a run (its exit status or signal, its stdin and a slow reader of its
  stdout, its host CPU time, files on the host, the CLI's flags, programs from nixpkgs) is a case
  in `cases()` of `native/exobox/tests/suite.rs`: a program in `native/fixtures/c/` run by
  `exobox run`. The library's API (hooks, held and passed fds, guards, templates) is
  `native/exobox/tests/{guest,net}.rs`'.
- A bug found gets a regression test first, in whichever of these fits; its comment says what
  broke and where. A known bug's test that fails is `#[ignore = "<why>"]` in the modes it fails
  in (`all!`'s arms), and its fix removes the ignore.
- Each test runs natively too, unless it can't (it needs the sandbox) or mustn't (it is unsafe on
  the host). The native run checks the test: a leak test must leak natively.
- Escape tests probe the filter with `--deny=errno`; the default (`kill`) has its own case.

## Code
- Comments live in the code, next to what they explain: why it is so, what broke before. The
  top-level README describes the project and its modes; there is no other docs tree yet.
- Library first: the CLI (`native/exobox/src/main.rs`) only turns arguments into a `Config`.
- Proven, current crates by default. Record each dependency's cost (binary size, build time) in
  `native/DEPS.md` when adding it.
