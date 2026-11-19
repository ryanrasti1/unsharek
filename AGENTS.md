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
  `exobox run`. The library's API (hooks, held and passed fds, setup closures, templates) is
  `native/exobox/tests/{guest,net}.rs`'.
- A bug found gets a regression test first, in whichever of these fits; its comment says what
  broke and where. A known bug's test that fails is `#[ignore = "<why>"]` in the modes it fails
  in (`all!`'s arms), and its fix removes the ignore.
- Each test runs natively too, unless it can't (it needs the sandbox) or mustn't (it is unsafe on
  the host). The native run checks the test: a leak test must leak natively.
- Escape tests make one forbidden call each and expect death by SIGSYS (`escape_gate.c`'s
  probes); every number's verdict is exobox-tcb's policy, proven (`./test --prove`).

## Code
- The trusted computing base is the crate `exobox-tcb` (`tcb/`) and nothing else
  (`tcb/README.md`: the guarantee, what isn't guaranteed, the design, the review checklist):
  lockdown's checks and the one seccomp filter. It depends on seccomp-fn and libc only, and on
  nothing of exobox's: build it as its own repository. Keep it small. A change that widens what
  the host allows (a filter rule, a kind of guest fd or mapping lockdown accepts) is a TCB change,
  with a test in `tcb/tests/` (`filter.rs`; `lockdown.rs`), and
  tcb/README.md's table and checklist follow it (a test checks the table's rows against the
  policy's, in order; Kani proves the filter is the policy: `./test --prove`). Everything else (exobox's
  API and batteries in `native/exobox`, the runtime `native/rt`, the kernel) is not trusted: it
  is given grants, never produces values the filter trusts, and knows nothing of the filter. A
  network hook is never a policy point.
- Comments live in the code, next to what they explain: why it is so, what broke before. The
  top-level README describes the project and its modes; `tcb/README.md` how to review isolation;
  there is no other docs tree yet.
- Library first: the CLI (`native/exobox/src/main.rs`) only turns arguments into a `Config`.
- Proven, current crates by default. Record each dependency's cost (binary size, build time) in
  `native/DEPS.md` when adding it.
