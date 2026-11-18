# Working on exobox

## Iterate in seconds
- `./test` builds incrementally and runs everything. Warm, it takes seconds; keep it that way. A
  change that makes it slower needs a reason in its commit message.
- Every run of anything is bounded: the suite gives each case a timeout of seconds (`timeout` in
  `native/exobox/tests/suite.rs`, 5 s by default), nextest backstops it (`.config/nextest.toml`),
  and commands run by hand get `timeout 10 …`. A hang is a failure, found in seconds, never a
  wait.
- Run the narrowest set while iterating (`./test -E 'test(/^hello::/)'`), then all of it before a
  commit.
- Never wait on a long build to see a result. If a step takes minutes (the kernel's cold build),
  it runs once and is cached; the loop after it doesn't repeat it.

## Builds
- During development every build is incremental: cargo for Rust and the test programs (build.rs),
  make for the kernel. No `nix build` or `nix develop` in the loop: `./test` sources
  `devshell.sh`, which caches the devshell's environment keyed on flake.nix and flake.lock.
- One `nix build` makes the distributed binary at the end. It is not part of the loop.

## Tests
- A bug found gets a regression test first: a program in `native/fixtures/c/` (its comment says
  what broke and where) and a case in `cases()`.
- Each case runs natively too, unless it can't (it needs the sandbox) or mustn't (it is unsafe on
  the host). The native run checks the test: a leak test must leak natively.
- Escape tests probe the filter with `--deny=errno`; the default (`kill`) has its own case.

## Code
- Comments live in the code, next to what they explain: why it is so, what broke before. The
  top-level README describes the project and its modes; there is no other docs tree yet.
- Library first: the CLI (`native/exobox/src/main.rs`) only turns arguments into a `Config`.
- Proven, current crates by default. Record each dependency's cost (binary size, build time) in
  `native/DEPS.md` when adding it.
