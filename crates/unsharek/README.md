# unsharek

The library and the CLI (`src/main.rs`, which only turns arguments into a `Config` for `run`).

**The API.** `Guest::boot(GuestConfig { mode, .. })` reserves the program's memory and the kernel's,
boots the guest kernel in this process and makes its basics (`/proc`, `/dev`, `/tmp`, stdio).
Before lockdown the process is an ordinary one: `g.run(closure)` runs a closure with the calling
thread's syscalls served by the guest kernel, as its init (PID 1, root: mounts, files, ids, the
hostname), memory calls staying the host's; between closures nothing is routed (syscall user
dispatch, switched by a selector byte). `mount_closure(&[paths])` shows store paths' closures, read
only, each at its own path (mapped from the image cache, mounted in the guest: the program's code
maps in place from them); `map_image` maps an image as the read-only block device
`/dev/unsharek/<name>`. `pass_fd(fd, n)` gives the guest a host fd as its fd `n`, `hold_fd` keeps
one for the hooks; both are granted at lockdown. `unsharek::lockdown(config)` is unsharek-tcb's
lockdown, re-exported as it is: the booted guest registered itself with it, so it runs the guest's
preparation first and keeps the guest's own fds; `config` (`SandboxConfig`) has the caller's
grants (`c.grant(fd)`; `unsharek::stdio()` grants 0-2, as the CLI does): nothing else stays open.
After it, `g.run(closure)` is the program: `g.run(|| unsharek::execve(&argv, &env))` the guest's
exec of one, or Rust run as the program (its `i32` the status: tests, programs written against
unsharek).

**Templates.** `fork()` or `spawn(|g| { setup; lockdown(..)?; g.run(|| execve(..)) })` forks the guest before
lockdown: the child is a copy (the booted kernel, its mounts and files, copy-on-write) to set up
further, lock down and run; each child's guest RNG is reseeded. About 1 ms and under 2 MB a child
(`cargo xtask perf`). Coroutine and threaded mode.

**The network** (`net`). Loopback is the guest's own. A `connect` elsewhere is `on_connect(cx, pid,
addr)`, whose stream unsharek copies to and from the program's socket (half-closes and resets carried
both ways); `on_listen` takes listens not on loopback; `on_resolve(cx, pid, name)` answers the
guest's DNS (A only), and without it names resolve to addresses of unsharek's own, which
`cx.name_of(addr)` maps back. The hooks are async, run after lockdown on a small executor inside the
sandbox (`Cx`: `spawn`, `sleep_until`, `readable`, `held(name)`), so `on_start`'s task can own a
provider's multiplexed connection. A hook is not a policy point: it runs in the program's address
space, so policy is enforced at the far end of the provider's fd. futures-io by default, tokio with
the `tokio` feature.

**Embedding.** unsharek sets the process's global allocator (the hooks allocate after lockdown,
from a region reserved at build). A binary that embeds it links at a fixed address as the CLI does:
`unsharek_build::link_fixed_address()` in its `build.rs` (a PIE's relocations cost each sandbox
~400 KB).

Tests: `tests/suite.rs` (what the host sees of a run, natively and in each mode), `tests/guest.rs`
and `tests/net.rs` (the API), `tests/perf.rs` (the budgets).
