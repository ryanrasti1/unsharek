# exobox

Run unmodified Linux programs on an in-process Linux kernel, behind a seccomp filter that leaves the
host a handful of syscalls.

exobox links [LKL](https://github.com/lkl/linux) (Linux as a library) into its own process. A
program's syscalls never reach the host kernel: each one traps into exobox and is served by the
guest kernel, or by exobox itself. What the host sees after lockdown is a short allowlist
(`write` to stdout and stderr, one timed wait, an exit, and a few more depending on the mode),
pinned down to the argument. The guest kernel provides compatibility (files, sockets on loopback,
processes, signals, ttys). The security boundary is the host filter, not the guest kernel.

Status: preview, being built (November 2026). The pieces below exist and are tested separately
(`./test`); the sandbox runs its first programs as they are joined (see "Plan").

## Using it

```sh
exobox run -- /nix/store/…-hello/bin/hello            # a Nix program: its closure is mounted read-only
exobox run --mode threaded -- $(which python3) -c 'print(6 * 7)'
exobox run --image store=./app.erofs:/app -- /app/bin/server
exobox run --allow-path ./fixtures -- ./fixtures/probe # a host directory shown read-only, as is
```

A program sees a Linux machine of its own: `/proc`, `/dev`, a writable `/tmp`, its stdio, and the
filesystems it was given (Nix store paths, erofs images). Its exit status is exobox's.

## The library

The CLI is a thin layer over a Rust library. A sandbox is built (the guest kernel booted in this
process), given host data, set up in the guest, and run:

```rust
let mut sb = exobox::Sandbox::builder()
    .mode(Mode::Coroutine)                             // or Threaded (fork mode: not yet)
    .on_connect(OnConnect::new(|cx, pid, addr| provider.connect(cx, pid, addr)))
    .on_resolve(OnResolve::new(|cx, pid, name| provider.resolve(cx, pid, name)))
    .restrict(my_seccomp_program)                      // optional, repeatable: can only take away
    .build()?;                                         // boots the guest kernel
let store = sb.map_closure(&program, &[])?;            // host work: a Nix closure's images mapped
sb.pass_fd(channel, 1000)?;                            // a host fd as the guest's fd 1000
sb.hold_fd_as("net", provider_socket)?;                // a provider's connection, for the hooks
let manifest = std::fs::read("manifest.json")?;        // still the host's syscalls
{
    let _g = sb.intercept()?;                          // this thread's syscalls are the guest's:
    exobox::setup::mount_closure(&store)?;             //   ordinary Rust, as the guest's init:
    std::fs::write("/etc/app/manifest.json", &manifest)?; // mounts, files, ids, the hostname
}                                                      // dropped: the host's again
sb.run(&argv, &env)                                    // lockdown, then exec; never returns
```

- **`Sandbox::builder()…build()`** reserves the program's memory and the kernel's, boots the
  kernel, and sets up the guest's basics (`/proc`, `/dev`, `/tmp`, stdio). The mode, the network
  hooks and the restrictions are the builder's.
- **`map_image`** is the one way to give the guest host data that it maps: the image is mapped
  (a host `mmap`) and becomes a read-only block device, `/dev/exobox/<name>` (`map_image_as` names
  it). exobox owns the mapping, which it later maps code from in place and shares across forks.
  `map_closure(program, allow_paths)` maps a Nix program's closure from the image cache (built
  where missing; `map_store` for a `store::Store` of one's own), each with where it mounts.
- **`intercept()`** returns a guard: while it lives, every syscall of the calling thread is served
  by the guest kernel, as its init (PID 1, root): anything the guest kernel can do, a guard can
  (mounts, files, `setresuid`, `sethostname`). Memory calls stay the host's, so what is allocated
  inside is ordinary host memory. Guards come and go, interleaved with host work: the first
  installs the routing filter (seccomp's: it can't be removed), and after a guard's drop the
  runtime re-issues each trapped syscall on the host (**passthrough**, below), so host code behaves
  as before, with one exception: a host program can't be exec'd any more (the filters would follow
  it into the exec), so helpers are started before the first guard. Only the calling thread is
  routed; other threads' syscalls stay the host's.
- **`run(argv, env)`** is the lockdown and the exec: the routing filter if no guard installed it,
  the network hooks, the security filter (the mode's, with the restrictions stacked), then the
  program exec'd inside the guest with init's credentials as setup left them. Files and fds
  setup left open are the program's. The process's status is the program's; `run` returns only if
  the program couldn't be started. The sandbox's process must have no host threads of the
  caller's left (they would be unfiltered).
- **`pass_fd(fd, n)`** gives the guest host fd `fd` as its fd `n`, now, and `hold_fd(fd)` keeps
  one for the hooks; each widens the filter by `read` and `write` on exactly that fd. They are the
  only ways to widen it: `restrict(prog)` stacks a seccomp program of the caller's (seccompiler's,
  libseccomp's) that can only take away.
- **Templates.** `fork()` (or `spawn(|sb| { setup; sb.run(..) })`) forks the sandbox's process:
  the child is a sandbox of its own, a copy of this one as it is (the booted kernel, its mounts and
  files, shared copy-on-write), to set up further (its own images, fds, guards) and run; the parent
  goes on forking more and waits for them (`exobox::wait`, `waitpid`). exobox makes each child its
  own: its guest RNG reseeded with fresh host entropy, and in threaded mode the kernel copied at
  rest and the child's host threads and CPU token made again. A child starts to READY in about a
  millisecond and costs under 2 MB (`./test --perf`). Fork mode: not yet.
- **The network hooks** (`exobox::net`): the program's sockets are its own for loopback; a
  `connect` anywhere else is `on_connect(cx, pid, addr)`, whose stream exobox copies to and from
  the program's socket (half-closes and resets carried both ways); a `listen` not bound to loopback
  is offered to `on_listen`, whose inbound streams the program accepts; name lookups (the guest's
  libc asking the nameserver in its `/etc/resolv.conf`) are `on_resolve(cx, pid, name)` (A queries
  only: AAAA is answered with no data). Without `on_resolve`, names resolve to addresses of
  exobox's own, and `cx.name_of(addr)` tells `on_connect` the name: policy by name with no resolver.
  Errors are `NetError`s, which become errnos (`Refused` ECONNREFUSED, `Denied` EACCES, ...). With
  no hook, everything but loopback is unreachable. The hooks are async: they run after lockdown,
  on a small executor inside the sandbox (`Cx`: `spawn`, `now`, `sleep_until`,
  `readable`/`writable` and `held(name)` for held fds), so one long-lived task, started at
  lockdown by `on_start`, can own a provider's multiplexed connection. A template's hooks are given
  once, at build; each child holds its own provider's fd under a name the hooks look up.
  futures-io's `AsyncRead`/`AsyncWrite` by default, tokio's with the `tokio` feature;
  `OnConnect::drive` hands a provider the program's end (`GuestSocket`) to drive itself.
- **The authority rule.** The hooks run in the program's address space: a compromised program
  can read and write their memory and drive the provider's connection itself. So that connection
  must carry no more authority than the program's own channel: policy (which addresses, which
  names) lives behind it, at its other end, never in the hook.
- **Layers.** `Sandbox` is built on `Guest` (`Guest::boot`, `map_image`, `intercept`, `run`: the
  kernel and routing, no security filter); the CLI's `exobox run` is `exobox::run(Config)`: the
  builder, the closure's images mapped, `mount_closure` in a guard, `run`.
- **Embedding.** exobox sets the process's global allocator (the hooks allocate after lockdown,
  from a region reserved at build). A binary that embeds it links at a fixed address as the CLI
  does with one call in its `build.rs`, `exobox_build::link_fixed_address()` (`native/build`): a
  PIE's relocations would cost each sandbox ~400 KB.

Anything setup needs beyond that is code: in a guard, or in the guest itself (a first program that
mounts `/dev/exobox/<name>` with `mount(2)` and execs the next one).

**Examples.** `examples/` has small, runnable programs that use the library this way
([examples/README.md](examples/README.md)): a Nix program with its closure and its startup and
memory measured (`nix-program`), composing the guest in guards (`setup`), a host channel at
fd 1000 (`channel`), networking through a proxy that holds the policy (`net-policy`), coroutine
against threaded mode (`threads`), and the host filter refusing a hostile program (`escape`).
`cargo run -p exobox-examples --release --bin <name>`, from the devshell.

## How it works

- **Routing and security are two stacked seccomp filters.** The first (installed by the first
  intercept guard, or by `run`; on the calling thread, which the threads it makes inherit) traps
  every syscall the program makes (`SECCOMP_RET_TRAP`: a SIGSYS into exobox, which serves it) and
  allows everything from exobox's own syscall instruction, the gate. The second (the security
  filter, installed before the program starts) allows from the gate only the mode's list, with
  each argument pinned (exact fds, the program's memory, one `clone` flag set). With two filters
  the kernel takes the strictest answer, so the program's syscalls trap, and the gate gets exactly
  the list. The gate's address check is routing, not security: a compromised program can jump to
  the gate, and then only the list applies. A caller's restrictions are more filters on the same
  stack: the strictest answer still wins.
- **Passthrough.** Between guards (and for other threads during one) a trapped syscall is the
  host's: the SIGSYS handler re-issues it from the gate, which the routing filter allows, and
  returns its result as the call's. What can't be re-issued as is is handled deliberately
  (`exobox_rt::passthrough`): `rt_sigreturn` (a host signal handler's return) is made again at
  the trapped stack; `rt_sigprocmask`, `sigaltstack` and `arch_prctl(ARCH_SET_FS)` apply to the
  state the handler's own return restores (SIGSYS can't be blocked); a `clone` with a new stack
  (a thread, `posix_spawn`'s child) starts its child from the trapped context; a vfork is a fork
  that waits (the child would run over the handler's frames); `clone3` is ENOSYS (libc falls back
  to `clone`); `execve` is EPERM.
- **The trap.** The SIGSYS frame is moved off the program's stack (Go makes syscalls with ~128
  bytes to spare), the FS register switched to exobox's and back, and the call dispatched: to the
  guest kernel (x86-64 numbers translated to the generic table, structs translated), rewritten
  (`open` to `openat`, `fork` to `clone`, ...), emulated (memory, threads, futexes, the thread
  pointer), or refused. About 0.8 µs a call.
- **Signals** are the guest kernel's: actions, masks, delivery, default actions. At a call's
  return it hands a caught signal to the runtime, which builds Linux's frame on the program's stack
  (or its alternate stack) and runs the handler as the program; the handler's `rt_sigreturn` traps
  and hands the registers and mask back. A death by a signal is the sandbox's, by the same signal.
- **Memory.** Before lockdown exobox reserves one region for the program (its arena): readable,
  writable and executable, so JITs work. After lockdown there is no host `mmap`: the program's
  memory calls are served from the arena, and freed pages go back with `madvise` where the mode
  allows it.
- **Exec inside the guest.** exobox locks down first, then loads the program from the guest's
  files into the arena, with its interpreter, and builds its stack. Nothing the program brings (its
  `PT_INTERP`, its libraries' constructors) runs before the filter is in place.
- **The store.** A Nix program's closure is shown as erofs images, one per store path, built once
  and cached (the closure itself too: a store path's never changes). Their layout pads each ELF
  file to its memory image, so code is mapped in place: each image is mapped twice before
  lockdown, read-only for the guest's block device and privately into the arena's top, and the
  program's mappings of its files are answered with where their bytes already are there, shared by
  every sandbox through the host's page cache (what it writes is copy-on-write, its own).
- **The network.** The kernel impersonates the program's AF_INET sockets (its `tsi.c`, after
  libkrunfw's Transparent Socket Impersonation, with direct calls to the host instead of vsock):
  loopback, binds and listens are an inner socket of the guest's own; any other connect is a host
  op, answered when the hook is, and then the socket's bytes go through a kernel socketpair whose
  other end the runtime reads and writes, woken by the kernel when it can. So poll, epoll,
  nonblocking connects and `SO_ERROR` work as on Linux, and the runtime knows no protocol. A
  datagram to port 53 is a resolver query, answered from `on_resolve`. The runtime's executor waits
  on the hooks' host fds in the scheduler's idle wait (one `ppoll` over up to eight fds); passed
  fds (`pass_fd`) poll as their host fd does, the same way.
- **The kernel.** Stock LKL plus a short series (`lkl/README.md`): idle that waits instead of
  spinning, the program as PID 1, threads that join their process, a block device over host memory,
  and the rest of what a cooperative in-process host needs.

## Plan

1. A program runs in coroutine mode: `Guest`, `Sandbox`, the routing and security filters stacked,
   the dispatcher, exec inside the guest, the store mounted (`./test`'s `hello::coroutine`, then
   the rest of the coroutine cases: exit status, stdio, the escape probes, the hostile loader,
   Python).
2. The kernel series' remaining items: exit reporting, host stdio as guest files, the store's block
   device, the memory size, signals, fork, exec's kernel half.
3. Threaded mode: a host thread per program thread, made through the gate; the CPU passed between
   them through eventfds.
4. Fork mode: a guest fork is a host fork, sharing one guest kernel.
5. Templates (done, coroutine and threaded): a booted kernel forked per sandbox
   (`Sandbox::fork`, `spawn`), the kernel's pages
   shared copy-on-write.
6. Within the performance budgets (`./test --perf`): startup, memory per sandbox, parallel builds.
7. Code mapped in place from the store images (done, in release-mode arenas: coroutine and fork).
   Images from extents: a guest disk assembled from an ordered list of {metadata bytes | a range of
   a host file, mapped before lockdown | zeros}, and `exobox_erofs::synthesize(paths)`, which lays
   out an erofs image over a closure's files as they are in the host store (metadata made in
   memory, no file's data read or copied: one copy of every byte, the page cache shared with the
   host). Done: memblk disks of extents, `synthesize`. Next: `map_image` from extents, in-place
   mapping over the per-file mappings, `exobox::store` without image copies (the per-path image
   cache stays for very large closures: one host mapping per file costs every fork and exit).
8. For capnix (`~/src/capnix-proper`, "What exobox needs to provide"): a host fd passed to the guest
   at a given fd (its Cap'n Web channel at 1000), with the filter widened to exactly that fd; the
   program run as a given uid (setup is the guest's init, as root, and can drop to it before exec);
   a read-write block device served over a channel (a new kernel driver: Nix's `/nix/var` on
   ext4); FUSE in the store's kernel (a config fragment); a closure shown from the host's store
   with no copy (item 7's extents and `synthesize`).
9. Pluggable networking (done in coroutine mode): the guest's `connect`, `listen`/`accept` and name
   lookups go to the hooks the sandbox is built with (`on_connect`, `on_listen`, `on_resolve`,
   each `async` with the guest pid; `NetError`s map to errnos and resolver codes). The kernel's
   socket impersonation (`lkl/README.md`, items 15-16) keeps loopback the guest's and makes the
   program's socket a kernel socketpair end, so poll, epoll and nonblocking sockets work unchanged;
   exobox knows no protocol. The hooks run on a small async executor in the runtime, over its
   coroutines (`Cx`: `spawn`, `readable`/`writable` on held host fds, `sleep_until`, `now`, real
   wakers), so one long-lived task owns a multiplexed connection: a no_std, alloc-using async
   protocol core (capnweb's, with its `Runtime { spawn, now, sleep_until }` over `Cx`) runs on it
   unchanged, its allocations served after lockdown by exobox's allocator (talc over a region
   reserved before). capnix plugs in its Cap'n Web session this way. The idle `ppoll` takes up to
   eight fds; passed fds (`pass_fd`) poll as their host fd. Since the program shares the address
   space, the provider's connection must carry no more authority than the program's own. Left:
   threaded mode (the CPU token around the executor's kernel calls, a lock on its queues) and fork
   mode (the hooks run in init's process; a child's host ops forward to it).
10. Custom kernels, at build time: the kernel as its own Nix build (`lib.exoboxKernel { src, config }`:
   a source and a config fragment over `lkl/defconfig`, for more drivers or filesystems; LKL has
   no loadable modules), and `lib.mkExobox { kernel }` for an exobox built with it. In development,
   `EXOBOX_LKL_SRC` (another checkout) and `EXOBOX_LKL_CONFIG` (a fragment) select them. (Done:
   see "Building and testing".)

## Building and testing

```sh
./test            # everything, incremental, seconds warm (cargo-nextest)
./test --perf     # the performance budgets against native
```

`./test` enters the devshell (`flake.nix`, cached by `devshell.sh`) and builds the kernel out of
tree on first use (about 20 s). The kernel's source is the submodule `lkl/linux` (stock LKL plus
exobox's series, `lkl/README.md`), the same one `nix build` links: clone with
`git clone --recurse-submodules`, or `git submodule update --init lkl/linux`. `EXOBOX_LKL_SRC`
names another checkout (a worktree's, whose own submodule isn't checked out). `EXOBOX_LKL_CONFIG`
names a fragment of kernel config lines merged over `lkl/defconfig` (later lines win; a path
relative to the repository's root, or absolute). A change to any of them rebuilds what it touches:

```sh
echo CONFIG_SYSVIPC=y > sysv.config
EXOBOX_LKL_CONFIG=sysv.config ./test
EXOBOX_LKL_SRC=~/src/my-lkl ./test       # another kernel checkout
```

Kernel work happens in the submodule, on a branch of the kernel's repository. It reaches exobox as
one commit: the submodule's new commit, and whatever exobox needs for it (the host-operations
table, when the host interface moved), until `./test` passes. See `AGENTS.md` for how to work on it.

The distributed binary is one `nix build`. The kernel is its own derivation, built once (by
`lkl/Makefile`, from the submodule) and linked by the Rust build (`EXOBOX_LKL_PREBUILT`):

```sh
nix build                # exobox and exobox-erofs, in ./result/bin
nix build .#kernel       # the kernel alone: its archives, headers and .config
```

A custom kernel (more drivers or filesystems: LKL has no loadable modules) is a source and a config
fragment, from the flake's `lib`:

```nix
let exobox = builtins.getFlake "github:ryanrasti/exobox"; in
exobox.lib.mkExobox {
  kernel = exobox.lib.exoboxKernel {
    config = ''
      CONFIG_SYSVIPC=y
    '';
    # src = ./my-linux;  # default: the submodule lkl/linux
  };
}
```

or from the command line:
`nix build --impure --expr 'let f = builtins.getFlake (toString ./.); in f.lib.mkExobox { kernel = f.lib.exoboxKernel { config = "CONFIG_SYSVIPC=y\n"; }; }'`.
The package's `checkPhase` runs only the hermetic tests: lkl-sys's (the kernel it links boots) and
the unit tests of exobox and exobox-erofs.

## Modes

| Mode | Threads | Processes | Host syscalls allowed from the gate |
|---|---|---|---|
| `coroutine` (default) | the program's and the kernel's, as coroutines on one host thread | one | `write` (fds 1, 2), `read` (fd 0), `ppoll` (up to eight fds, no signal mask), `madvise` (inside the arena, one chunk, `MADV_DONTNEED`), `exit_group`; `read` and `write` on each held and passed fd (`hold_fd`, `pass_fd`) |
| `threaded` | a host thread per program thread, made lazily; one guest CPU passed between them | one | coroutine's, without `madvise`, plus `read`/`write` on the CPU-token eventfds, `clone` with exactly the thread flag set, `exit(0)` |
| `fork` | as threaded | a guest fork is a host fork; the processes share one guest kernel | threaded's, plus `clone(SIGCHLD)` with no stack |

`rt_sigreturn` from the gate (the SIGSYS handler's return) is allowed in every mode, and in
coroutine and threaded mode `kill` of the sandbox's own pid (a guest process that dies of a signal
makes the sandbox die of the same); the program's own `rt_sigreturn` traps, as it returns from a
handler the runtime ran. Anything else from the gate kills the sandbox (the CLI's hidden
`--deny=errno` returns `EPERM` instead, for the escape tests' probes). The list is only widened by
the typed calls (`pass_fd`, `hold_fd`: `read` and `write` on exactly that fd), and narrowed by
restrictions (`Builder::restrict`).

## License

GPL-2.0-only: exobox links the Linux kernel.
