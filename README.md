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
exobox run --deny=errno --allow 'getppid' -- ./probe  # one more host syscall, on top of the mode's
```

A program sees a Linux machine of its own: `/proc`, `/dev`, a writable `/tmp`, its stdio, and the
filesystems it was given (Nix store paths, erofs images). Its exit status is exobox's.

## The library

The CLI is a thin layer over a Rust library with three layers, each built only from the one
below:

```rust
// 1. Guest: the in-process kernel, and a program routed into it. No security policy.
let mut guest = exobox::Guest::boot(config)?;          // host work: reserve memory, boot the kernel
let store = guest.map_image("store.erofs")?;           // host mmap now, a read-only guest disk
let manifest = std::fs::read("manifest.json")?;        // still the host's syscalls
let setup = PreExec::new(move || {                    // from here on, syscalls go to the guest:
    exobox::setup::mount_erofs(&store, "/nix/store")?; //   ordinary Rust, in the guest:
    std::fs::write("/etc/app/manifest.json", &manifest)//   mounts, files, whatever the program needs
});
guest.run(Hooks { pre_exec: setup, ..Default::default() }, &argv, &env)
                                                       // then the program is exec'd; never returns

// 2. Security is a closure on top of that: install the host filter before the program starts.
// 3. Sandbox: Guest plus the default profiles (modes, deny action, extra rules).
let mut sb = exobox::Sandbox::boot(Mode::Threaded, config)?;
let store = sb.map_image(fd)?;
let channel = sb.hold_fd(provider_socket)?;            // a provider's connection, made before run
sb.run(Hooks {
    pre_exec: PreExec::new(move || exobox::setup::mount_erofs(&store, "/nix/store")),
    on_connect: OnConnect::new(move |cx, pid, addr| provider.connect(cx, channel, pid, addr)),
    on_resolve: OnResolve::new(move |cx, pid, name| provider.resolve(cx, channel, pid, name)),
    ..Default::default()                               // on_listen: none, so listens stay the guest's
}, &argv, &env)
```

- **`Guest::boot`** reserves the program's memory and the kernel's, boots the kernel, and sets up
  the guest's basics (`/proc`, `/dev`, `/tmp`, stdio). Everything up to `run` is ordinary host
  code.
- **`map_image`** is the one way to give the guest host data that it maps: the image is mapped
  before lockdown and becomes a read-only block device, `/dev/exobox/<name>`. exobox owns the
  mapping, which it later maps code from in place and shares across forks.
- **`run(hooks, argv, env)`** installs the routing filter, runs `hooks.pre_exec` as the guest's
  init (PID 1, the process the program becomes), then execs the program inside the guest. Inside
  `pre_exec` every syscall is the guest's: host data has to be read before `run` and moved in.
  Files and fds it leaves open are the program's.
- **The network hooks** (`exobox::net`): the program's sockets are its own for loopback; a
  `connect` anywhere else is `on_connect(cx, pid, addr)`, whose stream exobox copies to and from
  the program's socket (half-closes and resets carried both ways); a `listen` not bound to loopback
  is offered to `on_listen`, whose inbound streams the program accepts; name lookups (the guest's
  libc asking the nameserver in its `/etc/resolv.conf`) are `on_resolve(cx, pid, name)`. Errors
  are `NetError`s, which become errnos (`Refused` ECONNREFUSED, `Denied` EACCES, ...). With no
  hook, everything but loopback is unreachable. The hooks are async: they run after lockdown, on a
  small executor inside the sandbox (`Cx`: `spawn`, `now`, `sleep_until`, `readable`/`writable`
  on held fds), so one long-lived task can own a provider's multiplexed connection, a host fd held
  for it before `run` (`hold_fd`: the filter allows `read` and `write` on exactly it). futures-io's
  `AsyncRead`/`AsyncWrite` by default, tokio's with the `tokio` feature; `OnConnect::drive` hands a
  provider the program's end (`GuestSocket`) to drive itself.
- **The authority rule.** The hooks run in the program's address space: a compromised program
  can read and write their memory and drive the provider's connection itself. So that connection
  must carry no more authority than the program's own channel: policy (which addresses, which
  names) lives behind it, at its other end, never in the hook.
- **`Sandbox`** is `Guest` whose `pre_exec` runs the caller's setup and then stacks the security
  filter for the mode.
- **`exobox::setup`** holds small helpers for setup closures, written as ordinary Rust
  (`mount_erofs`, `mount_closure` for a Nix closure). The CLI's `exobox run` is
  `Sandbox::boot`, the closure's images mapped, `run` with `mount_closure`.

Anything setup needs beyond that is code: in the closure, or in the guest itself (a first program
that mounts `/dev/exobox/<name>` with `mount(2)` and execs the next one).

**Examples.** `examples/` has small, runnable programs that use the library this way
([examples/README.md](examples/README.md)): a Nix program with its closure and its startup and
memory measured (`nix-program`), composing the guest in `pre_exec` (`setup`), a host channel at
fd 1000 (`channel`), networking through a proxy that holds the policy (`net-policy`), coroutine
against threaded mode (`threads`), and the host filter refusing a hostile program (`escape`).
`cargo run -p exobox-examples --release --bin <name>`, from the devshell.

## How it works

- **Routing and security are two stacked seccomp filters.** The first (installed by `run`) traps
  every syscall the program makes (`SECCOMP_RET_TRAP`: a SIGSYS into exobox, which serves it) and
  allows everything from exobox's own syscall instruction, the gate. The second (the security
  filter, installed before the program starts) allows from the gate only the mode's list, with
  each argument pinned (exact fds, the program's memory, one `clone` flag set). With two filters
  the kernel takes the strictest answer, so the program's syscalls trap, and the gate gets exactly
  the list. The gate's address check is routing, not security: a compromised program can jump to
  the gate, and then only the list applies.
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
5. Templates: a booted kernel forked per sandbox (`Template::start`, `spawn`), the kernel's pages
   shared copy-on-write.
6. Within the performance budgets (`./test --perf`): startup, memory per sandbox, parallel builds.
7. Code mapped in place from the store images (done, in release-mode arenas: coroutine and fork),
   and a streaming image builder for stores that write images as paths arrive.
8. For capnix (`~/src/capnix-proper`, "What exobox needs to provide"): a host fd passed to the guest
   at a given fd (its Cap'n Web channel at 1000), with the filter widened to exactly that fd; the
   program run as a given uid (setup is the guest's init, as root, and can drop to it before exec);
   a read-write block device served over a channel (a new kernel driver: Nix's `/nix/var` on
   ext4); FUSE in the store's kernel (a config fragment); the streaming image builder (item 7) to
   the API in capnix's `spikes/storefs/README.md`.
9. Pluggable networking (done in coroutine mode): the guest's `connect`, `listen`/`accept` and name
   lookups go to the hooks the sandbox is given (`Hooks { on_connect, on_listen, on_resolve }`,
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
handler the runtime ran. `--deny=kill` (the default)
kills the sandbox on anything else from the gate; `--deny=errno` returns `EPERM`, for probing.
`--allow RULE` adds one syscall, with conditions on its arguments.

## License

GPL-2.0-only: exobox links the Linux kernel.
