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
guest.run(&argv, &env, move || {                       // from here on, syscalls go to the guest
    exobox::setup::mount_erofs(&store, "/nix/store")?; //   ordinary Rust, in the guest:
    std::fs::write("/etc/app/manifest.json", &manifest)//   mounts, files, whatever the program needs
})                                                     // then the program is exec'd; never returns

// 2. Security is a closure on top of that: install the host filter before the program starts.
// 3. Sandbox: Guest plus the default profiles (modes, deny action, extra rules).
let mut sb = exobox::Sandbox::boot(Mode::Threaded, config)?;
let store = sb.map_image(fd)?;
sb.run(&argv, &env, move || exobox::setup::mount_erofs(&store, "/nix/store"))
```

- **`Guest::boot`** reserves the program's memory and the kernel's, boots the kernel, and sets up
  the guest's basics (`/proc`, `/dev`, `/tmp`, stdio). Everything up to `run` is ordinary host
  code.
- **`map_image`** is the one way to give the guest host data that it maps: the image is mapped
  before lockdown and becomes a read-only block device, `/dev/exobox/<name>`. exobox owns the
  mapping, which it later maps code from in place and shares across forks.
- **`run(argv, env, before_exec)`** installs the routing filter, runs `before_exec` as the guest's
  init (PID 1, the process the program becomes), then execs the program inside the guest. Inside
  the closure every syscall is the guest's: host data has to be read before `run` and moved in.
  Files and fds the closure leaves open are the program's.
- **`Sandbox`** is `Guest` whose `before_exec` runs the caller's setup and then stacks the
  security filter for the mode.
- **`exobox::setup`** holds small helpers for setup closures, written as ordinary Rust
  (`mount_erofs`, `mount_closure` for a Nix closure). The CLI's `exobox run` is
  `Sandbox::boot`, the closure's images mapped, `run` with `mount_closure`.

Anything setup needs beyond that is code: in the closure, or in the guest itself (a first program
that mounts `/dev/exobox/<name>` with `mount(2)` and execs the next one).

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
- **Memory.** Before lockdown exobox reserves one region for the program (its arena): readable,
  writable and executable, so JITs work. After lockdown there is no host `mmap`: the program's
  memory calls are served from the arena, and freed pages go back with `madvise` where the mode
  allows it.
- **Exec inside the guest.** exobox locks down first, then loads the program from the guest's
  files into the arena, with its interpreter, and builds its stack. Nothing the program brings (its
  `PT_INTERP`, its libraries' constructors) runs before the filter is in place.
- **The store.** A Nix program's closure is shown as erofs images, one per store path, built once
  and cached. Their layout pads each ELF file to its memory image, so code can be mapped in place
  and shared by every sandbox through the host's page cache.
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
7. Code mapped in place from the store images, and a streaming image builder for stores that
   write images as paths arrive.
8. For capnix (`~/src/capnix-proper`, "What exobox needs to provide"): a host fd passed to the guest
   at a given fd (its Cap'n Web channel at 1000), with the filter widened to exactly that fd; the
   program run as a given uid (setup is the guest's init, as root, and can drop to it before exec);
   a read-write block device served over a channel (a new kernel driver: Nix's `/nix/var` on
   ext4); FUSE in the store's kernel (a config fragment); the streaming image builder (item 7) to
   the API in capnix's `spikes/storefs/README.md`.
9. Pluggable networking: the guest's `connect`, `listen`/`accept` and name lookups go to a provider
   the sandbox is given (`sb.net(impl Net)`: `async fn connect(addr, guest: SocketEnd)`,
   `resolve(name)`, `listen(addr, incoming)`, with the guest pid; errors map to errno). It runs on a
   small async executor in the runtime, over its coroutines (`spawn`, `readable(fd)`/`writable(fd)`
   on held host fds and guest socket ends, `sleep_until`, real wakers), so one long-lived task can
   own a multiplexed connection: a no_std, alloc-using async protocol core runs on it unchanged.
   exobox makes a socketpair end the program's fd, so poll, epoll, nonblocking sockets and fork work
   unchanged; it knows no protocol. capnix plugs in its Cap'n Web session this way. Needs `ppoll`
   on a few host fds at once (the filter allows one today). Since the program shares the address
   space, the provider's connection must carry no more authority than the program's own.
10. Custom kernels, at build time: the kernel as its own Nix build (`lib.exoboxKernel { src, config }`:
   a source and a config fragment over `lkl/defconfig`, for more drivers or filesystems; LKL has
   no loadable modules), and `lib.mkExobox { kernel }` for an exobox built with it. In development,
   `EXOBOX_LKL_REF` or `EXOBOX_LKL_SRC`, and `EXOBOX_LKL_CONFIG` (a fragment) select them. (Done:
   see "Building and testing".)

## Building and testing

```sh
./test            # everything, incremental, seconds warm (cargo-nextest)
./test --perf     # the performance budgets against native
```

`./test` enters the devshell (`flake.nix`, cached by `devshell.sh`) and builds the kernel out of
tree on first use (about 20 s). The kernel's source is the commit `flake.lock` pins for the `linux`
input, the same one `nix build` links, taken from `EXOBOX_LKL_REPO` (default
`/home/ryan/src/lkl-linux`) into `target/lkl-src` (when the pin changes, only the files that
changed are rewritten). `EXOBOX_LKL_REF` names another commit or a branch (its committed head,
followed as it moves) and `EXOBOX_LKL_SRC` a checkout to build as it is, both for work on the
kernel. `EXOBOX_LKL_CONFIG` names a fragment of kernel config lines merged over `lkl/defconfig`
(later lines win; a path relative to the repository's root, or absolute). A change to any of them
rebuilds what it touches:

```sh
echo CONFIG_SYSVIPC=y > sysv.config
EXOBOX_LKL_CONFIG=sysv.config ./test
EXOBOX_LKL_REF=exobox/native ./test      # the kernel branch's committed head
EXOBOX_LKL_SRC=~/src/my-lkl ./test       # a kernel checkout, uncommitted edits included
```

A kernel bump is one commit: `nix flake update linux` (the pin moves to the branch's head), then
whatever exobox needs for it (the host-operations table, when the host interface moved), until
`./test` passes; flake.lock and those changes are committed together. See `AGENTS.md` for how to
work on it.

The distributed binary is one `nix build`. The kernel is its own derivation, built once (by
`lkl/Makefile`, from the flake's `linux` input) and linked by the Rust build
(`EXOBOX_LKL_PREBUILT`):

```sh
nix build                # exobox and exobox-erofs, in ./result/bin
nix build .#kernel       # the kernel alone: its archives, headers and .config
nix flake update linux   # bump the pinned kernel (flake.lock) to the branch's head: see above
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
    # src = ./my-linux;  # default: the flake's linux input
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
| `coroutine` (default) | the program's and the kernel's, as coroutines on one host thread | one | `write` (fds 1, 2), `read` (fd 0), `ppoll` (one fd, no signal mask), `madvise` (inside the arena, one chunk, `MADV_DONTNEED`), `exit_group` |
| `threaded` | a host thread per program thread, made lazily; one guest CPU passed between them | one | coroutine's, without `madvise`, plus `read`/`write` on the CPU-token eventfds, `clone` with exactly the thread flag set, `exit(0)` |
| `fork` | as threaded | a guest fork is a host fork; the processes share one guest kernel | threaded's, plus `clone(SIGCHLD)` with no stack |

`rt_sigreturn` (the SIGSYS handler's return) is allowed in every mode. `--deny=kill` (the default)
kills the sandbox on anything else from the gate; `--deny=errno` returns `EPERM`, for probing.
`--allow RULE` adds one syscall, with conditions on its arguments.

## License

GPL-2.0-only: exobox links the Linux kernel.
