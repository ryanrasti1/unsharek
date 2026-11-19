# exobox

Run unmodified Linux programs on an in-process Linux kernel, behind a seccomp filter that leaves the
host a handful of syscalls.

exobox links [LKL](https://github.com/lkl/linux) (Linux as a library) into its own process. A
program's syscalls never reach the host kernel: each one traps into exobox and is served by the
guest kernel, or by exobox itself. What the host sees after lockdown is a short allowlist
(`write` to stdout and stderr, one timed wait, an exit, and a few more depending on the mode),
pinned down to the argument. The guest kernel provides compatibility (files, sockets on loopback,
processes, signals, ttys). The security boundary is the host filter, not the guest kernel.

Status: preview (November 2026). All three modes run real programs: bash, Python, gcc under
`make -j4`, rustc and cargo, xz, a nixpkgs package built from source (by capnix, as Nix's builder,
with Nix's own output hash), and static binaries from three toolchains (Go with CGO off, musl's
busybox, a glibc `-static-pie` program). "Status" below lists what isn't done yet.

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

The CLI is a thin layer over a Rust library. A guest is booted (the guest kernel, in this
process), given host data, set up, locked down, and run:

```rust
let mut g = exobox::Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() })?;
g.on_connect(OnConnect::new(|cx, pid, addr| provider.connect(cx, pid, addr)))?;
g.on_resolve(OnResolve::new(|cx, pid, name| provider.resolve(cx, pid, name)))?;
let store = g.map_closure(&program, &[])?;             // host work: a Nix closure's images mapped
g.pass_fd(channel, 1000)?;                             // a host fd as the guest's fd 1000
g.hold_fd_as("net", provider_socket)?;                 // a provider's connection, for the hooks
let manifest = std::fs::read("manifest.json")?;        // the host's syscalls
g.run(|| -> std::io::Result<()> {                      // this thread's syscalls are the guest's:
    exobox::setup::mount_closure(&store)?;             //   ordinary Rust, as the guest's init:
    std::fs::write("/etc/app/manifest.json", &manifest) //  mounts, files, ids, the hostname
})??;                                                  // and the host's again
let locked = g.lockdown(|s| {                          // exobox-tcb's lockdown, with the grants
    s.grant(0).grant(1).grant(2);
    Ok(())
})?;
locked.exec(&argv, &env)                               // the program; never returns
```

- **`Guest::boot(GuestConfig { mode, .. })`** reserves the program's memory and the kernel's, boots
  the kernel, and sets up the guest's basics (`/proc`, `/dev`, `/tmp`, stdio). The network hooks
  are set on the guest (`on_connect`, `on_listen`, `on_resolve`, `on_start`).
- **`map_image`** is the one way to give the guest host data that it maps: the image is mapped
  (a host `mmap`) and becomes a read-only block device, `/dev/exobox/<name>` (`map_image_as` names
  it). exobox owns the mapping, which it later maps code from in place and shares across forks.
  `map_closure(program, allow_paths)` maps a Nix program's closure from the image cache (built
  where missing; `map_store` for a `store::Store` of one's own), each with where it mounts.
- **`g.run(closure)`**, before lockdown, runs the closure with every syscall of the calling thread
  served by the guest kernel, as its init (PID 1, root): anything the guest kernel can do, setup
  can (mounts, files, `setresuid`, `sethostname`, `clock_settime`). Memory calls stay the host's,
  so what is allocated inside is ordinary host memory. The routing is syscall user dispatch,
  per thread and switched by a selector byte: free to turn on and off, so closures come and go,
  interleaved with host work, and between them the process is an ordinary one (threads, signals,
  fork, and exec of host programs all work natively). Only the calling thread is routed.
- **`g.lockdown(|s| grants)`** makes the guest's own host fds (threaded mode's CPU-token
  eventfds, fork mode's pidfd), installs the hooks and calls exobox-tcb's lockdown (below, "Where
  isolation is") with the caller's grants: `s.grant(fd)` keeps an fd open, for `read` and `write` as
  its own mode allows (an `O_RDONLY` file can't be written). Nothing is granted by default, stdio
  included (`exobox::stdio` grants 0-2 as the CLI does); passed and held fds are granted. Every fd neither granted
  nor the guest's is closed. Then threaded mode's kernel thread starts, under the filter. The
  process must be single-threaded by then.
- **`locked.exec(argv, env)`** is the guest's exec of the program, with init's credentials as
  setup left them; it returns only if the program couldn't be started. **`locked.run(|| -> i32)`**
  instead runs a closure as the program: on this thread, its syscalls trapped and served as an
  exec'd program's are, its return value the exit status (`exobox::execve` inside it is the exec).
  For tests and for programs written in Rust against exobox; single-threaded (the escape example
  is one). The runtime's loader refuses to exec before lockdown.
- **`pass_fd(fd, n)`** gives the guest host fd `fd` as its fd `n`, now, and `hold_fd(fd)` keeps
  one for the hooks; lockdown grants each `read` and `write`. Grants are the only way to widen
  the filter. A caller that wants it narrower installs a seccomp filter of its own before
  lockdown: filters stack, and the strictest answer wins.
- **Templates.** `fork()` (or `spawn(|g| { setup; g.lockdown(..)?.exec(..) })`) forks the guest's
  process before lockdown: the child is a guest of its own, a copy of this one as it is (the booted
  kernel, its mounts and files, shared copy-on-write), to set up further (its own images, fds,
  setup), lock down and run; the parent goes on forking more and waits for them (`exobox::wait`,
  `waitpid`). Each child's guest RNG is reseeded with fresh host entropy, and threaded mode's
  host threads and CPU tokens are made at each child's own lockdown. A child starts to READY in
  about a millisecond and costs under 2 MB (`./test --perf`). Coroutine and threaded mode (a
  fork-mode template: not yet).
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
- **A hook is not a policy point.** The hooks run after lockdown, in the program's address space:
  a compromised program can read and write their memory, skip any check they make, and drive the
  provider's connection itself. So that connection must carry no more authority than the
  program's own channel: policy (which addresses, which names) is enforced at its far end, in the
  provider's own process, never in a hook. Anything a hook decides, a compromised program can
  skip. The network's only part of the TCB is the held fds: which ones, and the filter pinning
  `read` and `write` to exactly them.
- **Where isolation is.** In `exobox-tcb` (`tcb/`, its own crate: seccompiler and libc, nothing
  of exobox's), about 800 lines with comments (its tests and the old compiler apart) ([tcb/README.md](tcb/README.md): the guarantee, what
  isn't guaranteed, the design and a review checklist). `Sandbox::configure_and_lockdown` takes
  the caller's grants and a `Confined` guest (its own fds, its mode, its gate's address) and, in
  order: checks there is exactly one thread; checks the guest's fds are eventfds (and in fork mode
  a pidfd); checks every mapping is private, read-only, or fork mode's shared anonymous memory;
  closes every fd neither granted nor the guest's; turns core dumps and dumpability off; drops
  every capability; sets `no_new_privs`; and installs **one
  seccomp filter** with TSYNC: a hand-written gate check (a call not from the runtime's one
  syscall instruction is TRAP, served in-process, in every thread and process made after; another
  ABI is KILL) and then seccompiler's allowlist for the mode, each argument pinned, KILL for the
  rest. Nothing else protects the host: the runtime, the guest kernel, the hooks, the store and
  exobox's API run in the process after lockdown (or decide only what the guest sees, before it),
  and a bug in them breaks the guest, never the host.
- **Layers.** `exobox` (`native/exobox`: the API, the CLI and the batteries `setup`, `store`,
  `net`, `alloc`) over `exobox-tcb`, and three internal crates, none of them trusted: `exobox-rt`
  (`native/rt`, the runtime: boot, the gate, syscall user dispatch, the dispatcher, scheduler,
  arena and loader; it knows nothing of the filter), `lkl-sys` (the kernel, the runtime's alone)
  and `exobox-erofs` (images). The CLI's `exobox run` is `exobox::run(Config)`: `Guest::boot`, the
  closure's images mapped, `mount_closure` in a `run` closure, `lockdown` with stdio granted,
  `exec`.
- **Embedding.** exobox sets the process's global allocator (the hooks allocate after lockdown,
  from a region reserved at build). A binary that embeds it links at a fixed address as the CLI
  does with one call in its `build.rs`, `exobox_build::link_fixed_address()` (`native/build`): a
  PIE's relocations would cost each sandbox ~400 KB.

Anything setup needs beyond that is code: in a `run` closure, or in the guest itself (a first program that
mounts `/dev/exobox/<name>` with `mount(2)` and execs the next one).

**Examples.** `examples/` has small, runnable programs that use the library this way
([examples/README.md](examples/README.md)): a Nix program with its closure and its startup and
memory measured (`nix-program`), composing the guest in setup closures (`setup`), a host channel at
fd 1000 (`channel`), networking through a proxy that holds the policy (`net-policy`), coroutine
against threaded mode (`threads`), and the host filter refusing a hostile program (`escape`).
`cargo run -p exobox-examples --release --bin <name>`, from the devshell.

## How it works

- **Two mechanisms, two jobs.** Before lockdown, routing is **syscall user dispatch** (SUD):
  per thread, with a selector byte the runtime flips to turn it on and off (no syscall), and the
  gate (exobox's own syscall instruction) exempt. Setup closures run with it on, so their syscalls
  trap (SIGSYS into exobox, which serves them in the guest); between them it is off and the
  process is an ordinary one. SUD is not inherited by new threads or forks and is cleared by exec,
  so it never follows host code anywhere. From lockdown on, isolation is **one seccomp filter**,
  installed once, with TSYNC, as lockdown's last act; every thread and process made after inherits
  it. Its hand-written gate check sends every call not from the gate to TRAP (the same SIGSYS
  entry; the handler accepts both kinds of trap) and kills other ABIs; seccompiler's allowlist of
  the mode's calls, each argument pinned (granted fds with their access, one `clone` flag set,
  the sandbox's own pid), judges the gate's. The gate check answers only TRAP or KILL, so the
  gate's address stays routing, not security: a compromised program can jump to the gate, and
  then only the list applies. SUD is switched off at lockdown; no SUD or `prctl` rule is in the
  filter.
- **Lockdown.** Before anything the program brings runs (its exec, its interpreter, a `run`
  closure, the hooks' first task), exobox-tcb checks there is one thread, the guest's fds and
  every mapping, closes every fd not granted (`close_range`), turns core dumps off, drops
  capabilities, sets `no_new_privs` and installs the filter (tcb/README.md). The runtime's host
  threads (threaded mode's kernel idler, then one per program thread) start after it, through the
  filter's one `clone`.
- **The trap.** The SIGSYS frame is moved off the program's stack (Go makes syscalls with ~128
  bytes to spare), the FS register switched to exobox's and back, and the call dispatched: to the
  guest kernel (x86-64 numbers translated to the generic table, structs translated), rewritten
  (`open` to `openat`, `fork` to `clone`, ...), emulated (memory, threads, futexes, the thread
  pointer), or refused. About 1 µs a call.
- **Signals** are the guest kernel's: actions, masks, delivery, default actions. At a call's
  return it hands a caught signal to the runtime, which builds Linux's frame on the program's stack
  (or its alternate stack) and runs the handler as the program; the handler's `rt_sigreturn` traps
  and hands the registers and mask back. A death by a signal is the sandbox's, by the same signal.
- **Memory.** Before lockdown exobox reserves one region for the program (its arena): readable,
  writable and executable, so JITs work. After lockdown there is no host `mmap`: the program's
  memory calls are served from the arena. In every mode memory stays at its peak (no `madvise`:
  with host threads it would race their page faults, the Dirty-COW class, and one model for every
  mode is simpler); freed pages are cleared when handed out again, only those that were written.
- **Exec inside the guest.** exobox locks down first, then loads the program from the guest's
  files into the arena, with its interpreter, and builds its stack. Nothing the program brings (its
  `PT_INTERP`, its libraries' constructors) runs before the filter is in place.
- **The store.** A Nix program's closure is shown as erofs images, one per store path, built once
  and cached (the closure itself too: a store path's never changes). A store path that is a file
  or a symlink (a setup hook, a source tarball) gets an image whose root holds it: the file is
  bind-mounted from it onto its store path (nothing copied), the symlink made. Their layout pads each ELF
  file to its memory image, so code is mapped in place: each image is mapped twice before
  lockdown, read-only for the guest's block device and privately into the arena's top (read-only
  there too, but for each ELF's writable segments, from the image's layout), and the program's
  mappings of its files are answered with where their bytes already are there, shared by every
  sandbox through the host's page cache, at every exec in every mode (its data pages get the
  file's bytes copied in, its own). Library code is never writable, as natively.
- **The network.** The kernel impersonates the program's AF_INET sockets (its `tsi.c`, after
  libkrunfw's Transparent Socket Impersonation, with direct calls to the host instead of vsock):
  loopback, binds and listens are an inner socket of the guest's own; any other connect is a host
  op, answered when the hook is, and then the socket's bytes go through a kernel socketpair whose
  other end the runtime reads and writes, woken by the kernel when it can. So poll, epoll,
  nonblocking connects and `SO_ERROR` work as on Linux, and the runtime knows no protocol. A
  datagram to port 53 is a resolver query, answered from `on_resolve`. The runtime's executor waits
  on the hooks' host fds in the scheduler's idle wait (one `ppoll` over up to eight fds); passed
  fds (`pass_fd`) poll as their host fd does, the same way.
- **Fork mode: a guest fork is a host fork.** The kernel's clone calls a host op inside it, and
  the runtime forks its process; the processes run one kernel. Shared between them, mapped shared
  before lockdown: the kernel's memory (its data, its pool, every coroutine stack: kernel code
  keeps objects on its stack that other processes reach, so every trap, init's main thread's too,
  is served on one) and the runtime state that runs it (the scheduler, the CPU token and every
  process's host-thread slots, the host ops' pools, the futex table, keyed by process). Private,
  copied by the fork: the program's memory and the runtime's per-process state. Each process's
  threads take turns on threaded mode's CPU token, a hand-off to a thread of another process being
  a write to its eventfd. A process's `exit_group` and fatal signals are the kernel's, its parent
  waits for the status, and its last task's end ends the host process; init's end is the
  sandbox's (the others see its pidfd and exit), and a process that dies on the host (a crash, the
  filter's kill) ends the sandbox too, seen by init's SIGCHLD (every process is init's host child).
  `--max-procs` bounds the processes alive at once (a fork past it is EAGAIN). exec is the guest's,
  in the process's own arena (high-water: an exec reuses the old image's pages).
- **The guest's machine.** Booting sets its realtime clock to the host's (the kernel's clock is
  the host's monotonic one), makes `/proc`, `/dev` (its nodes 0666, devpts), `/tmp` and
  `/dev/shm`, seeds its RNG from the host, brings loopback up and makes fds 0-2 the host's stdio.
  With a network hook, `/etc/resolv.conf` and `/etc/hosts` are written when it is set, before setup.
- **The kernel.** Stock LKL plus a short series (`lkl/README.md`): idle that waits instead of
  spinning, the program as PID 1, threads that join their process, a block device over host memory,
  host fds as guest files, fork and exec's kernel halves, socket impersonation, and the rest of what
  a cooperative in-process host needs.

## Status

Works, in every mode unless noted: the escape and hostile-loader probes, exec inside the guest,
the store mounted from images, signals, ttys, pipes and host fds, threads, fork mode's processes,
templates (coroutine and threaded), the network hooks (coroutine and threaded; fork mode in
init's process), custom kernels. `./test` runs about 590 cases in a few seconds.

Not yet, or known limits:

- **Fork mode:** a forked process's network beyond loopback (the hooks run in init's process; a
  child's connect is ENETUNREACH for now), `MAP_SHARED` memory shared across a fork, and templates.
- **Credentials:** after a setup closure drops root, exobox's own later setup calls run with what it left:
  a template's `fork`/`spawn` (the child's RNG reseed needs CAP_SYS_ADMIN) and `map_image` (mknod
  needs CAP_MKNOD) fail. Drop root in the last setup closure, after any `map_image`.
- **Bad pointers:** LKL has no MMU, so a bad pointer passed to a call the guest kernel serves is
  read by it as is, and is the sandbox's SIGSEGV rather than the program's EFAULT. It ends the
  sandbox, not more. Calls programs make with bad pointers on purpose (`statx`'s probe) are
  checked first.
- **GS:** exobox doesn't use it, so a program may; the program's FS is switched on every trap.
- **Signals to running code:** a signal for a thread running user code is delivered at its next
  call. Go's asynchronous preemption (SIGURG to a loop with no calls) doesn't land, so such a loop
  isn't preempted: with `GOMAXPROCS=1`, or at a GC's stop-the-world, the others wait until it makes
  a call. In coroutine mode a thread in user code keeps every other thread from running.
- **Closure size:** at most 256 images (store paths, allowed directories) a sandbox; more fails
  at startup with "No space left on device" (`exobox_rt::memblk::MAX`).
- **`/proc/self/exe`:** `readlink` of it is answered; exec of it is ENOEXEC.
- **Performance:** see below.

## Performance

| | native | sandbox |
|---|---|---|
| startup to READY (coroutine) | - | ~5 ms, ~4.2 MB PSS |
| a template's child | - | ~1 ms, under 2 MB |
| a syscall (`getppid`) | 0.08 µs | ~1.3 µs |
| `xz -T4`, 16 MB (threaded) | 0.13 s | 1.12x |
| `rustc`, 16 codegen units (fork) | 1.57 s | 2.82x |
| `make -j4`, 32 C files (fork) | 1.21 s | 3.19x |

The goal is parallel builds within 5% of native. Where the time goes (`native/PERF.md`, measured
with the counters in `native/bench`): the sandbox reports one CPU, so rustc compiles serially;
the guest's one CPU token is taken for work that needs no kernel (futexes, `mprotect`), and handed
to threads that are still asleep; and exec copies every program and library into the process's
memory in threaded and fork mode, under the token. The kernel's own work is a small share (~0.3 s
of make's gap). Those fixes come first; an SMP guest kernel (guest CPUs as a pool of tokens) for
what remains.

## Next

1. The performance fixes above, in `native/PERF.md`'s order, remeasured after each.
2. Fork mode's network: a forked process's hook calls forwarded to init's executor.
3. Images from extents: `map_image` over an ordered list of {metadata | a range of a host file |
   zeros} (the kernel side and `exobox_erofs::synthesize` exist), so a closure's files are shown
   as they are in the host store, nothing copied.
4. An SMP guest kernel, if the numbers still call for it.
5. Closures from pre-built images: a mount source of one erofs image per store path, built by the
   caller's own Nix derivation (a closure shown per file costs a host mapping per file, which every
   fork copies and every exit tears down). `build` stays deterministic (a tested property), so
   Nix's store optimisation hard-links identical images.

## Building and testing

```sh
./test            # everything, incremental, seconds warm (cargo-nextest)
./test --perf     # the performance budgets against native
native/bench/run --work rustc,make --modes native,fork   # build workloads, with counters
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
nix build .#checks.x86_64-linux.smoke   # the release check (nix/smoke.nix)
```

The smoke check runs the package's `exobox` in all three modes inside Nix's build sandbox (Nix's
seccomp filter under exobox's, the sandbox's `/dev` and `/proc`, no `$HOME`), on hello, Python,
bash, a Go program and busybox, each output checked. The image cache is `$EXOBOX_IMAGE_CACHE`
(else `$XDG_CACHE_HOME/exobox/images`, else `~/.cache/exobox/images`), and closures come from
`nix-store --query --requisites`: in a build with no Nix database, the check registers its
programs' closure in one of its own (`closureInfo`, `nix-store --load-db` under `NIX_STATE_DIR`).

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
| `coroutine` (default) | the program's and the kernel's, as coroutines on one host thread | one | `write` (fds 1, 2), `read` (fd 0), `ppoll` (up to eight fds, no signal mask), `exit_group`; `read` and `write` on each held and passed fd (`hold_fd`, `pass_fd`) |
| `threaded` | a host thread per program thread, made lazily; one guest CPU passed between them | one | coroutine's, plus `read`/`write` on the CPU-token eventfds, `clone` with exactly the thread flag set, `exit(0)` |
| `fork` | as threaded | a guest fork is a host fork; the processes share one guest kernel | threaded's, plus `clone(SIGCHLD)` (from init's process) or `clone(CLONE_PARENT \| SIGCHLD)` (from the others), with no stack |

`rt_sigreturn` from the gate (the SIGSYS handler's return) is allowed in every mode, and `kill` of
the sandbox's own pid (fork mode: init's process's; a guest init that dies of a signal makes the
sandbox die of the same, and in fork mode so does a process that dies on the host); the program's
own `rt_sigreturn` traps, as it returns from a handler the runtime ran. Anything else from the gate
kills the sandbox. The list is only widened by grants (`pass_fd`, `hold_fd`, `s.grant`: `read`
and `write`, as granted, on exactly that fd).

## License

GPL-2.0-only: exobox links the Linux kernel.
