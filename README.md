# unsharek
A sandboxing tool that runs unmodified Linux programs in a separate (unshared) kernel, secured by an
extremely minimal and tight seccomp filter: as few as 6 host syscalls.

A cold sandbox **runs bash in ~14ms with just 4.6MB PSS** (including bash itself)
A warm sandbox (forked from a template) **boots in just 3ms and costs an incremental 1.9MB PSS**


## Using it

```sh
unsharek --closure /nix/store/…-hello -- /nix/store/…-hello/bin/hello   # a store path and its closure
unsharek --system -- python3 -c 'print(6 * 7)'      # the host's system read-only: the easy way
unsharek --system --mode fork -- bash               # an interactive shell (anything that forks: fork mode)
```

**Host directories** (experimental): `--ro` serves one live and read-only, `--rw` read-write, each
through a confined server process of its own ([Filesystem](#filesystem)):

```sh
unsharek --system --mode fork --ro ./src:/src --rw ./out:/out -- bash -c 'cp -r /src/. /out/ && ls /out'
```

**Network** (experimental): `--net public` (public addresses only) or `--net all`, and `--publish`
for inbound ([Network](#network-experimental)):

```sh
unsharek --system --mode fork --net public -- curl -sI https://example.com    # connect
unsharek --system --mode fork --net all --publish 8080:8000 -- python3 -m http.server 8000
curl localhost:8080                                                         # listen, from the host
```

The program sees a Linux machine of its own: `/proc`, `/dev`, a writable `/tmp` (in the guest's
memory), its stdio, and what it was given read-only. Its environment is empty but for `--setenv`
and `--keep-env NAME`. Its exit status (or death by a signal) is unsharek's; 125 means the sandbox
itself failed.

## The library

The CLI is a thin layer over a Rust library:

```rust
let mut g = unsharek::Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() })?;
g.mount_closure(&[&program])?;                       // its store paths, mapped and mounted
g.run(|| std::fs::write("/etc/motd", "hi\n"))??;     // setup: this thread's syscalls are the guest's
let c = unsharek::SandboxConfig::new()
    .grant([0, 1, 2])                                // kept: none but these, and the guest's
    .pipe(|c| g.configure_sandbox(c))?;              // the guest's part, setup's last step
unsharek::lockdown(c)?;                              // unsharek-tcb's lockdown, re-exported as is
g.run(|| unsharek::execve(&argv, &env))?;            // after lockdown, run's closure is the program
```

Before lockdown the process is an ordinary one, and `run` closures are ordinary Rust whose syscalls
the guest kernel serves (mounts, files, ids). Templates (`fork`, `spawn`) copy a set-up guest for
more sandboxes, about 1 ms each. See [crates/unsharek](crates/unsharek/README.md) and
[examples/](examples/README.md).

## How it works

unsharek links [LKL](https://github.com/lkl/linux) (Linux as a library) into its own process. Before lockdown,
syscall user dispatch routes setup's calls to the guest kernel; after it, one seccomp filter traps
every call into the runtime, which serves it in the guest kernel. Only the runtime's own syscall
instruction reaches the host, and only for the mode's few calls.

| Crate | What it is |
|---|---|
| [unsharek](crates/unsharek/README.md) | The API, the CLI, and the batteries: setup, the store, the network hooks |
| [unsharek-tcb](crates/unsharek-tcb/README.md) | Lockdown and the one seccomp filter: the whole TCB |
| [seccomp-fn](seccomp-fn/README.md) | The filter's compiler, and seccomp-fn-verify, its proof (Kani) |
| [unsharek-rt](crates/unsharek-rt/README.md) | The runtime: the trap, dispatcher, scheduler, arena and loader |
| [lkl-sys](crates/lkl-sys/README.md) | The guest kernel: LKL plus unsharek's series, and its bindings |
| [unsharek-erofs](crates/unsharek-erofs/README.md) | Store images whose ELF files map in place |
| [unsharek-fs](crates/unsharek-fs/README.md) | Host directories: the virtio-fs device, whose server is a socket |
| [unsharek-fs-server](crates/unsharek-fs-server/README.md) | Plugin: the Landlock-confined file server for `--ro DIR`, `--rw DIR` |
| [unsharek-build](crates/unsharek-build/README.md) | The fixed-address link for binaries that embed unsharek |
| [guest-tests](crates/guest-tests/README.md), [fixtures](crates/unsharek-fixtures/README.md) | The tests: in the guest, and from the host |

## The TCB and Runtime Modes
By default `unsharek` runs Linux programs unmodified in `coroutine` mode, meaning that all in-guest threads are implemented as coroutines on a single host thread and non-preemptable. Most programs work in `coroutine` mode but for performance and compatibility, `unsharek` offers 3 modes:

| Mode | For | Threads | Processes | Host syscalls after lockdown |
|---|---|---|---|---|
| `coroutine` (default) | single programs | the program's and the kernel's, as coroutines on one host thread | one | `read`, `write` (granted fds), `ppoll` (≤ 8 fds), `kill` (itself), `exit_group`, `rt_sigreturn` |
| `threaded` | multithreaded programs | a host thread per program thread; one guest CPU passed between them | one | coroutine's, plus `clone` (a thread's exact flags) and `exit(0)` |
| `fork` | programs that fork (bash, make) | as threaded | a guest fork is a host fork; one shared guest kernel | threaded's, plus `clone(SIGCHLD)` or `clone(CLONE_PARENT \| SIGCHLD)`, no new stack |

That list, and lockdown's checks of what fds and mappings the process keeps, are the whole TCB:
nothing else in the process (the runtime, the guest kernel, the program) is trusted. The exact policy, each argument
pinned and proven equal to its compiled filter, is [unsharek-tcb's table](crates/unsharek-tcb/README.md).

The experimental features below widen it, explicitly: `--net` adds `recvmsg` on its control socket
and `close` of the connections it received, and both `--net` and `--ro`/`--rw` DIR add a host
process of their own, isolated by its own filter (and Landlock), much like a VM's device process.

## Network (experimental)
The guest kernel impersonates the program's sockets (inspired by libkrun's Transparent Socket
Impersonation): loopback stays in the guest; any other `connect` or `listen` is handed to the host.

The CLI provides two modes:
- `--net public`: the guest can reach public addresses only (no loopback, private ranges, link-local or metadata IPs)
- `--net all`: the guest can reach whatever the host can reach

Additionally, you can publish a port from the guest:
- `--publish [IP:]HOST:GUEST`: connections to HOST on the host reach the guest's listener on GUEST

## Filesystem
`--closure` store paths are mapped read-only before lockdown: their code maps in place, shared
across sandboxes through the host's page cache. `--system` serves the host's system directories
live instead.

**Plugin (experimental): host directories, live.** `--ro DIR[:AT]` and `--rw DIR[:AT]` serve a host
directory through Linux's stock virtio-fs driver, from a file server of its own
([unsharek-fs-server](crates/unsharek-fs-server/README.md): virtiofsd's passthrough file system,
confined by Landlock to the directory and by its own proven filter).

## Motivation: yet another sandbox?
A sandbox can be lightweight, interoperable, or strongly isolated. Until now you've had to pick two.

- **Containers** (Docker, bwrap, nsjail): lightweight and interoperable, but weak on isolation (shares the host kernel, hundreds of syscalls by default).
- **VMs** (Firecracker, Kata): strongly isolated, but heavy on memory overhead (tens of MB) and startup time (100+ms) and needs significant plumbing
- **Isolates** (Cloudflare Workers): lightweight but weaker interop (custom runtime) and isolation story (v8 is a huge TCB)
- **WASM**: lightweight and isolated, but can't run regular Linux programs
- **gVisor**: middling on all three: a reimplemented kernel (compatibility gaps), dozens of host syscalls, and a large TCB

`unsharek` is all three:
- **lightweight**: <5MB overhead per instance, milliseconds to boot
- **interoperable**: unmodified Linux programs on a real Linux kernel; pipes, sockets and stdio shared with the host like any process
- **isolated**: 6 host syscalls in coroutine mode, each argument pinned and proven: less host kernel surface than a VM's KVM interface, with a [~600-line TCB](crates/unsharek-tcb/README.md)

The timely reason is agents, but not for the reason you'd expect (i.e., sandboxing tool calls). Instead, it's that agents are producing code at a much faster rate than we can review or control. New primitives for fine-grained isolation, sharing, and policy are the bottleneck to deploying safely.

## Status and performance
`unsharek` has been run on  a handful for programs and works in every mode unless noted: unmodified dynamic and static programs (glibc, musl, Go), exec in
the guest, signals, ttys, pipes, threads, fork mode's processes, templates (coroutine and threaded),
the network. That said, it is early and expect rough edges.

Very little has been done yet in terms of work for performance and there is no fundamental reason that the architecture
cannot approach (and in some cases even beat -- such as in the case of syscall heavy code which in the guest can simply
be  function call) native Linux programs. 

Preliminary numbers:

| | native | coroutine | threaded | fork |
|---|---|---|---|---|
| idle bash, PSS (8 at once) | 0.9 MB | 4.6 MB | 4.6 MB | 4.8 MB |
| template child, PSS / start | - | 1.9 MB / 3.0 ms | 1.9 MB / 3.8 ms | - |
| `getppid` | 0.16 µs | 2.7 µs | 2.8 µs | 2.8 µs |
| `xz -T1`, 8 MB | 0.44 s | 1.05x | 1.05x | 1.06x |
| `xz -T4`, 8 MB | 0.15 s | 3.30x | 1.10x | 1.13x |
| `rustc`, 16 codegen units | 1.24 s | - | 1.09x | 1.05x |
| `make -j4`, 12 C files | 0.70 s | - | - | 2.04x |

Medians on a 24-CPU Core Ultra 9, 2026-11-19: the full table, with spreads, is
[bench/STATS.md](bench/STATS.md) (`cargo xtask stats`, under a minute; [bench/](bench/README.md)).
The guest has one CPU, which is most of the build gap ([bench/PERF.md](bench/PERF.md)). Known
limits:

- **Fork mode:** `MAP_SHARED` memory across a fork, and templates.
- **Signals to running code** are delivered at the thread's next syscall, in every mode: a loop
  that makes no calls can't be interrupted from inside the guest (not even by `timeout`), and Go's
  asynchronous preemption doesn't land. In coroutine mode such a loop also stalls every other thread.
- **No MMU:** LKL is a no-MMU Linux, so compatibility isn't complete: a bad pointer passed to a call
  ends the sandbox (SIGSEGV) rather than returning EFAULT, and fork is fork mode's, not the kernel's.
- **At most 256 store paths** through `--closure`. `exec` of `/proc/self/exe` is ENOEXEC: the guest
  kernel keeps one exe link for every process (init's), which the runtime answers `readlink` for
  but can't exec.

## Development

```sh
nix develop                  # or `direnv allow`; the devshell
cargo xtask test             # everything, incremental, seconds warm (cargo-nextest; args pass through)
cargo xtask test -E 'test(/::fork$/)'   # one mode of the suite
cargo xtask perf             # the performance budgets; `vs-native` for build workloads
cargo xtask stats            # the headline numbers, into bench/STATS.md
cargo xtask prove            # Kani: the filter is its policy (minutes)
nix build                    # the distributed binary; .#checks.x86_64-linux.smoke, the release check
```


## License

GPL-2.0-only: unsharek links the Linux kernel.
