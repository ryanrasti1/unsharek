# unsharek

A sandboxing tool that runs unmodified Linux programs in a separate (unshared) kernel, secured by a
strict seccomp filter: as few as 8 host syscalls, each argument pinned.

unsharek links [LKL](https://github.com/lkl/linux) (Linux as a library) into its own process. It then
traps the program's syscalls and serves them in the guest kernel. It is secured by applying an
extremely minimal seccomp profile.

See [crates/unsharek-tcb/README.md](crates/unsharek-tcb/README.md) for the TCB and the security
guarantees: about 600 lines, and the filter is proven equal to its policy.

## Using it

```sh
unsharek -- /nix/store/…-hello/bin/hello                # a Nix program: its closure is mounted read-only
unsharek --mode threaded -- $(which python3) -c 'print(6 * 7)'
unsharek --mode fork -- $(which bash) -c 'ls / | wc -l'  # anything that forks: fork mode
unsharek --ro ./data --setenv LANG=C.UTF-8 -- $(which sort) ./data/words   # a host directory, live
unsharek --mode fork --rw $PWD/out -- $(which bash) -c "echo built > $PWD/out/result"  # read-write
unsharek --image app=./app.erofs:/app -- /app/bin/server
```

The program sees a Linux machine of its own: `/proc`, `/dev`, a writable `/tmp` (in the guest's
memory), its stdio, and what it was given read-only. Its environment is empty but for `--setenv`
and `--keep-env NAME`. Its exit status (or death by a signal) is unsharek's; 125 means the sandbox
itself failed.

## The library

The CLI is a thin layer over a Rust library:

```rust
let mut g = unsharek::Guest::boot(GuestConfig { mode: Mode::Coroutine, ..Default::default() })?;
let mounts = g.map_closure(&program, &[])?;      // host work: the closure's images mapped
g.run(|| unsharek::setup::mount_closure(&mounts))??; // this closure's syscalls are the guest's: its init
let locked = g.lockdown(|s| {                     // unsharek-tcb: checks, closes every other fd,
    s.grant(0).grant(1).grant(2);                 // installs the filter; grants are the only way out
    Ok(())
})?;
locked.exec(&argv, &env)                          // the program; returns only if it couldn't start
```

Before lockdown the process is an ordinary one, and `run` closures are ordinary Rust whose syscalls
the guest kernel serves (mounts, files, ids). Templates (`fork`, `spawn`) copy a set-up guest for
more sandboxes, about 1 ms each. See [crates/unsharek](crates/unsharek/README.md) and
[examples/](examples/README.md).

## How it works

Syscall user dispatch routes a thread's syscalls to the guest kernel before lockdown, switched on
and off per closure. Lockdown (unsharek-tcb) checks there is one thread and that every fd and
mapping is allowed, closes the rest, and installs one seccomp filter: from then on every syscall
traps (SIGSYS) into the runtime, which serves it in the guest kernel; only the runtime's own
syscall instruction may reach the host, and only for the mode's few calls.

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

## Modes

| Mode | For | Threads | Processes | Host syscalls after lockdown |
|---|---|---|---|---|
| `coroutine` (default) | single programs | the program's and the kernel's, as coroutines on one host thread | one | `read`, `write` (granted fds), `ppoll` (≤ 8 fds), `kill` (itself), `exit_group`, `rt_sigreturn` |
| `threaded` | multithreaded programs | a host thread per program thread; one guest CPU passed between them | one | coroutine's, plus `clone` (a thread's exact flags) and `exit(0)` |
| `fork` | programs that fork (bash, make) | as threaded | a guest fork is a host fork; one shared guest kernel | threaded's, plus `clone(SIGCHLD)`, no new stack |

Anything else from the runtime's syscall instruction kills the sandbox; a call from anywhere else
traps and is served in the guest. The exact policy, with each argument, is
[unsharek-tcb's table](crates/unsharek-tcb/README.md).

## Network

The program's sockets are its own for loopback. With the library's hooks, a `connect` elsewhere is
`on_connect`, whose stream unsharek copies to and from the program's socket; a `listen` is offered
to `on_listen`; name lookups are `on_resolve`. With no hook, everything but loopback is unreachable.
**A hook is not a policy point**: hooks run after lockdown in the program's address space, so a
compromised program can skip them. Policy is enforced at the far end of the provider's fd, in its own
process. See [crates/unsharek](crates/unsharek/README.md).

## Filesystem

A Nix program's closure is shown as erofs images, one per store path, built once and cached; ELF
files are mapped in place from them, shared across sandboxes through the host's page cache. `--ro`
of a store path adds it (with its closure) the same way. Anything else the program writes goes to
the guest's own memory.

**Plugin (experimental): host directories, live.** `--ro DIR[:AT]` and `--rw DIR[:AT]` serve a host
directory through the guest's stock virtio-fs driver, from a file server of its own
([unsharek-fs-server](crates/unsharek-fs-server/README.md): virtiofsd's passthrough file system,
confined by Landlock to the directory and by its own proven filter). The sandbox gains one granted
socket per directory, and nothing in its filter. The host's changes are seen within a second; reads
and writes cost a round trip to the server per request (about 5x native on large files today).

## Status and performance

Works in every mode unless noted: unmodified dynamic and static programs (glibc, musl, Go), exec in
the guest, signals, ttys, pipes, threads, fork mode's processes, templates (coroutine and threaded),
the network hooks. `cargo xtask test` runs about 640 cases in seconds.

| | native | sandbox |
|---|---|---|
| startup to READY (coroutine) | - | ~5 ms, ~4.2 MB PSS |
| a template's child | - | ~1 ms, under 2 MB |
| a syscall (`getppid`) | 0.08 µs | ~1.3 µs |
| `xz -T4`, 16 MB (threaded) | 0.13 s | 1.12x |
| `rustc`, 16 codegen units (fork) | 1.57 s | 2.82x |
| `make -j4`, 32 C files (fork) | 1.21 s | 3.19x |

The guest has one CPU, which is most of the build gap ([bench/PERF.md](bench/PERF.md)). Known
limits:

- **Fork mode:** a forked process's network beyond loopback, `MAP_SHARED` memory across a fork, and
  templates.
- **Signals to running code** are delivered at the thread's next syscall, so Go's asynchronous
  preemption doesn't land.
- **Bad pointers** passed to a call the guest serves end the sandbox (SIGSEGV), not with EFAULT.
- **At most 256 images** a sandbox; `exec` of `/proc/self/exe` is ENOEXEC.

## Development

```sh
direnv allow                 # the devshell (.envrc, nix-direnv); or prefix: nix develop -c
cargo xtask test             # everything, incremental, seconds warm (cargo-nextest; args pass through)
cargo xtask test -E 'test(/::fork$/)'   # one mode of the suite
cargo xtask perf             # the performance budgets; `vs-native` for build workloads
cargo xtask prove            # Kani: the filter is its policy (minutes)
nix build                    # the distributed binary; .#checks.x86_64-linux.smoke, the release check
```

The kernel is the submodule `crates/lkl-sys/linux` (`git clone --recurse-submodules`), built out of
tree on first use (about 20 s) and incrementally after. `UNSHAREK_LKL_SRC` names another checkout and
`UNSHAREK_LKL_CONFIG` a config fragment over `crates/lkl-sys/defconfig`; see
[crates/lkl-sys](crates/lkl-sys/README.md), including custom kernels from the flake's `lib`. How to
work on unsharek: [AGENTS.md](AGENTS.md).

## License

GPL-2.0-only: unsharek links the Linux kernel.
