# unsharek examples

Small programs that use unsharek's library the way an application would. Each is one file in
`src/bin/`, runnable from the devshell:

```sh
direnv allow   # or `nix develop`: the toolchain, and $UNSHAREK_TEST_PYTHON & co.
cargo run -p unsharek-examples --release --bin nix-program
```

An example whose nixpkgs program isn't in the environment prints `skipped: ...` and exits 0.
`tests/smoke.rs` runs each one, small, as part of `cargo xtask test`.

Two things hold in all of them:

- **A sandbox takes its process over.** Lockdown is for good, and `Locked::exec` never returns
  on success: the process becomes the program, and exits with its status. An example that wants
  to watch or talk to its sandbox forks it off before lockdown (`Guest::spawn`: the process is
  then a template, its child the sandbox)
  and stays the parent. One that needs sandboxes of different configurations (one guest per
  process) or a cold one to measure re-runs itself as a child in a "role"
  (`unsharek_examples::role`, `self_command`).
- **Host work and setup interleave until lockdown.** Booting, mapping images, holding and
  passing fds are host work; inside a setup closure (`g.run(|| ...)`) the thread's syscalls are
  the guest's (mounts, files); between closures the process is an ordinary one again (threads,
  host programs: none may be left at lockdown). `g.lockdown(unsharek::stdio)` grants the program's
  stdio (none is by default) and locks down: after it the host has only the mode's short
  allowlist.

## nix-program: a Nix program and its closure

`unsharek` spelled out with the library: the program's closure from the image cache
(`store::Cache::open_default`, `store`), `Guest::boot`, each image mapped (`map_store`;
`map_closure` is both steps), `setup::mount_closure` in a setup closure, then lockdown and exec. The parent
measures the sandbox from outside. Arguments are the program to run (default:
`$UNSHAREK_TEST_PYTHON -c 'print(6*7)'`).

```
$ nix-program
running ["/nix/store/…-python3-3.14.10/bin/python3", "-c", "print(6*7)"] in a sandbox
[sandbox] 23 store paths (0 images built): 119.972µs for the closure, 5.470121ms to boot and map
42
--- exit 0
first output after 17.2ms
wall time 19.8ms; peak PSS 22880 KB (sampled), max RSS 28016 KB
```

Most of that PSS is Python's own. These binaries are linked as the `unsharek` CLI is, at a fixed
address, which saves a few hundred KB a sandbox: their `build.rs` calls
`unsharek_build::link_fixed_address()` (`crates/unsharek-build`), as any embedder's can.

## setup: composing the guest in setup closures

An "app" directory (a Python script and a data file) is packed with `unsharek_erofs::build`, mapped,
and mounted at `/app`; a config file made on the host is written to the guest's `/etc`. All of it
is ordinary Rust inside setup closures (`g.run`: `std::fs::write`, `setup::mount_erofs`), acting
on the guest because the thread's syscalls are the guest's init's there; between the two the
host work (reading host data, mapping the image) is the host's.

```
[setup] the closure mounted
[setup] /dev/unsharek/app mounted at /app; /etc/greeter/config written
app: hello from an erofs image
config: greeting=hi, written by host pid 1469064
/app holds ['data.txt', 'main.py'] (writable: False)
the host's /tmp/nix-shell.UYhUTA/.tmp95r7uM exists here: False
```

## channel: a host fd as the guest's fd 1000

`Guest::pass_fd` gives the guest one end of a socketpair as fd 1000, and lockdown grants `read`
and `write` on exactly that host fd: capnix's pattern. The example builds and sets up the
sandbox, forks it off with `Guest::spawn`, and talks over the other end; Python answers the
squares of its numbers.

```
host sent   3, sandbox answered 9
host sent   7, sandbox answered 49
host sent  12, sandbox answered 144
host sent  99, sandbox answered 9801
sandbox: exit 0
```

## net-policy: networking through a proxy that holds the policy

After lockdown the sandbox can't make host sockets, so its network is the hooks: `OnResolve` and
`OnConnect` (set on the guest), here multiplexed over one held fd (`Guest::hold_fd_as("net")`,
found by the hooks with `cx.held("net")`; framing in `src/mux.rs`) to a proxy process started
before the sandbox is booted. The session starts at lockdown (`on_start`), and each connect
carries the name its address was resolved from (`cx.name_of`), so the proxy decides by name. The
proxy holds the real network and the allowlist (a local HTTP server's name and port;
`example.com:80` too with `--internet`), refuses the rest (`NetError::NoName`,
`NetError::Refused`), and logs each attempt with the guest pid.

The policy is in the proxy, not in the hooks, because of the **authority rule**: the hooks run in
the program's address space, so a compromised program can rewrite them and drive the held fd
itself. Whatever the fd's other end allows is what the program can do.

```
[proxy] guest pid 1: resolve web.local -> 10.0.0.1
[proxy] guest pid 1: connect 10.0.0.1:38011 (web.local:38011) -> allowed, to 127.0.0.1:38011
[python] GET http://web.local:38011/ -> 'hello from the host!'
[proxy] guest pid 1: resolve web.local -> 10.0.0.1
[proxy] guest pid 1: connect 10.0.0.1:38012 -> refused (web.local allows port 38011 only)
[python] GET http://web.local:38012/ -> failed: [Errno 111] Connection refused
[proxy] guest pid 1: resolve elsewhere.test -> refused (no such name)
[python] GET http://elsewhere.test/ -> failed: [Errno -2] Name or service not known
sandbox: exit 0
```

(Only A queries reach the hook: glibc's AAAA query beside each is answered with no data by
unsharek. Without an `on_resolve` at all, every name would resolve to an address of unsharek's own,
and the connect hook would still learn the name.)

## threads: why threaded mode exists

The same four CPU-bound threads (the fixtures' `par_compute`) natively, in `Mode::Coroutine` (one
host thread: the program's threads take turns) and in `Mode::Threaded` (a host thread each, made
through one exact `clone` the filter allows). Use `--release` for numbers.

```
4 threads x 300000000 xorshift iterations each
   native: compute   378.0 ms, whole run   378.8 ms
coroutine: compute  1396.6 ms, whole run  1471.7 ms  (3.7x native)
 threaded: compute   362.5 ms, whole run   373.0 ms  (1.0x native)
```

## escape: the host filter

A hostile program, a closure run as the sandbox's program (`Locked::run`), calls host
syscalls through the runtime's own syscall instruction, the "gate", which it finds by scanning
the binary's code (it shares the address space: nothing in it is hidden), with a few lines of
`asm!`. It also tries an fd the process had open before lockdown, which lockdown closed. As a
sandbox is, its first forbidden call kills it: each attempt runs in a sandbox of its own, and
each is killed. The host fds a sandbox may use are its grants (`s.grant`, and `pass_fd`,
`hold_fd`).

```
this process (the sandbox's host parent) is pid 1471082

getppid
  getppid(), trapped: the guest's        -> 0
  => killed by SIGSYS (the host filter)

openat
  getppid(), trapped: the guest's        -> 0
  => killed by SIGSYS (the host filter)

socket
  getppid(), trapped: the guest's        -> 0
  read(an fd from before) via the gate   -> Bad file descriptor (os error 9)
  => killed by SIGSYS (the host filter)
```
