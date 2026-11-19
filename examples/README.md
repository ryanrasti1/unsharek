# exobox examples

Small programs that use exobox's library the way an application would. Each is one file in
`src/bin/`, runnable from the devshell:

```sh
source devshell.sh                     # the toolchain, and $EXOBOX_TEST_PYTHON & co.
cargo run -p exobox-examples --release --bin nix-program
```

An example whose nixpkgs program isn't in the environment prints `skipped: ...` and exits 0.
`tests/smoke.rs` runs each one, small, as part of `./test`.

Two things hold in all of them:

- **A sandbox takes its process over.** `Sandbox::run` never returns on success: the process
  becomes the program, and exits with its status. An example that wants to watch or talk to its
  sandbox re-runs itself as a child in a "role" (`exobox_examples::role`, `self_command`) and stays
  the parent.
- **Host work happens before `run`.** Booting, mapping images, holding and passing fds: all of it
  before lockdown. Inside `pre_exec` and after, every syscall is the guest's, and the host has only
  the mode's short allowlist.

## nix-program: a Nix program and its closure

`exobox run` spelled out with the library: the program's closure from the image cache
(`store::Cache::closure`, `images`), `Sandbox::boot`, each image mapped (`map_image`), and
`setup::mount_closure` in `pre_exec`. The parent measures the sandbox from outside. Arguments are
the program to run (default: `$EXOBOX_TEST_PYTHON -c 'print(6*7)'`).

```
$ nix-program
running ["/nix/store/…-python3-3.14.10/bin/python3", "-c", "print(6*7)"] in a sandbox
[sandbox] 23 store paths (0 images built): 119.972µs for the closure, 5.470121ms to boot and map
42
--- exit 0
first output after 17.2ms
wall time 19.8ms; peak PSS 22880 KB (sampled), max RSS 28016 KB
```

Most of that PSS is Python's own. The `exobox` CLI binary is linked at a fixed address, which
saves a few hundred KB a sandbox (`native/exobox/build.rs`); these examples are ordinary PIEs.

## setup: composing the guest in `pre_exec`

An "app" directory (a Python script and a data file) is packed with `exobox_erofs::build`, mapped,
and mounted at `/app`; a config file made on the host is written to the guest's `/etc`. All of it
is ordinary Rust in `pre_exec` (`std::fs::write`, `setup::mount_erofs`), acting on the guest
because it runs as the guest's init.

```
[pre_exec] /dev/exobox/app mounted at /app; /etc/greeter/config written
app: hello from an erofs image
config: greeting=hi, written by host pid 1469064
/app holds ['data.txt', 'main.py'] (writable: False)
the host's /tmp/nix-shell.UYhUTA/.tmp95r7uM exists here: False
```

## channel: a host fd as the guest's fd 1000

`Sandbox::pass_fd` gives the guest one end of a socketpair as fd 1000, and widens the filter to
`read` and `write` on exactly that host fd: capnix's pattern. The parent sends numbers; Python
answers their squares.

```
host sent   3, sandbox answered 9
host sent   7, sandbox answered 49
host sent  12, sandbox answered 144
host sent  99, sandbox answered 9801
sandbox: exit 0
```

## net-policy: networking through a proxy that holds the policy

After lockdown the sandbox can't make host sockets, so its network is the hooks: `OnResolve` and
`OnConnect`, here multiplexed over one held fd (`Sandbox::hold_fd`, framing in `src/mux.rs`) to a
proxy process started before the boot. The proxy holds the real network and the allowlist
(a local HTTP server's name and port; `example.com:80` too with `--internet`), refuses the rest
(`NetError::NoName`, `NetError::Refused`), and logs each attempt with the guest pid.

The policy is in the proxy, not in the hooks, because of the **authority rule**: the hooks run in
the program's address space, so a compromised program can rewrite them and drive the held fd
itself. Whatever the fd's other end allows is what the program can do.

```
[proxy] guest pid 1: resolve web.local -> 10.0.0.1
[proxy] guest pid 1: connect 10.0.0.1:38011 (web.local:38011) -> allowed, to 127.0.0.1:38011
[python] GET http://web.local:38011/ -> 'hello from the host!'
[proxy] guest pid 1: connect 10.0.0.1:38012 -> refused (web.local allows port 38011 only)
[python] GET http://web.local:38012/ -> failed: [Errno 111] Connection refused
[proxy] guest pid 1: resolve elsewhere.test -> refused (no such name)
[python] GET http://elsewhere.test/ -> failed: [Errno -2] Name or service not known
sandbox: exit 0
```

(Each lookup reaches the proxy twice, once for A records and once for AAAA. The duplicate lines
are left out above.)

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

A hostile program (`c/gate_probe.c`) calls host syscalls through the runtime's own syscall
instruction, the "gate", as a compromised program that found it would. Under the default
`Deny::Kill` its first forbidden call kills the sandbox; under `Deny::Errno` each call gets EPERM;
`allow("getppid")` widens the filter by that one call, which then reaches the host (and returns
the example's pid: the sandbox's real parent).

```
this process (the sandbox's host parent) is pid 1471082

default: Deny::Kill
  getppid(), trapped: the guest's        -> 0
  => killed by SIGSYS (the host filter)

.deny(Deny::Errno)
  getppid(), trapped: the guest's        -> 0
  getppid() via the gate: the host's     -> Operation not permitted
  openat("/etc/passwd") via the gate     -> Operation not permitted
  survived
  => exit 0

.deny(Deny::Errno).allow("getppid")
  getppid(), trapped: the guest's        -> 0
  getppid() via the gate: the host's     -> 1471082
  openat("/etc/passwd") via the gate     -> Operation not permitted
  survived
  => exit 0
```
