# The kernel: what exobox needs from LKL

exobox's kernel is stock LKL (`github.com/lkl/linux` master, `d0f76a77e`, Linux 6.12) plus a short
series on `github.com/ryanrasti/linux`, branch `exobox/native`. This file is that series' plan,
written from first principles: what an in-process kernel hosting unmodified programs behind
seccomp needs that stock LKL doesn't do. Each item names the earlier work it learns from:
linux-workers' `lkl/wasi-main` (a cooperative WASI host, the same scheduling problem) and capnix's
tier A commits (`capnix-tiera`, the first native host). Neither is rebased; each change is
rewritten as the smallest one that does the job.

## The model the kernel has to serve
- One kernel per sandbox, one CPU. The host runs it either cooperatively (coroutine mode: every
  kernel and program thread a coroutine on one host thread) or with a host thread per program
  thread taking turns on the CPU (threaded and fork mode).
- The program is a real user process of the guest: PID 1, its own files, its threads guest threads
  of it. Its memory is the host's (an arena in the host process), never the kernel's: no nommu
  process memory, no `mm` work.
- The host enters the kernel only through `lkl_syscall` (a trapped program syscall, or a host
  operation) and is entered from it only through host ops. Nothing in the kernel makes a host
  syscall after lockdown except through those ops.

## The series

Ordered as the commits will be. "Test" is the exobox case (`native/exobox/tests/suite.rs`) that
fails without it.

| # | Change | Why it is needed | Learned from | Test |
|---|---|---|---|---|
| 1 | **Idle never spins.** `arch_cpu_idle` before the idle host task exists releases the CPU and waits for an interrupt. | Stock idle spins until boot completes, keeping the CPU from the threads that deliver interrupts: a cooperative host hangs at boot. | wasi-main `c07d5d26` | every case (boot) |
| 2 | **Tickless idle.** With nothing runnable, the tick stops until the next timer, and "no timer" stays far off without overflowing. | An idle sandbox must cost no CPU. | wasi-main `4d1b7f14`; tier A's `ULONG_MAX` deadline overflow | `idle` |
| 3 | **Leaving the kernel reschedules only for real work** (`others_runnable`: not the idle host task, not the fair server). | Otherwise every syscall switches to the idle host task and back (2.5x on Valkey). Performance, not correctness. | wasi-main `deb57f50`, `54daec2a` | (bench) |
| 4 | **The first program is PID 1**, the task of the thread that booted the kernel; `host0` becomes a kernel thread of its own. Its end ends the kernel, with its status. | The program needs a process of its own (fds, cwd, signals) that is init, and the sandbox's exit status is its. | wasi-main `cb9a866e`, `fd03cbd2`; tiera `ARCH_INIT_EXIT_ENDS_SYSTEM` | `exit_code`, `hello` |
| 5 | **A new host thread joins a named process as a thread** (`CLONE_THREAD`, sharing files, fs, signal handlers), instead of being cloned from `host0`. One entry point serves the program's `pthread_create`, in every process. | Threads share their process's fd table (tokio's EBADF). | tiera `new_host_task`, `threadof` (`009c04d5`); wasi-main `e0516735` | `thread_fds`, `forkthreads` |
| 6 | **A task's exit is reported to the host** (which host thread, whether its process ended, the wait status), and a host task can exit inside a syscall. | The host must end the host thread or process and know the status. | wasi-main `9ac1c73f`, `e0516735` | `exit_code`, `fork` |
| 7 | **`lkl_syscall` checks the number before indexing the table.** | Stock reads past the table for an out-of-range number. The host translates numbers, but this is the kernel's bound to keep. | wasi-main `bbbc3ae9` | `sysaudit` |
| 8 | **Signals delivered at a syscall's return to the program**: a host op runs the handler on the program's stack with a ucontext; it reports whether the interrupted call restarts. Used in every mode. | One signal implementation, the kernel's: dispositions, masks, `kill`, default actions, wait statuses. Tier A emulated signals in the shim outside fork mode; doing it once in the kernel removes that. | wasi-main `819fa591`, `4cba5a81` | `signals`, `abort`, `sigterm`, `sigsys` |
| 9 | **Fork as a host op inside `clone`**: `copy_user_thread` calls the host to fork the host process; the child's task bootstraps when first scheduled. | Fork mode: a guest fork is a host fork, one kernel shared by the processes. | tiera fork commit (`c6a0dc91`) | `fork`, `fork_rng`, `forkbomb`, `bash` |
| 10 | **Exec's kernel half as one operation**: close-on-exec fds, reset handlers, the new name. The host maps the image. | Exec maps memory the kernel doesn't own, but these parts are the kernel's state. | tiera `TIERA_OP_EXEC` | `bash`, every case's first exec |
| 11 | **Host stdio as guest files**: a file type whose reads and writes are done by the host on a host fd, outside the CPU, so `dup2`, pipes and inheritance work on them. | Programs redirect and pass on stdio; a read of stdin must not hold the CPU. | tiera `TIERA_OP_HOSTFD` | `stdin`, `stderr`, `stdio_meminfo`, `bash` |
| 12 | **A block device over host memory** (`memblk`): blocks served from mappings made before lockdown. With `BLOCK` and `EROFS_FS` on, the closure's images mount at `/nix/store`. | The guest sees the program's closure, read-only, with no copy at boot. | tiera `memblk` (`850279d3`) | `python`, `bash`, `dlopen`, `hostile_*` |
| 13 | **The memory size reported is the program's**: `sysinfo` and `/proc/meminfo` say the arena's size, given by the host, not the kernel's pool. | Runtimes size their heaps from it (V8 picked its smallest at 16 MB). Tier A faked `/proc/meminfo` in the shim; a reporting hook in the kernel is smaller. | tier A shim | `stdio_meminfo` |
| 14 | **Config knobs instead of hard-coded values**: `HZ` and `NR_IRQS` selectable for the arch; `TRACING` not selected. | Boot waits in jiffies (HZ 100: 45-75 ms, HZ 1000: 9-20 ms); every `irq_desc` is allocated at boot (4096: 2.4 MB of slab). | tiera tweaks (`191815fa`) | (boot time, memory) |

`lkl/defconfig` (here) turns the rest off: no sysfs (700 KB of slab, 3 ms of boot), `SLUB_TINY`, no
IPv6, no filesystems but ramfs, proc, devpts and erofs, a 16 MB pool.

## Probably needed; decided by the tests
- `wait_task_inactive` bounded on a cooperative host (wasi-main `0176e160`, `61b806b1`): it sleeps
  a tick per retry, which a single-CPU kernel may turn into a hang at exit or fork.
- IRQ chips set as IRQs are given out (wasi-main `7eb435b0`): moot if `NR_IRQS` is small enough.

## Left out
- **The nommu process memory series** (`mm/nommu.c`, windows, per-task `mm`: most of wasi-main).
  The program's memory is the host's arena.
- **WASI drivers** (console, sockets, filesystem, bindings). The WASI host comes later, on the
  same base.
- **`TIERA_OP_SIGPEND`** (the pending-signal hint for a fast `rt_sigprocmask`): an optimisation;
  first measure the plain path.
- **`TIERA_OP_TIFLAGS`** (interrupting a thread in user code for a signal): not needed until a
  test shows a signal waiting on a busy thread.
- **`TIERA_OP_NEWPROC`** (hosted programs, capnix's network proxy): out of scope.
- **The RNG seed**: the host writes host entropy through the guest's `RNDADDENTROPY` before
  lockdown and per fork; no kernel change.

## Building
Built out of tree by `make` (incremental; the cold build is about a minute), from a checkout of
the branch (flake input `linux`, overridable to a local worktree for kernel work). `liblkl.a`
is linked into the `exobox` binary; only the kernel object is used, not `tools/lkl/lib`: exobox
provides the host ops itself.
