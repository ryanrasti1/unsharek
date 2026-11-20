# The kernel: unsharek's LKL series

unsharek's kernel is stock LKL (`github.com/lkl/linux` master at `d0f76a77e`, Linux 6.12) plus a
series of 24 commits: branch `exobox-native` of `github.com/ryanrasti/linux`, checked out here as
the submodule `crates/lkl-sys/linux`. This file describes that series as it is, commit by commit: what each
does and why, what it adds to the host interface, and the test in `tools/lkl/tests/boot.c` that
fails without it. Each commit's message has the full account.

The series is what an in-process kernel needs to host unmodified programs behind seccomp that
stock LKL doesn't do. Its pieces are numbered **items** (1-16, plus the halt fix): unsharek's code
names them that way ("the kernel series' item 8" is signals), and several commits can belong to
one item.

## The model the kernel serves
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

In order (`git log --reverse d0f76a77e..exobox-native`). "Adds" is the host interface: host ops
(`struct lkl_host_operations`, called by the kernel), arch syscalls (`__NR_arch_specific_syscall +
n`, called by the host through `lkl_syscall`) and functions the host calls directly.

| # | Commit | Item | What and why | Adds | boot.c |
|---|---|---|---|---|---|
| 1 | `70f3ff6bca4f` HZ, the number of IRQs and TRACING as config options | 14 | `HZ` gets a prompt (100-1000; boot waits in jiffies: 45-75 ms at 100, 9-20 ms at 1000). `CONFIG_LKL_NR_IRQS` (every `irq_desc` is allocated at boot: the default 4096 cost 2.4 MB of slab; a multiple of `BITS_PER_LONG`, at most its square; `lkl_trigger_irq` no longer accepts `irq == NR_IRQS`). `LKL_TRACING` (default y) selects `TRACING`, which had no way off (~1 MiB of slab, 0.5 MiB of text). Defaults as before. | config options | - |
| 2 | `f939d62c7233` check the syscall number before indexing the syscall table | 7 | `run_syscall` read `syscall_table[no]` before checking `no`: out of bounds for a program's bad number (the host forwards them). | - | `syscall_bounds` |
| 3 | `4091609481e1` idle waits for an interrupt until the idle host task exists | 1 | Before the idle host task exists (end of boot) `arch_cpu_idle` returned at once and the idle loop spun holding the CPU; on a cooperative host the threads that deliver interrupts never ran and boot hung. Idle now releases the CPU and sleeps until the next interrupt. | - | (every boot: `start_kernel` 23-25 ms instead of 60-70) |
| 4 | `4deff32cba07` the thread that starts the kernel is init (PID 1); init's exit is the host's | 4 | The thread calling `lkl_start_kernel` is init: tid 1, the first program's process, the namespace's reaper. `host0`, the task host threads' tasks are cloned from, is a parked thread of init's process; the idle host task a kernel thread. init's exit isn't run: `lkl_syscall` returns its wait status (until item 6). | - | `gettid`, `getppid`, `init_exit` |
| 5 | `d436b2837941` a new host thread joins a process as a thread | 5 | A host thread's task was always a thread of init's process, so a program's threads in any other process had init's files and pid (tokio's workers found their fds EBADF). The process makes the thread, the new host thread takes it: `new_thread()` (pthread's clone flags, returns the tid at once, as clone must), then the new host thread's first call `attach_thread(tid)`. Borrowing a task from its own host thread could take it mid-syscall. | syscalls `new_thread`, `attach_thread` | `attach_thread` |
| 6 | `00769ca4fb2f` halt waits for the threads in the CPU's gate without spinning | halt | `lkl_cpu_cleanup` busy-waited for a thread parked in `lkl_cpu_get` to leave; on a cooperative host that thread never ran, so the halt hung whenever a program thread was entering a syscall. It sleeps on a semaphore now (20 ms of CPU or more before, 1-2 ms). | - | `stop_kernel` |
| 7 | `194b2df1d882` tickless idle | 2 | The kernel sat idle with the idle host task current and the tick at HZ: an idle sandbox woke its host HZ times a second. The CPU's last put with the idle host task current is now the kernel's idle (`tick_nohz_idle_enter`, the tick stopped to the next timer and re-stopped after each interrupt). With no timer at all the host timer is armed `TIMER_FAR` ahead (`KTIME_MAX / 2`), not `ULONG_MAX`, so the host's `now + delta` can't wrap into the past. | `timer_set_oneshot` gets deltas up to `KTIME_MAX / 2` | `tickless_idle` (101 timer fires in a 100 ms sleep at HZ 1000 before, 2-3 now) |
| 8 | `d1ba4fbacb22` leaving the kernel reschedules only for a runnable task | 3 | `lkl_cpu_put` rescheduled when `nr_running > 1`, which counts a queued idle host task and 6.12's fair server: a host task switched away and back at every syscall (3 switches per getpid). It asks `others_runnable()` now, from `nr_running_tasks()` in `kernel/sched/core.c`. Performance only. | - | `syscall_switches` (3009 context switches for 1000 getpids, 0 now) |
| 9 | `550c267ed1dd` a host task's exit is reported to the host (task_exit); init's exit runs | 6 | A task exiting in a syscall reached `__switch_to` from `do_exit` and waited for good: its host thread hung, and the host never learned the status. Now the dying task's host thread calls `task_exit(pid, status)` with the CPU released, which doesn't return (`pid`: the process's if it was its last thread, else 0). A fatal signal pending at a call's start or end ends the task there, so `exit_group` kills the other threads. init's exit runs as any process's (its files closed: `host0` drops its reference first) and is reported as `task_exit(1, status)`. | op `task_exit` | `task_exit`, `init_exit`, `stop_kernel` |
| 10 | `e20b050f8d00` host fds as guest files (host_fd) | 11 | The program's stdio had no guest file (dup2, pipes in their place, inheritance and fstat all had to be emulated) and a read of stdin would have held the CPU while waiting on the host. `host_fd(fd, flags)` makes a guest file whose I/O is the host's `hostfd_rw`, done with the task asleep and the CPU free, so the kernel runs on (and idles tickless) meanwhile. `fstat` says character device (libuv lost output written to an anon inode). | syscall `host_fd`; op `hostfd_rw` | `host_fd` |
| 11 | `ea7d26c84603` memblk, a read-only block device over host memory | 12 | The guest's store: erofs images the host mapped before lockdown, mounted at `/nix/store` with no copy and no host call (a read is a memcpy; bios done in the submitter's context). `memblk_add` returns the device number to mknod. | syscall `memblk_add` | `memblk` |
| 12 | `dfb2c4050eb4` the memory size reported is the program's (program_mem=) | 13 | `sysinfo` and `/proc/meminfo` reported the kernel's pool, while the program's memory is the host's arena: V8 sized its heap from it and ran 2.5x slower. `program_mem=<size>` on the command line sets `reported_ram_pages` in `mm/show_mem.c`, which both read. | command-line `program_mem=` | `meminfo` |
| 13 | `67da818630c6` signals delivered at a syscall's return to the program | 8 | LKL ran no signal delivery: a caught signal stayed pending for good (every interruptible sleep after it returned at once, `-ERESTART*` leaking out), default actions didn't run. A host task's syscall now ends as an arch's return to user mode does, without a signal frame: `get_signal` takes each pending signal, a caught one's handler is run by the host's `signal_handler` with the CPU released, then sigreturn's work (mask, alternate stack) is done and the call restarts or is `-EINTR`. A `new_thread_group_leader` process gets its own signal actions; init is killable (it must die of SIGTERM or `abort()`). | op `signal_handler` (`struct lkl_signal`) | `signals` |
| 14 | `cad907ec2f03` a program's fork is a fork of the host process | 9 | `clone` was `sys_ni_syscall` and `clone3` started a kernel thread at NULL. A clone that makes a process now calls the host's `fork(f, arg)` from `copy_thread` (copy_process can still fail after it), with the CPU held; in the child a thread runs `f`, which takes the child's task when it is first scheduled. `CLONE_CHILD_SETTID` is written once (LKL's `schedule_tail` at every switch rewrote it, into an exec'd program's memory). `clone(CLONE_THREAD)` is `-EINVAL`: threads are item 5's. | op `fork` | `fork` |
| 15 | `8eeb771cd7d6` exec's kernel half as one call, new_exec(name) | 10 | The loading is the host's (the memory is), but the rest of exec is kernel state the new program sees. `new_exec(name)` at the point of no return: other threads killed and waited for (`de_thread` rewritten: it is static and would wait for `host0`), files unshared and close-on-exec closed, `set_child_tid`/`clear_child_tid`, the robust list and rseq dropped, a vfork parent released, POSIX timers deleted, the alternate stack cleared, caught signals reset, the name set. | syscall `new_exec` | `exec` |
| 16 | `2815323570b4` AF_TSI and CONFIG_LKL_TSI | 15 | A family number (`AF_TSI`, `AF_MAX` one higher) for the next commit's sockets' `sk_family`, never registered. `CONFIG_LKL_TSI` (default y). | - | - |
| 17 | `2cb860cbf4d3` tsi.c, AF_INET sockets impersonated | 15 | No NIC, no TCP/IP in the host: after libkrunfw's TSI, a program's AF_INET socket is the guest's while local (an inner AF_INET socket: bind, loopback connects, listen) and the host's otherwise: a connect elsewhere is `net_connect`, answered by `lkl_net_done`; connected, its transport is a kernel socketpair whose other end the host reads and writes (nonblocking, woken by `net_ready`). A listen not on loopback is offered (`net_listen`, inbound connections `lkl_net_accept`); a datagram elsewhere is `net_sendto`, answered by `lkl_net_reply`. The host's calls run as a parked kernel thread of their own (`tsi`), not a thread of the program's. Nothing calls it yet. | ops `net_connect`, `net_listen`, `net_sendto`, `net_ready`; `lkl_net_done`, `_accept`, `_reply`, `_recv`, `_send`, `_shutdown`, `_close` | - |
| 18 | `aa7defcb2a36` run_syscall hands a program's AF_INET sockets to tsi.c | 15 | The one hook: `tsi_handler` at the top of `run_syscall` takes `socket(AF_INET, SOCK_STREAM or SOCK_DGRAM)` and `getsockopt(SOL_SOCKET)` on such a socket. `net/socket.c` is untouched. | - | `tsi_connect`, `tsi_listen`, `tsi_dgram` |
| 19 | `b86eb0f16694` host fd files poll as their host fd does | 16 | `host_fd` files had no poll and read as always ready: a guest epolling a passed channel (tokio) spun or blocked. The poll asks the host's `hostfd_poll`, and the host calls `lkl_hostfd_ready(fd)` when the fd may be ready. | op `hostfd_poll`; `lkl_hostfd_ready` | `hostfd_poll` |
| 20 | `09a9e0b44561` a nonblocking host fd file's reads and writes don't wait | 11 | An `O_NONBLOCK` host fd file still waited: tokio reads a registered fd to EAGAIN after each edge, and its runtime stalled. `hostfd_rw`'s last argument is flags now: `LKL_HOSTFD_WRITE`, and `LKL_HOSTFD_NONBLOCK` (set at `host_fd` or by `fcntl`), for which the host returns `-EAGAIN` rather than wait. | `hostfd_rw(..., flags)` | `hostfd_nonblock` |
| 21 | `43d42ce36c9f` lkl_net_syscall, the network host code's own syscalls as the tsi task | 15 | The host's network code may make syscalls of its own through a library (a stack probe's `/proc/self/maps`, `getrandom`); made with `lkl_syscall` from a host thread with no task, each got a thread of init's process that never ended, so init's process never did and the sandbox hung after the program's exit. `lkl_net_syscall` runs them as the `tsi` task; the calls that would end it or make it a process's are `-EINVAL`. | `lkl_net_syscall` | `tsi_syscall` |
| 22 | `35f332685c29` memblk disks of extents: host memory or zeros, in order | 12 | A disk was one mapping, an image file mapped whole. For an image synthesized over the host's own files (its metadata in a buffer, each file's data the host's mapping of it, an ELF slot's zeros), a disk is now an ordered table of extents (`struct lkl_memblk_extent { addr, len }`: whole 512-byte sectors, `addr` 0 for zeros, 1 to 2^20 of them, copied by the kernel), read by bisection and memcpy. | `memblk_add(extents, n)` replaces `memblk_add(addr, len)` | `memblk_extents` |
| 23 | `7e55ea2daab5` boot.c compiles again | - | Commit 22's merge put `memblk_extents` inside `hostfd_nonblock`'s last `if`: boot.c didn't compile from 22 to here. | - | (boot.c builds) |
| 24 | `ba962908b0c1` a blocking host fd write is whole, the host asked for the rest | 11 | A blocking write was whole only if the host wrote it all in one call, i.e. waited as long as a full pipe's reader took; unsharek can't (its host thread runs every task, or holds the one CPU token). The host may now take a write in pieces, or wait a while taking none and return `-ERESTARTSYS`; the kernel asks for the rest until it is whole or a signal is pending, as `pipe_write` does. | `hostfd_rw`'s contract (host_ops.h) | `hostfd_pieces` |

unsharek's own tests of the same items are in `crates/unsharek/tests/suite.rs` and
`crates/guest-tests` (e.g. `exit_code`, `thread_fds`, `forkthreads`, `sysaudit`, `abort`,
`sigterm`, `fork_rng`, `settid`, `exec_reset`, `stdin`, `stdout_full*`, `meminfo`, `python`,
`idle_cpu`; `net_*` and `passfd_epoll*` in `tests/net.rs`).

## Outside arch/lkl and tools/lkl
Five files of core Linux, +47 lines, each the smallest hook for what the arch can't do alone:
- `include/linux/socket.h` (commit 16): `AF_TSI`/`PF_TSI` (46) and `AF_MAX` 47. A socket's
  `sk_family` is a number; the impersonated sockets need one of their own so that nothing in
  `net/` takes them for inet's. The family is never registered.
- `kernel/sched/core.c` and `include/linux/sched/stat.h` (commit 8): `nr_running_tasks(except)`,
  beside `single_task_running()`: the runnable tasks less a queued fair server and less `except`.
  The runqueue is private to `kernel/sched/`, and the arch shouldn't reach into `sched.h`.
- `mm/show_mem.c` and `include/linux/mm.h` (commit 12): `reported_ram_pages`, used by
  `si_meminfo()` and `si_mem_available()`. Both report sites (`do_sysinfo`,
  `meminfo_proc_show`) read only these two functions, so one variable covers sysinfo and
  MemTotal, MemFree and MemAvailable; the kernel's own allocations stay bounded by the real pool.

## The config
`crates/lkl-sys/defconfig` (here) is the kernel's config, expanded by olddefconfig: HZ 1000 with
`NO_HZ_IDLE`, 128 IRQs, no tracing (item 14); `BLOCK` and `EROFS_FS` for memblk; `LKL_TSI` (its
default); `POSIX_TIMERS` (itimers deliver SIGALRM); no `FUTEX` (the host emulates futexes: the
program's memory isn't the kernel's); no sysfs (700 KB of slab, 3 ms of boot); `SLUB_TINY`; no
IPv6; of filesystems only proc, devpts, erofs and ramfs (the root, /tmp). The pool is `mem=` on the
command line, from unsharek's `GuestConfig::kernel_memory` (32 MB by default, 16 MB at least).

## Known limits
- **An exec from a thread other than the main one keeps the thread's tid**: after it,
  `gettid() != getpid()`. Linux's `de_thread` gives the exec-ing thread the leader's pid; here it
  can't be used (it is static, and would wait for `host0` in init's process), and `new_exec`'s
  rewrite of it leaves the tid alone.
- **The kernel never interrupts a thread running outside it.** A signal for a thread in user code
  waits for its next syscall's return, and so does a kill: an exec's, `exit_group`'s or a fatal
  signal's, which the exec or the process's end then waits for. (Go's asynchronous preemption,
  SIGURG to a loop without calls, isn't delivered: the suite's `go` case leaves it out.) unsharek
  works around the rest: threads parked in its own waits (emulated futexes, host fds) are woken
  to make a call (`Sched::interrupt_waits`), and threaded mode's `exit_group` ends the host
  process itself.
- **The kernel is tickless only while the idle host task is current.** A host task that leaves
  the kernel with nothing else runnable stays current, so while a program thread waits in the
  host's own wait (unsharek's emulated futex) the kernel isn't idle and its timer keeps firing: a
  1 s futex wait in unsharek fires the host timer about 100 times, a 1 s nanosleep 6 times. unsharek
  doesn't wake its waiters for those fires unless the program armed a signal timer. Making the
  host's waits release the CPU to the idle host task would end them.
- **`new_exec` leaves out** credentials (no setuid file is executed), personality, dumpability,
  and io_uring and perf (configured off).

## Left out
- **The nommu process memory series** (`mm/nommu.c`, per-task `mm` windows): the program's memory
  is the host's arena.
- **Interrupting a thread in user code** for a signal or a kill (the limit above): a host hook
  that makes the thread enter the kernel. Not needed until a program needs it (Go's preemption is
  the first).
- **A pending-signal hint** for a fast `rt_sigprocmask` that skips the kernel: an optimisation,
  not taken before the plain path is measured.
- **The RNG seed**: the host writes host entropy through the guest's `RNDADDENTROPY` before
  lockdown and per fork; no kernel change.

## Building
Built out of tree by `make` (`crates/lkl-sys/Makefile`, into `target/lkl`; incremental, the cold build ~20 s
on 24 cores) from the submodule `crates/lkl-sys/linux`, in development and in `nix build` alike (`nix build`
sees it through the flake's `inputs.self.submodules`). `UNSHAREK_LKL_SRC` names another checkout
(a worktree has no submodule checked out), `UNSHAREK_LKL_CONFIG` adds a config fragment over
`crates/lkl-sys/defconfig`. For `nix build` the kernel is its own derivation (`lib.unsharekKernel`), linked
through lkl-sys's `UNSHAREK_LKL_PREBUILT`.

The series is the branch `exobox-native` of `github.com/ryanrasti/linux`, the submodule's URL
(`git@github.com:ryanrasti/linux.git`, `.gitmodules`' branch). Work on it happens in a checkout
of that repository; a commit of it reaches unsharek as the submodule's new commit together with
unsharek's side of the change (the host-operations table in `crates/unsharek-rt`, when the host interface
moved), in one unsharek commit. `crates/lkl-sys` runs the make from its build.rs and links the
kernel object alone (`liblkl-kernel.a`, tools/lkl's `lib/lkl.o`), not `tools/lkl/lib`: unsharek
provides the host ops itself. The stock posix host (`liblkl-posix.a`) is linked only by lkl-sys's
smoke test.
