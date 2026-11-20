# unsharek-rt

The runtime: everything between the program and the guest kernel. Not trusted, and it knows nothing
of the filter.

- **The trap.** Every program syscall is a SIGSYS (syscall user dispatch before lockdown, the
  filter's TRAP after). The frame is moved off the program's stack (Go makes syscalls with ~128
  bytes to spare), FS switched to unsharek's and back, and the call dispatched: to the guest kernel
  (x86-64 numbers translated to the generic table, structs translated), rewritten (`open` to
  `openat`, `fork` to `clone`), emulated (memory, threads, futexes, the thread pointer), or refused.
  About 1 µs. The runtime's own host calls go through one syscall instruction, the gate.
- **Signals** are the guest kernel's; at a call's return a caught one's frame is built on the
  program's stack and its handler run, whose `rt_sigreturn` traps back.
- **Memory.** One arena, reserved before lockdown, readable, writable and executable (JITs work):
  the program's memory calls are served from it, with no host `mmap` after lockdown and no
  `madvise` in any mode; freed pages are cleared when handed out again. Images are mapped read-only
  at its top, so library code is mapped in place and never writable.
- **Exec** loads the program and its interpreter from the guest's files into the arena, after
  lockdown: nothing the program brings runs before the filter.
- **Scheduling.** Coroutine mode runs every thread as a coroutine on one host thread; threaded and
  fork mode give each program thread a host thread taking turns on one CPU token. **Fork mode** forks
  the host process for a guest fork: the kernel's memory and the scheduler's state are shared
  mappings made before lockdown, the program's memory is private; init's end is the sandbox's.

The `stats` feature builds counters (`cargo xtask vs-native --variant stats`).
