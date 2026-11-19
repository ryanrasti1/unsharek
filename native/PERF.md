# Build performance: where the time goes

Goal: parallel builds (Rust and C, `-j4`) within 5% of native wall time. This is the measurement
and analysis that comes first: what each mode costs on real build workloads, where that time goes,
and what each candidate fix would buy. Nothing in the runtime was changed for it; the experiments
below were built in a scratch copy of the tree (since deleted: each landed as a fix or was
rejected), and the counters are the runtime's cargo feature `stats`.

Measured 2026-11-18 on main `6d3364f` (fork mode merged, kernel `35f3326`) and re-measured on
`92def71` (the full-pipe fix, kernel `ba96290`: the table below), release builds.

## Summary

| workload | native | coroutine | threaded | fork | CPU-count fix (`aff8`) | `aff8` + idler without the token |
|---|---|---|---|---|---|---|
| `rustc` regex-syntax, `-C codegen-units=16 --emit=obj` | 1.57 s | 4.34 s (2.76x) | 4.44 s (2.82x) | 4.44 s (2.82x) | threaded 2.17 s (1.38x), fork 2.06 s (1.31x) | threaded 1.91 s (1.21x), fork 2.02 s (1.28x) |
| `xz -T4` 16 MB | 0.132 s | 0.465 s (3.5x) | 0.149 s (1.13x) | 0.148 s (1.12x) | same | same |
| `make -j4`, 32 C files + link (gcc) | 1.21 s | - | - | 3.85 s (3.19x) | 4.23 s (3.5x: noise) | 3.88 s (3.22x) |
| `rustmake`: 6 crates + a binary by rustc under `make -j4` | 6.99 s | - | - | 12.81 s (1.83x) | 7.80 s (1.12x; paired 1.05x) | 7.79 s (1.11x) |

Best of 3 interleaved runs, pinned to the 8 P-cores; "x" is best against best, "paired" the
median of same-rep ratios where it differs. The first measurement (`6d3364f`) agreed within noise
(rustc 2.84x / aff8 1.20-1.32x, make 2.95-3.33x, rustmake 1.82x / 1.12x). `cargo build` itself could not be measured: the cargo binary
crashes the sandbox in every mode ("Bugs found" below), so `rustmake` runs cargo's work (the same
crates, cargo's release flags, make's jobserver) without it.

What the numbers say, in order of size:

1. **The sandbox tells programs it has one CPU** (`sched_getaffinity` is emulated as the mask `1`).
   rustc sizes its codegen parallelism from it and runs its 16 codegen units one at a time: that
   alone is 2.9 s of rustc's 2.9 s-over-native, and 5.8 s of rustmake's 5.8 s. Reporting the host's
   CPUs (the `aff8` experiment) brings rustc to 1.2-1.4x and rustmake to 1.05-1.12x. Any program
   that sizes a thread pool from `nproc`/`available_parallelism` is serialized today.
2. **For C builds the single CPU token is saturated, but mostly not by kernel work.** In `make -j4`
   the token is held 69-75% of the wall time. Of 2.5 s held: 1.1 s is *hand-off latency* (the token
   assigned to a thread that is asleep on its eventfd, unused until the host wakes it), ~1.2 s is
   the runtime's own exec work done under the token (copying every exec'd program and library into
   the arena: 2.3 GB for 142 execs; zeroing the old image's pages: 0.8 GB), and only ~0.3 s is the
   guest kernel serving the 67k kernel-routed calls. A process costs ~4-13 ms more than natively
   (`true`: 4.9 ms against 0.7; `cc1 --version`: 21 ms against 8.2).
3. **For Rust builds, after (1), the remaining gap is the emulated futex.** 98% of rustc's 100-140k
   trapped calls are `futex` and `mprotect`, which need no kernel, yet each takes the token, and
   every futex wake moves the token to the wakee's host thread by a sleeping hand-off (6-13 µs).
   (A pipe ping-pong between two threads is 24-27 µs in threaded/fork mode against 6 µs in
   coroutine mode and 2.5-4.6 µs natively; a futex ping-pong between two threads, measured later,
   is close to native: 4-5 µs against 3-4. The cost is contention among many threads, not one
   wait and wake.) The kernel's own work in a rustc run is ~0.13 s. *Later found* (see "Fixes"):
   much of this traffic was the kernel's tick interrupting every parked waiter each millisecond.
4. **The kernel idler keeps the token while it sleeps** (to a timer, and since `92def71` while it
   watches host fds), and every return to user mode with a timer armed (or an fd watched) hands
   the token to it: 30-40% of rustc's contended acquires found the idler holding it. Freeing it
   (the `idler` experiment) cut rustc's hand-offs by 70% and its token time by half: 1.38x → 1.21x
   threaded (measured after `92def71`; before it, fork 1.32x → 1.18x).
5. Small: the SIGSYS round trip (~1 µs a call: 1-2% of make's wall), host fork (0.3-0.4 ms each,
   1% of make), `mprotect`/`mmap` taking the token.

**Recommendation** (details in "Ranked bottlenecks" and "Reaching 5%"): fix the CPU count first
(trivial, the biggest single win), then move futexes and the arena's memory calls off the token,
then exec without copies (programs and libraries mapped in place from the store images, no zeroing
of the old image), then cut the hand-off latency. Projected: Rust builds ~1.05x, `make -j4` ~1.3x.
For C builds the last 25% is per-process cost and the serialized kernel; an SMP guest kernel (the
"CPU is a token" design) is the right shape for that and is evaluated below, but by these numbers it
is the fourth thing to build, not the first: today it would parallelize ~0.3 s of make's 2.4 s gap
and ~0.1 s of rustc's.

## Fixes (phase 2) and where they leave each workload

Commits on the branch after this analysis, each measured with `./test --vs-native` (A/B: an
interleaved run with the commit before, `--variant`) and at the end with the full harness. The
machine was shared and loaded through most of phase 2 (load 10-17 for the final runs, against 1-5
for the analysis above), which slows sleeping hand-offs most: absolute ratios came out worse than
the analysis's for every binary, the old one included. Compare within a run.

| # | Commit | What | Measured |
|---|---|---|---|
| suite | `84de615`, `df3ce03` | `./test --vs-native` (native/bench/quick.py): rustc cgu16, rustc under make -j4, make -j4 of C, xz -T4, and syscall, futex/pipe ping-pong and fork+exec micro costs, scaled down, ratios against targets; `--variant` A/B | ~30 s a run (3 reps). The small workloads track the direction of the full-size ones but exaggerate per-process cost (small rustmake 1.36x when full-size is 1.12x; small make 3.4-3.9x for 2.2-3.2x) |
| 1 | `26de534` | `sched_getaffinity` reports the host's CPUs (threaded, fork) | rustc 2.82x -> 1.2-1.4x; rustmake 1.82x -> 1.05-1.12x (full size, quiet machine) |
| 2 | `6239209`, `203a295` | Exec without copies: the image zone is read-only on the host but for each ELF's writable segments (from the image's layout and the ELFs' program headers, made writable before lockdown); in place at every exec in every mode; library code faults when written, `mprotect(PROT_WRITE)` on it is EACCES. Then no `madvise` in any mode (one memory model), and ELF headers read with `pread` (reading them through the mapping cost 1.5 MB PSS) | make -j4: zeroing 764 -> 215 MiB, copies 2189 -> 1550 MiB, 2.45x -> 2.23x (1 rep). What is still copied is gcc's `cc1`/`collect2`, non-PIE: they must sit at their own addresses, 51 MB a compile; only a filter widening (a host `mmap` of an image fd at a fixed arena address) or a PIE gcc removes it. PSS per idle sandbox 4447/4479/4659 KB (budget 5120; 4321 before) |
| - | `71ec27b` | A timed futex wait woken for nothing waits again to the same deadline (it returned 0 after ~1 ms, every mode) | guest-tests' `futex_timeout` runs in every mode |
| - | `f68150c` | The kernel's timer interrupts the runtime's waits only once the program armed a signal timer (`alarm`, `setitimer`, `timer_settime`). It is the kernel's one timer, firing every tick while the kernel isn't idle: every parked futex waiter woke each millisecond and took the token to ask the kernel | vs-native, interleaved: rustc fork 2.47x/2.38x -> 1.97x/1.18x; rustc under make 2.40x/2.55x -> 1.75x/1.91x. `idle_cpu` passes in coroutine mode now (120 ms of CPU for 300 ms of sleeping before) |
| 6 | not committed | The idler without the token | No gain once fix 1 was in (full-size rustc fork 1.35x either way; the small suite worse). Contended acquires fell 84k -> 33k but each hand-off got slower (6 -> 18-30 µs), the total held time unchanged. A variant that slept without the token after handing it off hung `stdout_full` in fork mode 3 runs in 5; not understood, set aside |
| 3 | not committed (WIP) | Futexes off the token (per-bucket locks; a waiter blocks on its slot's futex eventfd, a waker writes it) | Hangs `group_exit_futex` (threaded, fork): with its host thread parked off the token, a thread's bound coroutine made runnable by the kernel is handed the token by directed hand-off, and nothing runs it. Needs the waiter to also watch its token eventfd and serve such a hand-off, or the kernel not to schedule a task whose thread is in user space. After the tick fix the futex's share is smaller; to be remeasured before going on |
| 5, 4 | not started | Arena calls under a per-process lock; fewer and faster hand-offs | - |

Before (main `c75ca78`) against after (`f68150c`), full size, fork mode, best of 3, interleaved,
on the loaded machine (paired medians in brackets where they differ by more than 0.1):

| workload | native | before | after |
|---|---|---|---|
| rustc cgu16 | 1.85-1.87 s | 2.34-2.48x | 1.73-2.06x |
| xz -T4 | 0.17 s | 1.14x | 1.13x |
| make -j4 of 32 C files | 1.56-1.57 s | 4.69-4.75x | 4.31-4.59x |
| rustc under make -j4 | 7.54 s | 1.42x | 1.23x |
| `cargo build -j4 --release` (6 crates, cargo works since main's statx fix) | 4.48-4.51 s | 2.96-3.07x | 1.41-1.42x |

What is left, from the counters of the last runs (instrumented build of `f68150c`):

- **make -j4: the token, and hand-offs above all.** Held 80% of the wall; of 5.6 s held, 4.1 s
  was hand-off latency (61k hand-offs at ~66 µs each on the loaded host, 18-29 µs on a quiet
  one), ~1 s exec (cc1's copies, 0.57 s, and the rest), ~0.5 s the kernel. Hand-offs (#4) are now
  the first thing to fix for C builds; under host load they dominate.
- **cargo / rustc: hand-offs and the idler.** rustc: token held 64%, 2.15 s of 2.2 s of it
  hand-off latency; 20k of 56k contended acquires found the idler holding the token. cargo: held
  84%, 11.5 s of hand-off latency over 187k hand-offs, 63k acquires from the idler. The idler fix
  (#6) measured nothing on a quiet machine, but its share here says to retry it with #4.
- **SMP for make -j4.** Not yet: the kernel's own work is still ~10% of the token's time. The
  serialization that dominates is waiting for sleeping threads to wake, which N CPU tokens would
  multiply rather than remove unless hand-offs get cheap first.

## Phase 3: hand-offs and the idler

| Commit | What | Measured |
|---|---|---|
| `a918918`, `ee33a7c` | busy_sleep (from the SMP work): a busy thread kept another's `nanosleep` from ending in threaded and fork mode. Arming the kernel's timer wakes its coroutine to re-read the deadline, which is on no heap until it runs; nobody ran it. A release now hands the idler the token while a timer is being re-read (`Timer::is_rereading`, from `b001710` on) | busy_sleep{,_calls} green; f68150c hadn't cured it |
| `e03b4f4` | Fix 4: the token is offered, not assigned. A release leaves it free and invites the target; a running thread that wants it takes it at once; the invited thread takes it if still free when it wakes, else goes first in line and is assigned it at the next hand-off (and pokes the holder: an offer lost to the sleeping idler hung guest_fork's `time::clock` 2 runs in 80 until it did) | vs-native, A/B: make -j4 3.74x -> 2.53x; rustc 1.31x -> 1.16x (fork), 1.32x -> 1.20x (threaded). Strict two-thread ping-pongs pay: pipe 20.7 -> 26 µs |
| `b001710` | Fix 6, retried: the idler sleeps to its timer without the token (handing it on or leaving it free) and takes it back after; a release hands it the token only for an earlier deadline or a timer being re-read. With host fds to watch it keeps the token, as before. After fix 4, nearly every contended acquire of the Rust builds found the token asleep in the idler | vs-native, A/B: rustc 1.14x -> 1.08x (threaded), 1.12x -> 1.09x (fork); rustc under make 1.36x -> 1.22x; getppid 3.0 -> 0.84 µs; futex ping-pong 6.3 -> 1.0-1.3 µs |
| `2e8ef70` | Found stress-testing fix 4: a signal sent to a thread on its way into an emulated futex wait (waiting for the token) was lost, and glibc's `setresuid` (which signals every thread and waits for each) hung guest-tests' `files::devnodes` about 1 run in 50. A wait now asks the kernel first when a signal was sent since its thread last asked, as Linux's futex_wait checks `signal_pending` | `signal_futex_race` hung every run (threaded, fork), now green; devnodes 240/240; no cost |
| fix 3 | Futexes off the token | Not built: after fixes 4 and 6 a rustc's token is held 7% of its wall, contended acquires fell 79k -> 16k, and a futex round trip is 1 µs (native 3) |

Full size, quiet machine (load ~1), best of 3, interleaved; `c75ca78` is main before any phase-2
fix (its numbers here differ from the loaded runs above):

| workload | native | `c75ca78` | before fix 4 (`ee33a7c`) | after fix 4 (`e03b4f4`) | now (`b001710`) |
|---|---|---|---|---|---|
| rustc cgu16, threaded | 1.61 s | 1.33x | 1.41x | - | **1.04x** |
| rustc cgu16, fork | | 1.13x | 1.24x | 1.15x | **1.05x** |
| make -j4, 32 C files | 1.21 s | 2.61x | 2.81x | 2.10x | **2.05x** |
| rustc under make -j4 | 7.10 s | 1.10x | 1.12x | 1.10x | **1.04x** |
| cargo build -j4 --release | 3.75 s | 1.25x | 1.16x | 1.13x | **1.07x** |
| xz -T4 | 0.14 s | 1.08x | 1.11-1.14x | 1.11x | **1.07-1.08x** |

What is left (counters of `b001710`):
- **Rust builds are at 4-9%.** rustc: token held 7% of the wall, hand-off latency 7 ms, the
  idler behind 247 of 16k contended acquires. The rest is CPU: 4.8 s against 4.5 natively
  (traps, the dispatcher).
- **make -j4 is at 2.05x, and the token is the bottleneck again, for work now:** held 52%; of its
  1.25 s, ~0.94 s is exec (cc1's and collect2's copies, 0.59 s: non-PIE, at their own
  addresses; clearing their old pages, 0.39 s), hand-offs only 0.09 s. The kernel's own work is
  the rest. Next: exec off the token (the copy and the clearing are the process's own memory), or
  a PIE gcc / a filter that lets exec map an image fd at a fixed address; then per-process cost
  (fork+exec+exit of `true`: 4 ms against 0.6). SMP is still not the lever: 0.3 s of kernel work.

## How it was measured

**Machine.** Intel Core Ultra 9 275HX: 8 P-cores (CPUs 0-7) and 16 E-cores, no SMT, 62 GB. Shared
with other agents' builds (load from 1 to 470 during the day). Every run is pinned with `taskset -c
0-7` (native and sandboxed alike), each rep runs every mode back to back in the same order, and
runs with load above ~10 were repeated. Even so, single runs vary 10-30%: compare best-of-N and
paired ratios, not single numbers.

**Harness.** `native/bench/run` (enters the devshell, builds release, runs
`native/bench/build_bench.py`):

```sh
native/bench/run --work rustc,xz --modes native,coroutine,threaded --reps 3
native/bench/run --work make,rustmake --modes native,fork --reps 3 --perf $(command -v perf)
native/bench/run --work rustc,make --modes native,fork,fork:stats --variant stats   # the counters
native/bench/run --work rustc --modes native,fork,fork:a --variant a=/path/to/another/exobox
```

Per run: wall time, CPU time across every process (`perf stat` task-clock; `wait4`'s rusage misses
fork mode's processes, which init reaps with `SA_NOCLDWAIT`), and the counters below when the binary
has them. JSON lines with `--log`. Workloads: `rustc` (regex-syntax 0.8 from `~/.cargo/registry`,
58k lines, no deps, `-C opt-level=3 -C codegen-units=16 --emit=obj`), `xz` (perf.rs's 16 MB),
`make` (32 generated C files of 60 functions each, `-O2`, linked), `rustmake` (6 generated crates,
a chain of dependencies, and a binary, `-C opt-level=3 -C codegen-units=16`, linked by cc), `cargo`
(the same workspace, `cargo build -j4 --release`; blocked by the crash). Every run has a timeout.

**Counters** (`native/rt/src/stats.rs`, the cargo feature `stats`: one-line calls where each event
happens, compiled out without it; `--variant stats` builds it as `target/release/exobox-stats`;
earlier, the same counters were spliced into a scratch copy by a script). TSC-based, relaxed atomics
in the shared section (so fork mode's processes add into one set), printed at the sandbox's end: per
trapped syscall number, calls and cycles in the dispatcher and how much of that was waiting for the
token; token acquires (free / contended / found the idler holding it), cycles each holder kept it,
hand-offs and their latency (owner set → the new owner running), eventfd waits; time inside
`lkl_syscall`; scheduler switches; arena clearing and copies (bytes, cycles); exec loads; host
forks. Overhead: the instrumented binary's walls match the plain one's within noise.

**Experiments** (scratch patches over the instrumented copy, deleted since: `aff8` became fix 1's
CPU count, `idler` fix 6, `spin` was rejected):
`aff8` (sched_getaffinity reports 8 CPUs), `idler` (the kernel idler sleeps without the token, and
a return to user mode hands the token to it only when a timer is due), `spin` (a token waiter spins
~20 µs before blocking).

`perf record` was not used: `perf_event_paranoid` is 2 here, so only user-space sampling of own
processes works, and the questions were about waiting, which sampling doesn't show; `perf stat`
(software events, user-space cycles) worked and is used for CPU time.

## Micro costs

| | native | coroutine | threaded | fork |
|---|---|---|---|---|
| `getppid` (LKL-served) | 0.075 µs | 1.29 µs | 1.33 µs | 1.40 µs |
| `rt_sigprocmask` | 0.094 µs | 0.99 µs | 1.05 µs | 0.89 µs |
| signal delivered and returned | 1.1 µs | 1.74 µs | 1.79 µs | 1.94 µs |
| pipe ping-pong round trip (two threads) | 2.5-4.6 µs | 6.0 µs | 23.9 µs | 26.7 µs |
| futex ping-pong round trip (two threads; syscall_bench's `futex`, added later) | 3-4 µs | - | 3.7-5 µs | 3.6-5 µs |
| fork + exec + exit of `true`, from bash | 0.68 ms | - | - | 4.9 ms |
| ... of `bash -c :` | 1.6 ms | - | - | 6.4 ms |
| ... of `cc1 --version` (51 MB binary) | 8.2 ms | - | - | 21.1 ms |
| host fork (parent's side, in the kernel's clone) | - | - | - | 0.28-0.42 ms |

(`./test --perf` syscalls and `native/bench`'s exec loop.) The trap round trip itself (SIGSYS
delivery, frame move, `rt_sigreturn`) is ~0.8 µs of the ~1.3 µs; an uncontended token adds little
(threaded ≈ coroutine). What makes the parallel modes slow is never the single call: it is
contention, hand-offs and the work done while holding the token.

## Where the time goes, per workload

### rustc -C codegen-units=16 (one process, ~16-40 threads)

| | wall | CPU | trapped calls | of them emulated | token held | of that, hand-off latency |
|---|---|---|---|---|---|---|
| native | 1.56 s | 4.45 s | (37k futex, 18k mprotect under strace) | | | |
| fork, shipped | 4.49 s | 4.43 s | 14.8k | 89% | 0.49-0.66 s | 0.40-0.54 s |
| fork, aff8 | 2.27 s | 5.3 s | 103k | 98% (83k futex, 18k mprotect) | 0.91 s (40%) | 0.78 s |
| threaded, aff8 | 2.01 s | 5.1 s | 145k | 99% (124k futex) | 0.81 s (40%) | 0.70 s |

- **Shipped: CPU/wall is 1.00.** Everything after the frontend runs on one codegen thread because
  `available_parallelism()` is 1. 2.9 s of the gap.
- **With 8 CPUs reported** the gap is 0.35-0.7 s. The guest kernel is nearly idle: 1,634
  kernel-served calls, ~0.13 s of the token's 0.9 s held is real work; the rest is hand-off latency
  (~100k hand-offs at 6-13 µs). The calls behind it are futexes (LLVM's and rustc's worker queues,
  std's Mutex/Condvar) and glibc growing its per-thread heaps with `mprotect`; neither touches the
  kernel. With the token, a futex wake is: the waker takes the token, marks the waiter runnable;
  on the waker's return the token goes, by a directed hand-off, to the waiter's host thread
  (asleep in `read` on its eventfd); the waiter wakes, returns, gives the token back. So futex
  traffic between N threads becomes token traffic through one sleeping chain, and rustc makes 2-3x
  the futex calls it makes natively (its spinning-then-parking locks park more when wakes are
  slow).
- The kernel idler: 25-42k of the 72-128k contended acquires found the idler holding the token in
  its timed `ppoll` (it keeps the token while sleeping to the next timer, and every return to user
  mode with any timer armed hands the token to it). Freeing it (`idler`): on `6d3364f` fork rustc
  1.32x → 1.18x, threaded unchanged; on `92def71` (whose idler also holds the token while it
  watches host fds) threaded 1.38x → 1.21x, fork 1.31x → 1.28x, with hand-offs 94-116k → 23-40k
  and contended acquires that found the idler 30-39k → 1-3k. With stdout a pipe (`xz -T4 | cat`)
  the shipped idler holds the token 90 of 130 ms; the experiment's simplification (a new fd wait
  while it already watches others is seen only at its next wake) stalled one such run 2 s, so the
  real fix must kick the idler when the watched set changes.
- Spinning before sleeping (`spin`) made it worse: 1.98-2.18x. With 16 codegen threads on 8 cores,
  spinners take cores from compiling threads (the host can't tell a spinner from work). Spinning is
  only a win with idle cores; capnix's `TIERA_SPIN` result (8 threads held at the one-CPU ceiling)
  was on an idle 24-core machine.
- Memory: file mappings copied 147 MiB (librustc_driver's 150 MB, copied at exec: threaded and fork
  mode are high-water, so nothing maps in place), in 30 ms; high-water clearing 170-250 MiB in
  25-35 ms. Small here.

### xz -T4 (one process, 4 compressing threads)

1.09-1.13x in threaded and fork mode; 2.7k trapped calls, token held 15% of the wall. The threads
only meet at block boundaries (159 futex calls). Coroutine mode runs the four on one host thread
(3.9x), as designed. Nothing to fix here beyond the general items; it shows that computing threads
scale.

### make -j4 of 32 C files (fork mode: ~140 processes)

| | wall | CPU | trapped calls | kernel-served | token held | hand-off | exec (copy + zero) | ld.so's mappings (copy) |
|---|---|---|---|---|---|---|---|---|
| native | 1.21-1.24 s | 4.61 s | | | | | | |
| fork | 3.66-4.00 s | 6.4-6.5 s | 72.8k | 92% | 2.5-2.9 s (69-75%) | 1.06-1.44 s (18-29 µs each) | 0.93-0.98 s | ~0.26 s |

The token is the bottleneck: busy 70% of the time with four jobs wanting it. What occupies it:

- **Hand-off latency, 1.1-1.4 s.** 60k contended acquires; each ends with the token assigned to a
  sleeping thread, idle for the 18-29 µs the host takes to wake it.
- **Exec, ~1.0 s, plus ~0.26 s of ld.so's library mappings.** Per exec ~7 ms under the token:
  the old image's dirty pages zeroed in place (800 MB in 0.49 s over the build; in a fork's child
  those pages are copy-on-write, so zeroing each one first copies it), then the new program and
  every library it maps *copied* from the guest's files into the arena (2.29 GB in 0.66-0.70 s:
  cc1 alone is 51 MB a compile). Threaded and fork mode are high-water (no `madvise`: the filter's
  Dirty-COW rule), and the arena's in-place mapping of store images works only in release mode,
  so in fork mode nothing is mapped in place.
- **The kernel's own work, ~0.3 s** for 67k calls: `readlink` 28k (gcc's driver resolving paths),
  `rt_sigaction` 8.3k, `openat` 7.2k, `newfstatat` 4.5k, `read` 4.2k, `close`/`fstat`/`lseek`
  ~2.5k each. 4-10 µs each including the trap, most of it waiting.
- Host forks: 111, 47 ms in all (0.42 ms each), not a problem at this closure size (~600
  mappings per process; a closure with thousands of per-file mappings makes fork and exit
  proportionally dearer: python's 7,741 ≈ 4 ms per exit).
- `clone` shows 9-11 ms a call: make's `posix_spawn` is a vfork, whose parent waits for the
  child's exec; that is exec's cost seen twice, not the fork's.
- CPU: 6.4 s against 4.6 natively: the 1.9 s extra is the copies and zeroing (~1.2 s), traps and
  hand-off bookkeeping.

None of the experiments moved it (aff8 2.95x, idler 3.35x, spin 3.11x: within noise of 2.95-3.33x):
the cost is the exec path and hand-offs, which none of them touch.

### rustmake: 6 crates and a binary, rustc under make -j4 (fork mode)

| | wall | CPU | trapped calls | emulated | token held | hand-off |
|---|---|---|---|---|---|---|
| native | 6.98-7.03 s | 12.1 s | | | | |
| fork, shipped | 12.72 s (1.82x) | 12.5 s | 73k | 47% | 2.0 s (16%) | 1.5 s |
| fork, aff8 | 7.83 s (1.12x) | 13.4 s | 198k | 80% (113k futex, 42k mprotect) | 1.65 s (21%) | 1.2 s |

The crate chain leaves little process-level parallelism, so this is mostly rustc's own threads:
the CPU count (5.7 s of the gap) and then the futex/hand-off pattern of the rustc workload. 23
execs; exec and copies are small here (45 ms, 40 ms). The idler held the token in 70-86k of the
112-133k contended acquires (its ppoll is 2.4 s of token-held time over the run), yet freeing it
measured no gain (1.13x): the waits moved to hand-offs.

## Ranked bottlenecks and candidate fixes

Ranked by share of the measured gap to native on these workloads. "Gain" is measured where an
experiment exists, otherwise estimated from the counters (and says so).

| # | Bottleneck | Share of the gap | Fix | Gain | Cost / risk |
|---|---|---|---|---|---|
| 1 | One CPU reported (`sched_getaffinity` → `1`) | rustc 2.9 of 2.9 s; rustmake 5.7 of 5.7 s; any pool sized from nproc | Report the host's affinity mask (read before lockdown; optionally capped by a config) | **Measured**: rustc 2.84x → 1.20-1.32x; rustmake 1.82x → 1.12x | Trivial. More threads also means more futex/token traffic (#3), which is why rustc doesn't reach 1.0x |
| 2 | Exec copies programs and libraries, and zeroes the old image, under the token (fork/threaded are high-water: no in-place mapping) | make: ~1.2 s of token time (of 2.5 s held), ~1.2-1.5 s CPU | Map in place in high-water mode: track which image-zone pages are pristine (still the image's bytes) instead of relying on `madvise` to restore them; place an exec's new image on pages never touched (or freshly forked-clean) instead of zeroing the old one in place, zeroing lazily at reuse. Alternatively allow `madvise(DONTNEED)` in the arena in fork mode (capnix's fork mode did) and use release mode | Estimated make -j4 3.0x → ~2.0x (−1.2 s token time, −1.2 s CPU); per exec ~7 ms → ≤1 ms; also memory (page cache shared instead of 51 MB per cc1) | Medium (the arena's clean/dirty model, exec's layout). The madvise route is smaller code but widens the filter in fork mode: a policy call (the Dirty-COW argument is about host kernel bugs in concurrent `madvise` + faults, which every multithreaded native malloc does) |
| 3 | Futexes emulated under the token; each wake a token hand-off to the wakee | rustc after #1: most of the remaining 0.35-0.7 s; rustmake after #1: most of 0.8 s; pipe round trip 24-27 µs vs 6 (coroutine) | Futexes off the token: a futex table with per-bucket spinlocks, a waiter blocks on its own slot's wake eventfd (a second fd range, or the token's with a tag), a waker writes it directly; timeouts with `ppoll` on that fd; signals and group exit wake the waiter as `interrupt_waits` does now. Fork mode: per-process table (it already is per-process space) | Estimated rustc/rustmake to ~1.05x (removes ~100k token acquisitions and hand-offs per rustc); futex round trip to ~5-8 µs | Medium: signal interruption, exit and exec paths, timeouts, requeue/PI ops (keep them on the slow path) |
| 4 | Hand-off latency: the token assigned to a sleeping thread sits idle until the host wakes it (6-29 µs) | make: 1.1-1.4 s of 2.5 s held; rustc: 0.7-0.8 s of 0.9 s held | (a) Fewer acquisitions (#3, #5); (b) release instead of assign: the releaser frees the token and wakes the next waiter, and a thread already awake may take it first (barging, bounded to keep FIFO fairness); (c) adaptive spinning only when cores are idle (measured harmful with oversubscription: rustc 1.2x → 2.0x) | Estimated make −0.5 to −1.0 s once #2 shortens holds; rustc follows #3 | Low-medium for (b); (c) needs a load signal and capnix saw a race on its spin path (`lkl_cpu_put: unbalanced put`) |
| 5 | Memory calls take the token though they touch only the arena (`mprotect` 18-43k per Rust build, `mmap`/`munmap`) | 0.1-0.4 s of summed waits per run; more acquisitions feeding #4 | A per-process arena lock instead of the token for `mmap`/`munmap`/`mprotect`/`madvise`/`brk` (file-backed `mmap` still needs the kernel for its reads, outside the arena lock) | Estimated 2-5% on Rust builds | Low-medium: the arena's Backing calls into LKL for file maps |
| 6 | The kernel idler keeps the token while it sleeps to a timer or watches host fds, and every return to user mode with a timer armed (or an fd watched) hands the token to it | 25-90k contended acquires per Rust run; half of rustc's token time | `idler` experiment: free the token while sleeping, hand it over only when a deadline is due or earlier than the idler's, or an fd wait begins | **Measured** (`92def71`): threaded rustc 1.38x → 1.21x, fork 1.31x → 1.28x; rustmake, make: within noise | Low. Must kick the idler when a timer earlier than its sleep is armed or the watched fds change (the experiment only half does the latter) |
| 7 | The guest kernel's own serialized work (what an SMP kernel parallelizes) | make: ~0.3 s; rustc: ~0.13 s; grows in share as #2-#4 shrink | SMP guest kernel (below), or a shorter kernel path (signal mask without the token as capnix did: `rt_sigprocmask`/`rt_sigaction` are 10k of make's calls) | make: up to ~0.3 s now, maybe 10-20% of the remaining wall after #2-#4 (queueing of 4 jobs on one CPU at ~30-40% utilisation) | SMP: high (below). Mask fast path: low-medium |
| 8 | Per-process fixed cost besides exec's copies (exec's LKL calls, the arena's tables, the kernel's fork/exit, init's reaping) | make: 140 processes × ~2-4 ms | A pristine "spawn server" process forked once at boot for exec'd children (capnix's fork-server idea), so an exec'd child doesn't inherit and clear its parent's dirty memory | Estimated a further −0.1 to −0.3 s on make after #2 | Medium-high: a second fork path |
| 9 | The SIGSYS round trip (~0.8 µs of each ~1.3 µs call) | make: 73k calls ≈ 60-90 ms CPU (1-2% of wall); Rust: <1% | Syscall-site rewriting (a jump to the dispatcher instead of the trap) | 1-2% | High: binary rewriting of loaded code and JIT output, the filter still needed for unrewritten sites. Last |
| 10 | Host fork (0.3-0.4 ms, under the token) and per-file store mappings | make: 47 ms of 2.4 s | One mapping per store image (the coordinator's 7,741-mapping python case: ~4 ms per exit); fork with the token released | <2% here; more with large closures | Low (images) / medium (fork without the token) |

## Answers to the SMP design question

**The design**: LKL made SMP with N CPU tokens; a kernel entry takes whichever CPU is free; a
host thread holds a CPU only while serving a trapped call, so a CPU is either running bounded
kernel code or idle on its eventfd, and RCU's quiescent state is "the token was returned".

### 1. How much of each gap would N CPUs parallelize?

From the token accounting (time held, split into hand-off latency, the runtime's own work under
the token, and the rest, which is the kernel's):

| workload (fork mode) | gap to native | kernel work N CPUs parallelize | removed by cheap fixes (measured or estimated) | other |
|---|---|---|---|---|
| rustc cgu16 | 2.9 s | ~0.13 s of token-held kernel work (1.6k kernel calls) | CPU count: 2.9 s → 0.5-0.7 s left (measured); idler: → 0.34-0.45 s left (measured); futex and mprotect off the token: most of the rest (estimated) | hand-off latency 0.8 s of token time, almost all from futex traffic |
| rustmake | 5.7 s | ~0.3-0.4 s | CPU count: 5.7 s → 0.8 s (measured); futex/mprotect off the token: most of the rest (estimated) | as above |
| make -j4 | 2.4-2.8 s | ~0.3 s | exec without copies/zeroing: ~1.2 s of token time and ~1.2 s CPU (estimated); hand-off reduction: part of 1.1-1.4 s (estimated) | per-process fixed cost ~0.3 s, traps ~0.1 s |

N CPUs would also run the runtime's work now done under the token (exec's copies) in parallel, so
an SMP kernel *today* would help make more than "0.3 s" suggests: with the copies spread over four
CPUs and fewer hand-offs, make might go from ~3x to ~1.8-2x. But the cheap fixes remove that same
work outright rather than parallelizing it, and are needed anyway (they cost CPU, not only wall).

The idler holding the token is real (rustc: 1.6 s of 5.1 s held by the idler in its ppoll, in the
shipped build) and freeing it is measured: rustc 1.38x → 1.21x threaded on `92def71`; nothing
measurable for make (its waits are exec work and hand-offs, not the idler). mprotect taking the token: 18-43k calls per Rust build, 0.1-0.4 s of summed waits.

### 2. Is the single guest CPU *the* bottleneck for make -j4 / cargo -j4?

For `make -j4`, the token is saturated (70%), so yes in the sense that everything queues on it.
But what fills it is mostly not the kernel: hand-off latency (~45%) and exec's copying and zeroing
(~45%); the kernel's own work is ~10%. After #2-#4, an estimate: make -j4 at ~1.3x native, with the
token busy maybe 30-40% of a ~1.6 s run, of which the kernel's work is most. At that point the one
CPU is the bottleneck of what is left: four jobs queueing on a 35%-busy server lose ~10-20%, which
is about the gap. For `cargo -j4`-style Rust builds (rustmake), no: the kernel is ~5% of the token
and the token ~20% of the wall; the gap is the CPU count and futexes.

### 3. Is the design reasonable?

Yes: CPU = token removes the hard part of capnix's analysis. capnix mapped CPU = program thread,
and then per-CPU operations (RCU grace periods, `schedule_on_each_cpu`, lru drains, slab flushes)
wait for a CPU busy in user code that nothing can interrupt without host signals. With CPUs as
tokens, a CPU is never "in user mode": it is either inside a bounded kernel path or idle and
wakeable by an eventfd write, every kernel exit is a quiescent point, and idle CPUs are like
`nohz` idle CPUs to RCU. No host signals, no new host syscalls. That is the right mapping.

What I'd worry about:

- **LKL's arch is UP by construction**, and the runtime leans on it: `kernel/cpu.c`'s single
  `struct lkl_cpu` *is* the big lock; `current_thread_info()` is one global; `__switch_to` hands
  the CPU between host threads through per-task semaphores and a global `abs_prev`; one
  `idle_host_task`; global IRQ bitmaps; one clockevent; `CONFIG_TINY_RCU`; `!SMP` spinlocks
  compile to nothing (so every kernel lock becomes real and untested on this arch). On our side,
  everything the token protects becomes shared: the scheduler (`Sched`: one run queue, `Cell`s
  throughout), the host-op semaphores/mutexes (cooperative today), the futex table, the arena, the
  hooks' executor, the TSI queues. That runtime audit is as large as the kernel port.
- **Lock-holder preemption.** Real kernel spinlocks held by a host thread the *host* deschedules
  (we are not a VM: no pause-loop exits, no paravirt spinlocks) make the other CPUs spin. Needs
  spin-then-sleep (an eventfd slow path) for kernel spinlocks, which no Linux arch has to do today.
- **Wakeups onto a busy CPU.** A task woken onto CPU k's run queue must run on CPU k's token: if k
  is busy while other CPUs are idle, it waits for k (or for idle balancing, which needs a CPU to be
  running to pull). Today's directed hand-off has the same shape with one CPU; with N it needs a
  policy (wake onto an idle CPU, as `select_task_rq` would, and make idle-CPU pulls cheap).
- **Contention inside the kernel.** Builds hit the dcache/VFS (path walks: 28k `readlink`, 7k
  `openat`, 4.5k `stat` in make), the page cache of erofs and the tmpfs/ramfs build directory, and
  fork/exit/wait (`tasklist_lock`, the process tree). Linux scales these on real hardware, but
  N tokens means the hand-off and spinning costs above per lock bounce.
- **Memory per sandbox.** Per CPU: per-CPU areas (tens of KB), tree RCU's `rcu_data`, SLUB's per-CPU
  slabs (fewer with `SLUB_TINY`), and ~4-6 per-CPU kernel threads (ksoftirqd, migration, cpuhp,
  kworker, rcu), each a coroutine stack: on the order of 100-200 KB per CPU touched, against a
  1.8 MB per-sandbox template budget. So size it per mode: coroutine 1 (no change), threaded/fork
  `min(host cores, a configured N)` with N=4 by default, and templates keep 1 unless asked.
- **Effort.** Kernel side: a per-CPU `current`, per-CPU areas, real atomics/spinlocks, IPIs as
  eventfd writes, N idle loops, tree RCU, per-CPU clockevents or a housekeeping CPU, CPU bring-up:
  ~4-8 weeks for someone fluent in arch code. Runtime side: the scheduler, host ops and every
  token-protected structure made concurrent: another ~4-6 weeks. Then the long tail of hangs under
  load. Two to four months, high risk; the failures are deadlocks, found under load.

Compared by expected gain on these workloads:

| option | expected gain | effort |
|---|---|---|
| Cheap fixes #1, #3, #5, #6 | Rust builds 1.8-2.9x → ~1.05-1.1x (measured for #1, estimated for the rest) | days to two weeks |
| #2 exec without copies, #4 fewer/faster hand-offs | make -j4 3x → ~1.3x (estimated) | two to four weeks |
| Moving store-image file I/O off the kernel path (serve `open`/`stat`/`readlink`/`read` of read-only erofs paths in the runtime) | make: part of the ~0.3 s kernel work (path lookups are most of make's calls) | high: the fd table, cwd, permissions and `/proc` are the kernel's; two sources of truth |
| SMP guest kernel (CPU = token) | after the cheap fixes, the remaining ~10-20% of make -j4; little for Rust builds | 2-4 months, high risk |
| Scale-out (a kernel per process) | not applicable: a build's processes must share a filesystem and process tree | - |

So: reasonable design, the right mapping of CPUs, and probably what the last 10-20% of a parallel C
build needs. Not first: by these measurements most of today's gap is elsewhere, and SMP on top of
today's exec path and futexes would parallelize waste rather than remove it.

## Reaching 5%

- **Rust builds** (rustc with codegen units, rustc under make): #1 gets to 1.05-1.4x, #1 + #6 to
  1.1-1.28x (measured). #3 and #5 target what remains (futex and mprotect traffic through the token, the idler); the
  counters say the kernel's work is ~5% of the token there, so ~1.05x looks reachable without an
  architectural change. To be confirmed by building #3.
- **C builds with make -j4**: #2 and #4 should get to ~1.3x (estimated). The rest is per-process
  cost (#8, #10), traps (#9) and the one CPU (#7). 5% for a fork/exec-heavy C build likely needs
  the SMP kernel or an equivalent cut of the kernel's serialized work, plus the spawn-server exec;
  I would decide that after #2-#4 are in and remeasured, when the token's remaining occupancy is
  known.

Suggested order: #1 (hours), #6 (a day), #3 (a week), #5, #2 (two weeks), #4, then remeasure with
`native/bench/run` and the counters before deciding on SMP.

## Bugs found while measuring

- **cargo crashed the sandbox** in every mode (a NULL dereference after Rust std's `statx(0, NULL, ...)` probe): fixed on main by `22f1bd0` (statx checks the program's pointers before LKL reads them); the `cargo` workload runs since.
- `./test --perf`'s `xz::threaded` and `xz::fork` time out: the full-stdout-pipe hang (`xz -T2 |
  cat`), known and being fixed; the harness writes stdout to files.
- In fork mode `wait4`'s rusage doesn't include the build's processes (init reaps them with
  `SA_NOCLDWAIT`): use `perf stat` (the harness's `--perf`) for CPU time.
