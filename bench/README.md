# bench

What unsharek costs against native, measured three ways:

| Command | What | Time |
|---|---|---|
| `cargo xtask stats` | The headline numbers: README.md's, written to [STATS.md](STATS.md) | under a minute |
| `cargo xtask vs-native` | Build workloads, each mode against native, pass/fail against a target ratio (`quick.py`) | about a minute |
| `bench/run` | Full-size build workloads with the runtime's counters (`build_bench.py`; [PERF.md](PERF.md), the analysis) | minutes |

`cargo xtask perf` (crates/unsharek/tests/perf.rs) is the budgets: a regression check, not a
report. `stats` reads its template trial and reuses `quick.py`'s workloads, so each thing is
measured in one place.

## `cargo xtask stats`

Each row is the median of `--reps` runs (default 3; memory is one sample of 8 sandboxes), its spread in parentheses, with the ratio to
native where native has the same thing:

- **idle bash, RSS and PSS:** `bash -c 'echo READY; read x'` blocked on stdin, 8 at once; RSS is
  one process's resident memory, PSS its share with the 8 counted together (shared pages split).
  In a sandbox that is the guest kernel, the runtime and bash.
- **template child, PSS and start to READY:** sandboxes forked from one booted, set-up sandbox
  (`Guest::spawn`), 8 at once: what each further sandbox costs. Coroutine and threaded mode.
- **hello, start to exit:** a fixture that prints and exits, the whole `unsharek` run.
- **getppid:** one syscall served by the guest kernel (`syscall_bench`), against the host's.
- **xz -T1:** single-threaded CPU work (8 MB, level 3): compute with few syscalls, so what the trap
  and the scheduler add to plain CPU time. Every mode.
- **xz -T4, make -j4, rustc:** parallel work: four compressor threads; `make -j4` of 12 C files
  and a link (fork mode: it forks); rustc with 16 codegen units (its threads). The guest has one
  CPU, which is most of the gap (PERF.md).

It waits for a quiet machine (1-minute load under 4, I/O pressure under 5%) before each section,
up to `--wait` seconds, and stops rather than publish numbers taken under load (`--force` to measure
anyway; the output says so). `--reps`, `--n`, `--load` and `--wait` tune it.
