# unsharek: headline numbers

`cargo xtask stats` (2026-11-19, commit 5979d61-dirty; Intel(R) Core(TM) Ultra 9 275HX, 24 CPUs, Linux 6.18.59; median of 3, spread in parentheses; 41 s to run). bench/README.md says what each row measures.

| | native | coroutine | threaded | fork |
|---|---|---|---|---|
| idle bash, RSS | 4.3 MB | 15.1 MB | 15.1 MB | 14.7 MB |
| idle bash, PSS (8 at once) | 0.9 MB | 4.6 MB | 4.6 MB | 4.8 MB |
| template child, PSS (8 at once) | - | 1.9 (1.9-1.9) MB | 1.9 (1.9-1.9) MB | - |
| template child, start to READY | - | 3.0 (2.9-3.2) ms | 3.8 (3.5-3.8) ms | - |
| hello, start to exit | 5.3 (5.3-30.9) ms | 21 (16-21) ms, 3.88x | 21 (21-21) ms, 3.90x | 21 (21-21) ms, 3.87x |
| getppid | 0.16 µs | 2.74 (2.73-2.74) µs, 17.45x | 2.81 (2.76-3.40) µs, 17.90x | 2.80 (2.74-2.81) µs, 17.82x |
| xz -T1, 8 MB | 0.44 (0.44-0.47) s | 0.46 (0.46-0.58) s, 1.05x | 0.46 (0.46-0.47) s, 1.05x | 0.47 (0.47-0.47) s, 1.06x |
| xz -T4, 8 MB | 0.15 (0.14-0.15) s | 0.48 (0.47-0.48) s, 3.30x | 0.16 (0.16-0.17) s, 1.10x | 0.16 (0.16-0.17) s, 1.13x |
| make -j4, 12 C files | 0.70 (0.69-0.70) s | - | - | 1.43 (1.35-5.38) s, 2.04x |
| rustc, 16 codegen units | 1.24 (1.24-1.53) s | - | 1.35 (1.30-1.83) s, 1.09x | 1.31 (1.28-1.33) s, 1.05x |

Ratios are to native. Fork mode is the only one that runs `make` (it forks). A template child is
a sandbox forked from a booted, set-up one (`Guest::spawn`); fork-mode templates don't exist yet.
