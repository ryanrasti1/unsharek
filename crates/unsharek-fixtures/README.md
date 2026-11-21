# unsharek-fixtures

The C programs the host-side suite (`crates/unsharek/tests/suite.rs`) runs under `unsharek`, one a
file in `c/`, built by `build.rs` and found through `DIR`. Each prints `<NAME>_OK` when it passes;
the escape probes (`escape_gate.c`) instead each make one forbidden host call and must die of SIGSYS.
