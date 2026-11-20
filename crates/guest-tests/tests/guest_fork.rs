//! The guest tests (crates/guest-tests/src), under `exobox run --mode fork`, a sandbox per test: see .config/nextest.toml.
guest_tests::all!(fork);
