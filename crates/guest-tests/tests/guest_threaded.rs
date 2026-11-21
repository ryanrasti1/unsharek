//! The guest tests (crates/guest-tests/src), under `unsharek --mode threaded`, a sandbox per test: see .config/nextest.toml.
guest_tests::all!(threaded);
