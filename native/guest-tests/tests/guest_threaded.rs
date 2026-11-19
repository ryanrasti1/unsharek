//! The guest tests (native/guest-tests/src), under `exobox run --mode threaded`, a sandbox per test: see .config/nextest.toml.
guest_tests::all!(threaded);
