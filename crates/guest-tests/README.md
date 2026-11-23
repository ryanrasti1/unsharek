# guest-tests

What a program observes inside the guest (files, threads, signals, sockets, `/proc`, exec, fork), as
Rust `#[test]`s: a function in `src/`, listed in `all!` (`src/lib.rs`). One source, four test
binaries: `guest_native` runs them as they are (which checks the tests themselves), and
`guest_coroutine`, `guest_threaded` and `guest_fork` run each test in a sandbox of its own in that
mode, through nextest's run-wrapper `run-in-guest`. A test that fails in a mode is
`#[ignore = "<why>"]` in that mode's arm of `all!`.
