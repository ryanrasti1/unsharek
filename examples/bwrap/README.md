# unsharek under bubblewrap

bubblewrap is the outer jail: its namespaces decide what exists at all (the store, one work
directory). unsharek is the inner one: its seccomp filter decides which host kernel calls can
be made, each argument pinned. Together a program sees only what bwrap shows, and reaches the
host kernel only through unsharek's few calls.

```sh
examples/bwrap/run.sh ./work $(command -v busybox) sh -c 'echo hi > /work/out'
```

`run.sh` runs `unsharek --mount <store path>:map --mount /work:rw` inside `bwrap
--unshare-all` (a static program: its store path mapped in place). The `rw` mount is a live host directory (experimental): its paths are confined
by unsharek's Landlock ruleset and, under it, by bwrap's view. With `--no-landlock` only bwrap
confines them, which is what that flag is for: an environment that already scopes file access.

The cases run by `cargo xtask test` are `crates/unsharek/tests/jails.rs` (`bwrap_*`).
