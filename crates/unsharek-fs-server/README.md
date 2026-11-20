# unsharek-fs-server

**Plugin (experimental).** Serves one host directory to a sandbox's virtio-fs device (unsharek-fs),
from a process of its own: virtiofsd's passthrough file system (fuse-backend-rs) on the other end
of the device's socket. When enabled (the CLI's `--ro DIR`, `--rw DIR`), this crate is part of the
TCB, as its process's confinement, but not the core sandbox's: the sandbox gains a granted socket
and nothing in its filter.

`spawn` forks the server twice (it is no child of the sandbox's), before the sandbox boots. The
server confines itself before its first request:

1. its fds: the socket, stderr, and what the file system opens; every other fd closed;
2. Landlock, to the directory: read-only, or read-write; nothing else on the file system, so `..`,
   symlinks, renames and hard links can't reach outside it whatever the file system code does;
3. core dumps off, not dumpable, no capabilities, `no_new_privs`;
4. its seccomp filter (`src/policy.rs`): the 45 calls the file system and its loop make, as a
   plain function compiled by seccomp-fn and proven by seccomp-fn-verify (`cargo xtask prove`).

It acts as its own user (the requests' uid and gid are zeroed), refuses a read-only directory's
changes early (EROFS) with Landlock under that, and refuses a `LOOKUP` of `.` or `..`, which
fuse-backend-rs would answer with the root's parent. The sandbox can send it anything (a
compromised program writes the guest kernel's memory): `tests/server.rs` speaks raw FUSE to it as
such a sandbox would.
