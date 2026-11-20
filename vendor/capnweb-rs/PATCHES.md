# capnweb-rs, vendored

A copy of capnweb-rs (`rust/` of capnweb, as capnix-proper's `deps/capnweb` has it), for unsharek's
network plugin, with these changes. Each is proposed upstream; once capnweb-rs has them, this copy
goes and unsharek depends on capnweb-rs itself.

1. **`packet`: a packet transport an embedder drives** (`src/packet.rs`, `src/lib.rs`'s `pub mod
   packet`, under `std`, without `tokio`). `UdsTransport`'s wire format (one JSON message per
   `SOCK_SEQPACKET` packet, SCM_RIGHTS descriptors as `["fd", i]`) over a `PacketSocket` trait:
   the embedder's nonblocking `send`, `send_fds`, `recv` and readiness (`poll_ready`), so the
   transport makes no syscall of its own and runs on any `Runtime` (an in-process sandbox's
   executor, `capnweb::local`). Descriptors are `Fd` numbers, never closed by the transport.
2. **A message without descriptors is a plain send** (`PacketSocket::send`: a `write(2)` on a
   seqpacket socket), so a side that only receives fds needs no `sendmsg`. (`UdsTransport` always
   `sendmsg`s.)
3. **No stack growth in the sandbox**: already upstream (the `stack-growth` feature, off here:
   `default-features = false`); nothing to change.
4. `#![allow(dead_code)]` in `src/lib.rs`: built without `tokio`, much of the crate is unused here.

Not copied: tests, examples, the JS parity tooling, docs other than `runtime.md`.
