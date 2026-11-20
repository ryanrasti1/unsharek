# Runtimes, and the core without std

capnweb-rs runs on a pluggable async runtime, and its protocol core builds without std. One
source tree, five features:

| Feature | Default | What it adds |
|---|---|---|
| `std` | yes | thread-local recording state, caught panics |
| `stack-growth` (implies `std`) | yes | stack growth for deep messages: `stacker` segments, `serde_stacker` parsing (see [Message depth](#message-depth-and-the-stack)) |
| `tokio` (implies `std`) | yes | tokio as the runtime when none is entered; `FramedStreamTransport`, `UdsTransport`, byte channels (`ByteChannel`, `ByteChannelSession`), HTTP batch; `io::Compat`; `ReadableStream::new`/`take` and `WritableStream::new`/`take` on tokio's `AsyncRead`/`AsyncWrite` |
| `websocket` (implies `tokio`) | yes | `WebSocketTransport` |
| `local-runtime` | no | `capnweb::local::LocalRuntime`, a single-threaded executor with a virtual clock (with or without std) |

`--no-default-features` is `#![no_std]` + `alloc`. A crate that used `default-features = false`
before this split (and so got tokio, without WebSocket) now asks for `features = ["tokio"]`, and
`features = ["stack-growth", "tokio"]` to keep growing the stack for deep messages.

## What works where

| | `no_std` + `alloc` | std, no tokio | tokio |
|---|---|---|---|
| Stubs, promises, payloads, errors, `#[rpc_target]`/`#[rpc_interface]` | yes | yes | yes |
| Sessions: calls, pipelining, release, abort, `map()` and record/replay closures | yes | yes | yes |
| Streams (`ReadableStream`, `WritableStream`, flow control) over `io::ByteRead`/`ByteWrite` | yes | yes | yes |
| `FramedTransport` (4-byte big-endian length + JSON) over `ByteRead` + `ByteWrite` | yes | yes | yes |
| Custom transports (`AnyRpcTransport`) | yes | yes | yes |
| `FramedStreamTransport` (tokio streams), byte channels, UDS, HTTP batch, WebSocket | | | yes |

Without std:

- **Depth.** As without `stack-growth` ([below](#message-depth-and-the-stack)): JSON nesting is
  bounded by `MAX_JSON_DEPTH`, and the stack never grows.
- **Panics** in callbacks, abort handlers and pending promises aren't caught; they reach the
  embedder's panic handler (use `panic = "abort"`).
- **One executor thread.** What std keeps per thread (the entered runtime, the call interceptor and
  `map()` recorder, each scoped to a synchronous call) is one global. Poll all of the core's work on
  one thread at a time. Wakers may be called from any thread.
- **Locks** are spin locks (`spin`). No lock is held across an `.await` or while a waker runs, so on
  one thread they never spin.
- **`HashMap`** is hashbrown's with its default (foldhash) hasher.

## The abstraction

### `capnweb::runtime::Runtime`

```rust
pub type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

pub trait Runtime: Send + Sync + 'static {
    /// Polls `task` to completion in the background, waking it through real wakers. A task that
    /// wakes itself and returns Pending runs again only after the tasks already ready (FIFO).
    fn spawn(&self, task: Task);
    /// Monotonic time since an arbitrary fixed origin.
    fn now(&self) -> Duration;
    /// Completes once `now()` reaches `deadline`.
    fn sleep_until(&self, deadline: Duration) -> Task;
}
```

The core spawns each session's read loop, the continuations that give promises JavaScript's
ordering (`eager_promise.rs`), and the pumps and writers of streams. The stream flow controller
times round trips with `now()`. The core sets no timers itself; `sleep_until` is for embedders'
deadlines, through `capnweb::runtime::{sleep, sleep_until, now}`. Where JavaScript resumes in a
later microtask the core yields by waking itself once, hence the FIFO requirement.

`Send` and `Sync` are there because the core's values are shared with the multi-threaded tokio
build; one signature serves both. A single-threaded executor satisfies them with a `Send` run queue;
an embedder value that isn't `Send` (a C `void *`) needs a wrapper of its own.

### Which runtime runs a task

1. The runtime entered on this thread: `runtime::enter(&rt, || ...)` for synchronous code,
   `runtime::scope(rt, future)` for a future (entered on each poll), `runtime::spawn(future)` from
   inside one. Every task the core spawns on a `Runtime` is entered while polled, so a session
   created inside a scope stays on that runtime.
2. With `tokio`: the ambient tokio runtime (`Handle::try_current()`). Code that never names a
   runtime behaves as before.
3. The process-wide default, `runtime::set_default(rt)` (once).

So a std + tokio program can run a session on another executor: create it inside `scope`/`enter`.
With nothing current, `RpcSession::new` panics as `tokio::spawn` does, and a pending eager promise
fails.

`runtime::TokioRuntime` is tokio as a `Runtime`; `local::LocalRuntime` is the reference executor.

### `capnweb::io::{ByteRead, ByteWrite}`

```rust
pub trait ByteRead: Send {
    /// Ok(0) for a non-empty buf is the end. Pending registers the waker.
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize>>;
}
pub trait ByteWrite: Send {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>>;
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>>;
    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>>;
}
```

`futures::io`'s shape with `capnweb::Error` for errors, so neither std nor tokio. `ByteReadExt` and
`ByteWriteExt` add `read`, `read_exact`, `write`, `write_all`, `flush`, `close`. `io::pipe(cap)` and
`io::duplex(cap)` are in-memory pipes; `io::Compat` (tokio) adapts both ways.

They carry:

- `FramedTransport::new(reader, writer)` / `FramedTransport::builder()` (max frame size, custom
  types, abort handlers): the session's transport. Frames leave in `send()` order; an abort, a bad
  or truncated frame, the end of the stream, or a failed read or write aborts it, waking pending
  sends and receives; dropping it aborts it.
- `ReadableStream::from_reader(r)` / `take_reader()` and `WritableStream::from_writer(w)` /
  `take_writer()`: byte streams in RPC values, on JavaScript's wire protocol, with its flow
  control (at most `MAX_QUEUED_WRITES` chunks of 64 KiB unacknowledged per stream).

### Sync primitives

Inside the core: `platform::Mutex` (std's, or a spin lock), and `sync.rs`'s `AsyncMutex`,
`Signal` (a set-once broadcast, the abort reason) and an unbounded channel, all on `core::task`
wakers. `futures`' `oneshot`, `FuturesUnordered` and `abortable` (alloc-only) do the rest. Nothing
is supplied by the embedder.

## Plugging in an executor (capnix on exobox)

capnix implements, over exobox's executor:

1. `Runtime`: `spawn` → exobox's `spawn` (FIFO); `now` → its monotonic clock as a `Duration`;
   `sleep_until` → its `sleep_until`.
2. `ByteRead` + `ByteWrite` over the held fd (the kernel connection): `poll_read`/`poll_write` try
   the nonblocking `read`/`write`; on `EAGAIN` register the waker with exobox's
   `readable(fd)`/`writable(fd)` and return `Pending`. `poll_close` shuts the fd's write side.
   The same, over each guest socket end, for the byte streams it pumps.
3. Then, inside a task on that executor:

   ```rust
   let rt: Arc<dyn capnweb::runtime::Runtime> = Arc::new(ExoboxRuntime::new(cx));
   cx.spawn(capnweb::runtime::scope(rt, async move {
       let transport = capnweb::FramedTransport::new(FdReader(fd), FdWriter(fd))?;
       let session = capnweb::RpcSession::new(Arc::new(transport), None, Default::default())?;
       let bootstrap = session.get_remote_main();
       // calls, pipelining, streams: one session, many concurrent calls and streams
   }));
   ```

   (or `capnweb::runtime::set_default(rt)` once, if nothing else in the process uses capnweb on
   another runtime; in a std + tokio build, outside tokio threads). With std, the entered runtime
   is per thread; without std, keep all capnweb work on the executor's one thread.

`LocalRuntime` (`src/local.rs`) is the same in miniature: a FIFO queue of `ArcWake` tasks, timers
on a clock, and `block_on(future, idle)` whose `idle` is where a real embedder waits (`ppoll`).

## Message depth and the stack

Parsing, evaluating and serializing a message recurse once per level of nesting. Two bounds apply:

- **`RpcLimits::max_depth`** (per session, default `DEFAULT_MAX_DEPTH`, 256), as in JavaScript: the
  evaluator refuses a received message nested deeper, with `TypeError: Deserialization exceeded
  maximum allowed message depth of N.`, and the session aborts.
- **The JSON parser's.** `FramedTransport` and `UdsTransport` always parse with serde_json's
  recursion limit, 128 levels (each escaped array is two). The session's string-level path
  (`TransportMessage::Text`: WebSocket, HTTP batch, custom string transports) and `deserialize()`
  parse at any depth with `stack-growth`, and up to `MAX_JSON_DEPTH` (128) without it. A deeper
  message fails to parse (`recursion limit exceeded`) and aborts the session.

**With `stack-growth`** (the default), parsing and each level of evaluation run under
`stacker::maybe_grow`: when less than 128 KiB of stack remains, the next level runs on a freshly
mapped 2 MiB segment (`mmap`, `mprotect`, then `munmap`); `deserialize()` maps an 8 MiB one
whenever less than 4 MiB remains. Any message up to `max_depth` is handled on any thread, at the price of those syscalls
on a stack that is small or already deep. On a 128 KiB stack, every message maps a segment.

**Without `stack-growth`** (`default-features = false, features = ["std", ...]`, and always without
std) neither `stacker` nor `serde_stacker` is linked: nothing maps a stack, and nothing recurses
past the JSON bound. A deeper message is refused with an error, never a stack overflow, *provided
the stack holds the deepest admissible message*. Measured on x86-64, optimized:

| | stack |
|---|---|
| a session's own work, a shallow call | about 20 KiB |
| parsing a message `MAX_JSON_DEPTH` deep, before `max_depth` refuses it | under 80 KiB in all |
| each level of evaluation, up to `max_depth` | about 2 KiB |

The conversion from parsed JSON is iterative and a received message is moved, not cloned, into the
evaluator, so they take no stack per level. So the stack bounds `max_depth`: 32 needs about 85 KiB
in all; the default 256 is bounded by the parser at about 128 levels, some 300 KiB. Unoptimized
builds take many times as much per level (some 30 KiB per level of evaluation: at the default
`max_depth`, more than a 2 MiB thread stack).

### An embedder on a small fixed stack

An embedder whose handlers run on a small fixed stack and must not make syscalls while handling a
message (capnix in exobox's network hooks: 128 KiB coroutine stacks) turns stack growth off and
sizes `max_depth` for its stack:

```toml
capnweb-rs = { default-features = false, features = ["std", "tokio"] }  # no "stack-growth"
```

```rust
let options = capnweb::RpcSessionOptions {
    limits: capnweb::RpcLimits { max_depth: 32, ..capnweb::DEFAULT_LIMITS },  // about 85 KiB
    ..Default::default()
};
let session = capnweb::RpcSession::new(transport, main, options)?;
```

Every message is then handled on the caller's stack: a call nested within `max_depth` is answered,
a deeper one (or one nested past the JSON bound) aborts the session with an error. Values the
embedder sends are bounded by the sender's fixed limit (`DEFAULT_MAX_DEPTH`, as in JavaScript;
about 3.5 KiB per level optimized), so keep its own outgoing values shallow; a received value
relayed onward is within `max_depth`. `deserialize()` evaluates with the default limits, so on a
small stack use it only on input known to be shallow. Cargo unifies features: a crate elsewhere in
the build that enables `stack-growth` (or capnweb's default features) turns it back on;
`cargo tree -e features -i capnweb-rs` shows who.

## Tests

```sh
cargo test --all-features                       # the suite, on tokio, plus local_session
cargo test --features local-runtime --test local_session                          # std build
cargo test --release --no-default-features --features std,local-runtime --test local_session  # std, no stack growth, 128 KiB stacks
cargo test --no-default-features --features local-runtime --test local_session    # no_std build
cargo test --no-default-features --features tokio,websocket,local-runtime         # the suite without stack growth
./check-no-std.sh                               # wasm32v1-none build, a no_std staticlib run from C, no stacker without stack-growth
```

- `tests/local_session.rs` runs full sessions on `LocalRuntime` over `FramedTransport` on an
  `io::duplex`, with no tokio: calls, errors (named ones keep their name), concurrent calls,
  virtual-time timers, pipelining checked on the wire, returned capabilities and their release,
  callbacks, `map()` replay, closures replayed by the receiver, streams in each direction (returned
  and passed, readable and writable), flow control bounding a slow reader's sender, and 24
  downloads, 24 uploads, 24 writable sinks and 24 calls at once; and message depth: a server with
  a small `max_depth`, fed raw frames over each kind of transport, answers a call within it and
  refuses, with an error, one past it and one past the JSON bound. A test that stalls fails at
  once; one that spins fails after a virtual minute. Without std the harness serializes its tests
  (one executor thread). Without `stack-growth` each test runs on a thread with a 128 KiB stack
  (1 MiB unoptimized), so one that needs more overflows it.
- `no-std-check/` is a `#![no_std]` staticlib with a bump allocator and a panic handler;
  `capnweb_selftest()` runs a call, a pipelined call, a named error, a closure called back and a
  256 KiB stream. `check-no-std.sh` links it into `main.c` and runs it. It is outside the workspace:
  its panic handler can't be built with the test harness.
