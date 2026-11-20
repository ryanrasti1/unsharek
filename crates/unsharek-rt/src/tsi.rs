//! The runtime's half of the kernel's socket impersonation (arch/lkl/kernel/tsi.c): the `net_*`
//! host ops, the guest's end of a connection as an async byte stream ([`GuestSocket`]), the copy
//! between it and a hook's stream ([`splice`]), the resolver, and readiness for passed fds
//! (`hostfd_poll`). The hooks themselves ([`Hooks`]) are unsharek's, type-erased here.
//!
//! **What the kernel does and what is here.** A program's connect to a non-loopback address
//! reaches [`net_connect`] (a host op: the CPU held, it must only note it and return). A task on
//! the executor calls the `connect` hook; on success `lkl_net_done(sock, 0)` gives the
//! connection's host end, a [`GuestSocket`], and [`splice`] copies both ways between it and the
//! hook's stream. A listen offered by the kernel ([`net_listen`]) runs the `listen` hook, whose
//! inbound streams become `lkl_net_accept` ends; a datagram to port 53 ([`net_sendto`]) is a
//! resolver query (`dns`), answered with `lkl_net_reply` from the `resolve` hook's addresses.
//! Every other datagram is ENETUNREACH (no UDP yet).
//!
//! **Who closes what** ([`splice`], what capnix's `net` cap relies on): each direction is a byte
//! stream on its own.
//! - The program's `shutdown(SHUT_WR)`, or its `close()`: the hook's stream is shut down for
//!   writing (`poll_shutdown`: a half-close, after everything the program wrote). After a
//!   `close()` nothing more is read from it either: the stream is dropped once shut down.
//! - The program's close with data it hadn't read (TCP's RST): the stream is dropped without a
//!   shutdown (an abort).
//! - The stream's EOF (a read of 0): the program reads EOF (`shutdown(SHUT_WR)` of the host end);
//!   it may still write, until its own shutdown or close ends the other direction.
//! - The stream's error (read, write or shutdown): the program's socket is reset (its next call
//!   fails with ECONNRESET) and the stream dropped.
//! - When both directions are done, the stream is dropped and the host end closed.
//!
//! **Modes.** Coroutine mode only so far. Threaded mode: the calls into the kernel ([`kernel`])
//! must hold the CPU token, and the registry's cells a lock. Fork mode: the hooks live in init's
//! process; another process's host ops would forward to it.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::cell::{Cell, RefCell};
use core::ffi::{c_int, c_uint, c_ulong, c_void};
use core::future::{Future, poll_fn};
use core::net::{Ipv4Addr, SocketAddrV4};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use lkl_sys as l;
use rustix::io::Errno;

use crate::dns::{self, Rcode};
use crate::executor::{self, Cx};



/// A call into the kernel from the executor (`lkl_net_*`, `lkl_hostfd_ready`): the CPU is taken
/// inside. The seam for threaded mode, where the calling host thread must first hold the CPU
/// token.
pub fn kernel<R>(f: impl FnOnce() -> R) -> R {
    f()
}

/// A syscall the hooks' own code made on the executor (a library's: capnweb-rs's stacker reads
/// /proc/self/maps for its stack's bounds), as the kernel's tsi task (`lkl_net_syscall`): no
/// thread of the program's. Made as the executor coroutine's own guest task, the first such call
/// made the executor a thread of init's process, which nothing ever ended (it waits for its tasks,
/// not in the kernel): after the program's exit_group init's process lived on, its files open,
/// and the sandbox never ended (capnix's `the_default_net_refuses_without_caps`;
/// `net_exit_code_provider_syscall`). Exits and the host-task calls are EINVAL.
pub fn host_syscall(nr: core::ffi::c_long, a: [usize; 6]) -> isize {
    let mut p = a.map(|v| v as core::ffi::c_long);
    // SAFETY: the kernel runs; the arguments are the hooks' code's (LKL reads its pointers).
    kernel(|| unsafe { l::lkl_net_syscall(nr, p.as_mut_ptr()) as isize })
}

/// How long the sandbox's end waits at most for the network to drain ([`drain`]).
pub const DRAIN_NS: u64 = 1_000_000_000;

/// At the sandbox's end (init's exit, its files closed): the executor runs until the network has
/// drained, then the caller ends the sandbox. Drained: every connection's end and every lent sock
/// gone (each copy has handed the program's last bytes and its EOF to the hook's stream, or its
/// reset), and the executor settled (no task ready, none waiting to write to a held fd: the
/// provider's session has written its last frames). Bounded by [`DRAIN_NS`]: a stream that never
/// takes its bytes doesn't keep the sandbox alive; nor do tasks that only wait to read (a
/// session's reader) or sleep. As Linux sends a socket's buffered data after a close, the
/// program's exit included: bytes written just before an exit were lost when the sandbox ended at
/// once (capnix's `bytes_written_just_before_exit_arrive`; `net_exit_flush_*`).
pub fn drain() {
    if !executor::installed() || executor::on_executor() {
        return;
    }
    let deadline = executor::now().saturating_add(DRAIN_NS);
    while !(R.objs.try_borrow().is_ok_and(|o| o.is_empty()) && executor::settled()) && executor::now() < deadline {
        executor::wait_parked(deadline);
    }
}

// ---- what the hooks give back ----

/// A hook's byte stream, both directions (unsharek adapts futures-io's and tokio's traits).
pub trait ByteStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>>;
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>>;
    /// Flush, then shut down writing: the peer reads EOF.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>>;
}

pub type BoxStream = Pin<Box<dyn ByteStream>>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T>>>;

/// A `listen` hook's inbound connections: each its peer and its connection; `None` when it stops.
pub trait Incoming {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<(SocketAddrV4, Conn)>>;
}

/// A connection a host fd backs ([`Conn::Fd`]): the guest's socket reads and writes the fd itself
/// (the kernel's `lkl_net_done_fd`), with nothing copied here. What the sandbox can't do on the fd
/// is this object's: the program's `shutdown`, and, when it drops, the close (the fd's too).
pub trait FdConn {
    /// The program's `shutdown(how)`. Called inside a host op: it must not block (spawn a task).
    fn shutdown(&mut self, how: i32);
}

pub type BoxIncoming = Pin<Box<dyn Incoming>>;

/// What a `connect` hook gives for a connection it accepts.
pub enum Conn {
    /// A stream: [`splice`]d with the guest's socket.
    Stream(BoxStream),
    /// The provider drives the guest's socket itself: called once it is connected.
    Drive(Box<dyn FnOnce(GuestSocket)>),
    /// A host fd, the guest's socket's own: nothing copied ([`FdConn`]).
    Fd(i32, Box<dyn FdConn>),
}

/// The `connect` hook: `(cx, pid, addr)` to a connection or the connect's errno.
pub type ConnectFn = Box<dyn FnMut(Cx, i32, SocketAddrV4) -> BoxFuture<Result<Conn, Errno>>>;
/// The `listen` hook: `(cx, pid, addr)` to the inbound connections, or an errno (the listen stays
/// the guest's).
pub type ListenFn = Box<dyn FnMut(Cx, i32, SocketAddrV4) -> BoxFuture<Result<BoxIncoming, Errno>>>;
/// The `resolve` hook: `(cx, pid, name)` to its IPv4 addresses or the resolver's answer code.
pub type ResolveFn = Box<dyn FnMut(Cx, i32, String) -> BoxFuture<Result<Vec<Ipv4Addr>, Rcode>>>;

/// The hooks, type-erased: unsharek's `Hooks` with its errors already errnos (connect) and
/// response codes (resolve).
#[derive(Default)]
pub struct Hooks {
    pub connect: Option<ConnectFn>,
    pub listen: Option<ListenFn>,
    pub resolve: Option<ResolveFn>,
}

struct Registry {
    hooks: RefCell<Hooks>,
    /// Kernel objects the host waits on: ends (data, room, the guest's shutdown) and lent socks
    /// (the program's close). `net_ready(obj)` wakes them.
    objs: RefCell<Vec<Obj>>,
    /// The host-fd-backed connections the guest's sockets hold ([`Conn::Fd`]), by fd.
    fds: RefCell<Vec<(i32, Box<dyn FdConn>)>>,
}

struct Obj {
    ptr: usize,
    read: Option<Waker>,
    write: Option<Waker>,
    /// A lent sock the program closed.
    closed: bool,
}

// SAFETY: one host thread (see the module comment).
unsafe impl Sync for Registry {}

static R: Registry = Registry {
    hooks: RefCell::new(Hooks { connect: None, listen: None, resolve: None }),
    objs: RefCell::new(Vec::new()),
    fds: RefCell::new(Vec::new()),
};

/// Install the hooks (unsharek's `Guest::lockdown`, before the program starts).
pub fn set_hooks(h: Hooks) {
    *R.hooks.borrow_mut() = h;
}

fn register(ptr: usize) {
    R.objs.borrow_mut().push(Obj { ptr, read: None, write: None, closed: false });
}

fn unregister(ptr: usize) {
    R.objs.borrow_mut().retain(|o| o.ptr != ptr);
}

fn with_obj<T>(ptr: usize, f: impl FnOnce(&mut Obj) -> T) -> Option<T> {
    R.objs.borrow_mut().iter_mut().find(|o| o.ptr == ptr).map(f)
}

// ---- the host ops ----

/// Fork mode, in a fork's child process: the hooks, the registry and the executor are init's
/// process's (this one has a stale copy of them, and running it would touch the shared scheduler
/// from the wrong process). So a child's host ops are forwarded ([`FWD`]): queued in shared
/// memory, init's executor woken, and served there as init's own. The kernel objects they name
/// (socks, ends) are the shared kernel's, the same in every process; what can't cross is a host fd
/// (each process has its own table), so a connection a forwarded op makes is served by init's
/// process, its bytes copied between the guest's end and the host fd there ([`FdStream`]): no
/// filter change (the received fds stay init's, on its control socket).
fn elsewhere() -> bool {
    crate::par::forked()
}

/// What a forked process forwards to init's executor: its host op, with the arguments as the
/// kernel gave them (socks and ends are the shared kernel's, valid in every process).
#[derive(Clone, Copy)]
enum Fwd {
    None,
    Connect { sock: usize, pid: i32, addr: SocketAddrV4 },
    Listen { sock: usize, pid: i32, addr: SocketAddrV4 },
    /// A resolver query: its bytes in [`FwdQueue::msgs`]`[slot]`.
    Resolve { sock: usize, pid: i32, ns: SocketAddrV4, slot: u8, len: u16 },
    Ready { obj: usize },
    FdShutdown { fd: i32, how: i32 },
    FdClose { fd: i32 },
}

const FWD_LEN: usize = 256;
const FWD_MSGS: usize = 8;
const FWD_MSG: usize = 512;

/// The forwarded host ops, in order (a sock's connect before its readiness): a ring, and the
/// queries' bytes. Shared (fork mode's processes), touched with the CPU token held. Full, a
/// connect, listen or lookup fails at once (ENOBUFS); a readiness is kept once per object, and if
/// even that overflows every waiter is woken (`all`).
#[unsafe(link_section = "unsharek_shared")]
static FWD: FwdQueue = FwdQueue {
    ring: [const { Cell::new(Fwd::None) }; FWD_LEN],
    head: Cell::new(0),
    len: Cell::new(0),
    all: Cell::new(false),
    msgs: [const { Cell::new([0; FWD_MSG]) }; FWD_MSGS],
    msg_used: [const { Cell::new(false) }; FWD_MSGS],
};

struct FwdQueue {
    ring: [Cell<Fwd>; FWD_LEN],
    head: Cell<usize>,
    len: Cell<usize>,
    all: Cell<bool>,
    msgs: [Cell<[u8; FWD_MSG]>; FWD_MSGS],
    msg_used: [Cell<bool>; FWD_MSGS],
}

// SAFETY: touched with the CPU token held (one host thread at a time, in any process).
unsafe impl Sync for FwdQueue {}

impl FwdQueue {
    fn push(&self, f: Fwd) -> bool {
        if self.len.get() == FWD_LEN {
            return false;
        }
        self.ring[(self.head.get() + self.len.get()) % FWD_LEN].set(f);
        self.len.set(self.len.get() + 1);
        true
    }
    fn pop(&self) -> Option<Fwd> {
        if self.len.get() == 0 {
            return None;
        }
        let f = self.ring[self.head.get()].replace(Fwd::None);
        self.head.set((self.head.get() + 1) % FWD_LEN);
        self.len.set(self.len.get() - 1);
        Some(f)
    }
    fn has_ready(&self, obj: usize) -> bool {
        (0..self.len.get()).any(|i| matches!(self.ring[(self.head.get() + i) % FWD_LEN].get(), Fwd::Ready { obj: o } if o == obj))
    }
}

/// From a forked process: `f` queued for init's executor, which is woken. False if full.
fn forward(f: Fwd) -> bool {
    let ok = FWD.push(f);
    executor::wake_from_fork();
    ok
}

/// Whether forked processes forwarded anything not yet taken (init's executor, before it blocks).
pub fn forwarded_pending() -> bool {
    FWD.len.get() > 0 || FWD.all.get()
}

/// init's executor, each turn: what forked processes forwarded, served as init's own host ops.
pub fn take_forwarded() {
    if FWD.all.replace(false) {
        let wake: Vec<Waker> = R.objs.borrow_mut().iter_mut().flat_map(|o| [o.read.take(), o.write.take()]).flatten().collect();
        for w in wake {
            w.wake();
        }
    }
    while let Some(f) = FWD.pop() {
        match f {
            Fwd::None => {}
            Fwd::Connect { sock, pid, addr } => {
                register(sock);
                executor::spawn(connect_task(sock, pid, addr, true));
            }
            Fwd::Listen { sock, pid, addr } => {
                register(sock);
                executor::spawn(listen_task(sock, pid, addr, true));
            }
            Fwd::Resolve { sock, pid, ns, slot, len } => {
                let msg = FWD.msgs[slot as usize].get()[..len as usize].to_vec();
                FWD.msg_used[slot as usize].set(false);
                executor::spawn(resolve_task(sock, pid, ns, msg));
            }
            Fwd::Ready { obj } => ready(obj),
            // SAFETY: as the host ops themselves.
            Fwd::FdShutdown { fd, how } => unsafe { net_fd_shutdown(fd as core::ffi::c_long, how) },
            // SAFETY: as the host ops themselves.
            Fwd::FdClose { fd } => unsafe { net_fd_close(fd as core::ffi::c_long) },
        }
    }
}

/// A host fd's connection served by init's process for a forked process's socket (which can't use
/// init's fd): a byte stream over the fd, [`splice`]d with the guest's end. The [`FdConn`] is the
/// connection's shutdown and close.
struct FdStream {
    fd: i32,
    conn: Option<Box<dyn FdConn>>,
}

impl ByteStream for FdStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        loop {
            match crate::trap::read(self.fd as u32, buf) {
                Err(Errno::AGAIN) => {
                    if executor::poll_fd(self.fd, executor::POLLIN, cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                r => return Poll::Ready(r),
            }
        }
    }
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        loop {
            match crate::trap::write(self.fd as u32, buf) {
                Err(Errno::AGAIN) => {
                    if executor::poll_fd(self.fd, executor::POLLOUT, cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                r => return Poll::Ready(r),
            }
        }
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<(), Errno>> {
        if let Some(c) = self.conn.as_mut() {
            c.shutdown(1); // SHUT_WR
        }
        Poll::Ready(Ok(()))
    }
}

/// A connection's stream for a forked process's socket: an fd connection served here.
fn served(conn: Conn) -> Conn {
    match conn {
        Conn::Fd(fd, c) => Conn::Stream(Box::pin(FdStream { fd, conn: Some(c) })),
        c => c,
    }
}

fn addr_of(addr: *const l::lkl_sockaddr, len: c_int) -> Option<SocketAddrV4> {
    if addr.is_null() || len < 16 {
        return None;
    }
    // SAFETY: the kernel's sockaddr_in, len bytes: family, port and address in network order.
    let b = unsafe { core::slice::from_raw_parts(addr as *const u8, 8) };
    Some(SocketAddrV4::new(Ipv4Addr::new(b[4], b[5], b[6], b[7]), u16::from_be_bytes([b[2], b[3]])))
}

/// A `sockaddr_in` for the kernel.
fn sockaddr(a: SocketAddrV4) -> [u8; 16] {
    let mut s = [0u8; 16];
    s[..2].copy_from_slice(&2u16.to_ne_bytes()); // AF_INET
    s[2..4].copy_from_slice(&a.port().to_be_bytes());
    s[4..8].copy_from_slice(&a.ip().octets());
    s
}

fn neg(e: Errno) -> c_int {
    -e.raw_os_error()
}

/// `lkl_net_done`: the reference the host held, given back.
fn done(sock: usize, err: c_int) -> *mut c_void {
    // SAFETY: a sock the kernel lent us, given back once.
    kernel(|| unsafe { l::lkl_net_done(sock as *mut c_void, err) })
}

/// The program's connect to a non-loopback address: the `connect` hook, on a task.
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn net_connect(sock: *mut c_void, pid: c_int, addr: *const l::lkl_sockaddr, len: c_int) -> c_int {
    let Some(addr) = addr_of(addr, len) else { return neg(Errno::INVAL) };
    if R.hooks.borrow().connect.is_none() {
        return neg(Errno::NETUNREACH);
    }
    let sock = sock as usize;
    if elsewhere() {
        return if forward(Fwd::Connect { sock, pid, addr }) { 0 } else { neg(Errno::NOBUFS) };
    }
    register(sock);
    executor::spawn(connect_task(sock, pid, addr, false));
    0
}

/// `forwarded`: a forked process's connect, whose socket can't use a host fd of init's: an fd
/// connection is served here instead ([`served`]).
async fn connect_task(sock: usize, pid: i32, addr: SocketAddrV4, forwarded: bool) {
    // The hook is called on the executor, not in the host op.
    let fut = {
        let mut h = R.hooks.borrow_mut();
        match h.connect.as_mut() {
            Some(f) => f(Cx, pid, addr),
            None => return,
        }
    };
    let r = until_closed(sock, fut).await;
    unregister(sock);
    let r = if forwarded { r.map(|r| r.map(served)) } else { r };
    match r {
        // The program closed its socket meanwhile: the attempt is dropped, the reference given back.
        None => {
            done(sock, neg(Errno::CANCELED));
        }
        Some(Err(e)) => {
            done(sock, neg(e));
        }
        Some(Ok(Conn::Fd(fd, c))) => {
            // SAFETY: a sock the kernel lent us, given back once (with the fd, or not taken).
            if kernel(|| unsafe { l::lkl_net_done_fd(sock as *mut c_void, fd as core::ffi::c_long) }) == 0 {
                R.fds.borrow_mut().push((fd, c));
            }
            // Not taken (the program closed its socket): `c` drops, the connection with it.
        }
        Some(Ok(conn)) => {
            let end = done(sock, 0);
            if end.is_null() {
                // Closed after all (or no memory): the stream is dropped, an abort.
                return;
            }
            let g = GuestSocket::new(end);
            match conn {
                Conn::Stream(s) => splice(g, s).await,
                Conn::Drive(f) => f(g),
                Conn::Fd(..) => unreachable!("an fd connection is given above"),
            }
        }
    }
}

/// `fut`, unless the program closes `sock` first (None).
async fn until_closed<T>(sock: usize, mut fut: BoxFuture<T>) -> Option<T> {
    poll_fn(move |cx| {
        if let Poll::Ready(v) = fut.as_mut().poll(cx) {
            return Poll::Ready(Some(v));
        }
        if closed(sock, cx) { Poll::Ready(None) } else { Poll::Pending }
    })
    .await
}

/// Whether the program closed lent `sock`; if not, `cx` is woken when it does.
fn closed(sock: usize, cx: &mut Context<'_>) -> bool {
    with_obj(sock, |o| {
        if !o.closed {
            o.read = Some(cx.waker().clone());
        }
        o.closed
    })
    .unwrap_or(true)
}

/// The program's listen, offered: the `listen` hook, on a task. Without it the listen stays the
/// guest's alone (nonzero).
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn net_listen(sock: *mut c_void, pid: c_int, addr: *const l::lkl_sockaddr, len: c_int) -> c_int {
    let Some(addr) = addr_of(addr, len) else { return neg(Errno::INVAL) };
    if R.hooks.borrow().listen.is_none() {
        return neg(Errno::OPNOTSUPP);
    }
    let sock = sock as usize;
    if elsewhere() {
        return if forward(Fwd::Listen { sock, pid, addr }) { 0 } else { neg(Errno::OPNOTSUPP) };
    }
    register(sock);
    executor::spawn(listen_task(sock, pid, addr, false));
    0
}

/// `forwarded`: a forked process's listen: its connections, fd ones too, served here ([`served`]).
async fn listen_task(sock: usize, pid: i32, addr: SocketAddrV4, forwarded: bool) {
    let fut = {
        let mut h = R.hooks.borrow_mut();
        match h.listen.as_mut() {
            Some(f) => f(Cx, pid, addr),
            None => return,
        }
    };
    // A hook that refuses: the listen stays the guest's.
    let mut incoming = match until_closed(sock, fut).await {
        Some(Ok(i)) => i,
        _ => {
            unregister(sock);
            done(sock, 0);
            return;
        }
    };
    loop {
        let next = poll_fn(|cx| {
            if let Poll::Ready(v) = incoming.as_mut().poll_next(cx) {
                return Poll::Ready(v);
            }
            if closed(sock, cx) { Poll::Ready(None) } else { Poll::Pending }
        })
        .await;
        let Some((peer, conn)) = next else { break };
        let conn = if forwarded { served(conn) } else { conn };
        let a = sockaddr(peer);
        let stream = match conn {
            Conn::Fd(fd, c) => {
                // SAFETY: the lent sock; the address is a sockaddr_in.
                let r = kernel(|| unsafe {
                    l::lkl_net_accept_fd(sock as *mut c_void, a.as_ptr() as *const l::lkl_sockaddr, 16, fd as core::ffi::c_long)
                });
                // Refused (the backlog is full, or it closed): `c` drops, the connection with it.
                if r == 0 {
                    R.fds.borrow_mut().push((fd, c));
                }
                continue;
            }
            Conn::Stream(s) => s,
            // A driver of its own isn't a listen's: dropped.
            Conn::Drive(_) => continue,
        };
        // SAFETY: the lent sock; the address is a sockaddr_in.
        let end = kernel(|| unsafe { l::lkl_net_accept(sock as *mut c_void, a.as_ptr() as *const l::lkl_sockaddr, 16) });
        if end.is_null() {
            // Refused (the backlog is full, or it closed): this one is dropped.
            continue;
        }
        executor::spawn(splice(GuestSocket::new(end), stream));
    }
    unregister(sock);
    done(sock, 0);
}

/// A datagram from the program to a non-loopback address: a resolver query if to port 53 and a
/// `resolve` hook is set; anything else is ENETUNREACH.
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn net_sendto(
    sock: *mut c_void,
    pid: c_int,
    addr: *const l::lkl_sockaddr,
    len: c_int,
    buf: *const c_void,
    size: c_ulong,
) -> c_int {
    let Some(to) = addr_of(addr, len) else { return neg(Errno::INVAL) };
    if to.port() != 53 || R.hooks.borrow().resolve.is_none() {
        return neg(Errno::NETUNREACH);
    }
    // SAFETY: the kernel's copy of the datagram, size bytes.
    let bytes = unsafe { core::slice::from_raw_parts(buf as *const u8, size as usize) };
    if elsewhere() {
        // Its bytes into a shared slot, for init's executor; none free or too long: no answer
        // (the resolver asks again, as for a lost datagram).
        let Some(slot) = FWD.msg_used.iter().position(|u| !u.get()) else { return neg(Errno::NOBUFS) };
        if bytes.len() > FWD_MSG {
            return neg(Errno::MSGSIZE);
        }
        let mut m = [0u8; FWD_MSG];
        m[..bytes.len()].copy_from_slice(bytes);
        FWD.msgs[slot].set(m);
        FWD.msg_used[slot].set(true);
        let f = Fwd::Resolve { sock: sock as usize, pid, ns: to, slot: slot as u8, len: bytes.len() as u16 };
        if !forward(f) {
            FWD.msg_used[slot].set(false);
            return neg(Errno::NOBUFS);
        }
        return 0;
    }
    let msg = bytes.to_vec();
    executor::spawn(resolve_task(sock as usize, pid, to, msg));
    0
}

async fn resolve_task(sock: usize, pid: i32, ns: SocketAddrV4, msg: Vec<u8>) {
    let reply = match dns::parse(&msg) {
        // Only an A query asks the hook (its answer is IPv4 addresses): another (glibc's AAAA
        // beside each A) is no data at once, not a second call of the hook for the same name.
        Ok(q) if q.qtype != dns::TYPE_A => Some(dns::answer(&q, Rcode::NoError, &[])),
        Ok(q) => {
            let fut = {
                let mut h = R.hooks.borrow_mut();
                h.resolve.as_mut().map(|f| f(Cx, pid, q.name.clone()))
            };
            let (rc, addrs) = match fut {
                Some(f) => match f.await {
                    Ok(a) => (Rcode::NoError, a),
                    Err(rc) => (rc, Vec::new()),
                },
                None => (Rcode::Refused, Vec::new()),
            };
            Some(dns::answer(&q, rc, &addrs))
        }
        Err(Some((id, rc))) => Some(dns::failure(id, rc)),
        Err(None) => None,
    };
    if let Some(r) = reply {
        let from = sockaddr(ns);
        // SAFETY: the lent sock; the answer as the nameserver's.
        kernel(|| unsafe {
            l::lkl_net_reply(sock as *mut c_void, from.as_ptr() as *const l::lkl_sockaddr, 16, r.as_ptr() as *const c_void, r.len() as c_ulong)
        });
    }
    done(sock, 0);
}

/// The program's `shutdown` of a host-fd-backed connection: its [`FdConn`]'s.
///
/// # Safety
/// A host op: called by the kernel.
pub unsafe extern "C" fn net_fd_shutdown(fd: core::ffi::c_long, how: c_int) {
    // A socket init made before the fork, inherited: its connection is init's.
    if elsewhere() {
        forward(Fwd::FdShutdown { fd: fd as i32, how });
        return;
    }
    if let Some((_, c)) = R.fds.borrow_mut().iter_mut().find(|(f, _)| *f as core::ffi::c_long == fd) {
        c.shutdown(how);
    }
}

/// The program's last reference to a host-fd-backed connection is gone: its [`FdConn`] dropped
/// (which closes the connection and the fd), on the executor (a drop may call the provider).
///
/// # Safety
/// A host op: called by the kernel.
pub unsafe extern "C" fn net_fd_close(fd: core::ffi::c_long) {
    // A socket init made before the fork, inherited, last closed here: the connection is init's
    // to end; this process's copy of the fd (the fork's) closed (a received fd: the close row's).
    if elsewhere() {
        forward(Fwd::FdClose { fd: fd as i32 });
        let _ = crate::trap::close(fd as u32);
        return;
    }
    let c = {
        let mut fds = R.fds.borrow_mut();
        fds.iter().position(|(f, _)| *f as core::ffi::c_long == fd).map(|i| fds.remove(i))
    };
    if let Some((_, c)) = c {
        executor::spawn(async move { drop(c) });
    }
}

/// An end's readiness changed, or a lent sock was closed: whoever waits on it looks again.
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn net_ready(obj: *mut c_void) {
    let obj = obj as usize;
    if elsewhere() {
        // Its waiters are init's (every lent sock and end is init's executor's): forwarded,
        // once per object; if even that overflows, init wakes every waiter.
        if !FWD.has_ready(obj) && !forward(Fwd::Ready { obj }) {
            FWD.all.set(true);
        }
        return;
    }
    ready(obj);
}

fn ready(obj: usize) {
    let wake = with_obj(obj, |o| {
        // For a lent sock this is the program's close (`closed` is only read for socks: an
        // end's state is what its calls return).
        o.closed = true;
        (o.read.take(), o.write.take())
    });
    if let Some((r, w)) = wake {
        for w in [r, w].into_iter().flatten() {
            w.wake();
        }
    }
}

/// A guest file of a passed host fd, polled: what the host fd has ready now; the rest is watched
/// (`executor::watch_hostfd`), and the kernel told when it may be ready. In a forked process too:
/// the watch is shared, init's process polls it.
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn hostfd_poll(fd: c_int, events: c_uint) -> c_uint {
    let events = events as i16 & (executor::POLLIN | executor::POLLOUT);
    let ready = executor::fd_ready(fd, events);
    if ready & events != events && executor::installed() {
        executor::watch_hostfd(fd, events & !ready);
    }
    ready as u16 as c_uint
}

// ---- the guest's socket ----

/// The host's end of a connection with the program's socket: what the program writes is read
/// here, what is written here the program reads. Nonblocking calls into the kernel
/// (`lkl_net_recv`/`lkl_net_send`), woken by the kernel's `net_ready` when they can get further.
/// Dropped, the end is closed (the program reads EOF); [`GuestSocket::reset`] closes it with a
/// reset (ECONNRESET).
pub struct GuestSocket {
    end: usize,
}

impl GuestSocket {
    fn new(end: *mut c_void) -> GuestSocket {
        register(end as usize);
        GuestSocket { end: end as usize }
    }

    fn call(&self, f: impl FnOnce(*mut c_void) -> core::ffi::c_long) -> Result<usize, Errno> {
        let r = kernel(|| f(self.end as *mut c_void));
        if r < 0 { Err(Errno::from_raw_os_error(-r as i32)) } else { Ok(r as usize) }
    }

    /// Read what the program wrote: `Ok(0)` once it shut its writing down (it may still read);
    /// `Err(EPIPE)` once it closed its socket; `Err(ECONNRESET)` if it closed with data unread.
    pub fn poll_read(&mut self, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        // The waker first, then the call: a net_ready in between still wakes it.
        with_obj(self.end, |o| o.read = Some(cx.waker().clone()));
        // SAFETY: our end, the buffer borrowed for the call.
        match self.call(|e| unsafe { l::lkl_net_recv(e, buf.as_mut_ptr() as *mut c_void, buf.len() as c_ulong) }) {
            Err(Errno::AGAIN) => Poll::Pending,
            r => Poll::Ready(r),
        }
    }

    /// Write for the program to read: `Err(EPIPE)` once it closed its socket.
    pub fn poll_write(&mut self, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        with_obj(self.end, |o| o.write = Some(cx.waker().clone()));
        // SAFETY: as poll_read.
        match self.call(|e| unsafe { l::lkl_net_send(e, buf.as_ptr() as *const c_void, buf.len() as c_ulong) }) {
            Err(Errno::AGAIN) => Poll::Pending,
            r => Poll::Ready(r),
        }
    }

    /// The program reads EOF (`shutdown(SHUT_WR)` of this end); it may still write.
    pub fn shutdown(&mut self) -> Result<(), Errno> {
        // SAFETY: our end.
        self.call(|e| unsafe { l::lkl_net_shutdown(e, 1) }).map(|_| ())
    }

    /// Close with a reset: the program's next call on its socket fails with ECONNRESET.
    pub fn reset(self) {
        let end = self.end;
        core::mem::forget(self);
        close(end, true);
    }
}

fn close(end: usize, reset: bool) {
    unregister(end);
    // SAFETY: our end, closed once.
    kernel(|| unsafe { l::lkl_net_close(end as *mut c_void, reset as c_int) });
}

impl Drop for GuestSocket {
    fn drop(&mut self) {
        close(self.end, false);
    }
}

impl core::fmt::Debug for GuestSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GuestSocket").field("end", &(self.end as *const ())).finish()
    }
}

// ---- the copy ----

const BUF: usize = 16 << 10;

/// One direction's state.
struct Dir {
    buf: Vec<u8>,
    pos: usize,
    len: usize,
    /// The source ended (EOF): the sink is to be shut down.
    eof: bool,
    done: bool,
}

impl Dir {
    fn new() -> Dir {
        Dir { buf: alloc::vec![0; BUF], pos: 0, len: 0, eof: false, done: false }
    }
}

/// How the copy ended (the stream's fate: see the module comment).
enum End {
    /// Both directions done: the stream dropped, the end closed.
    Done,
    /// The program reset the connection: the stream dropped without a shutdown.
    Abort,
    /// The stream failed: the program's socket reset.
    Reset,
}

/// Copy both ways between the program's socket and a hook's stream until both directions are
/// done; who closes what is in the module comment.
pub async fn splice(mut g: GuestSocket, mut s: BoxStream) {
    let mut up = Dir::new(); // the program → the stream
    let mut down = Dir::new(); // the stream → the program
    // After the program's close the stream is only shut down, never read again.
    let mut guest_closed = false;
    let end = poll_fn(|cx| {
        // The program → the stream.
        while !up.done {
            if up.pos < up.len {
                match s.as_mut().poll_write(cx, &up.buf[up.pos..up.len]) {
                    Poll::Ready(Ok(0)) | Poll::Ready(Err(_)) => return Poll::Ready(End::Reset),
                    Poll::Ready(Ok(n)) => up.pos += n,
                    Poll::Pending => break,
                }
            } else if up.eof {
                match s.as_mut().poll_shutdown(cx) {
                    Poll::Ready(Ok(())) => up.done = true,
                    Poll::Ready(Err(_)) => return Poll::Ready(End::Reset),
                    Poll::Pending => break,
                }
            } else {
                match g.poll_read(cx, &mut up.buf) {
                    Poll::Ready(Ok(0)) => up.eof = true,
                    Poll::Ready(Ok(n)) => (up.pos, up.len) = (0, n),
                    Poll::Ready(Err(Errno::PIPE)) => {
                        up.eof = true;
                        guest_closed = true;
                    }
                    Poll::Ready(Err(_)) => return Poll::Ready(End::Abort),
                    Poll::Pending => break,
                }
            }
        }
        if guest_closed {
            down.done = true;
        }
        // The stream → the program.
        while !down.done {
            if down.pos < down.len {
                match g.poll_write(cx, &down.buf[down.pos..down.len]) {
                    Poll::Ready(Ok(n)) => down.pos += n,
                    // The program closed: what is left is dropped (the other direction ends too).
                    Poll::Ready(Err(Errno::PIPE)) => down.done = true,
                    Poll::Ready(Err(_)) => return Poll::Ready(End::Abort),
                    Poll::Pending => break,
                }
            } else if down.eof {
                let _ = g.shutdown();
                down.done = true;
            } else {
                match s.as_mut().poll_read(cx, &mut down.buf) {
                    Poll::Ready(Ok(0)) => down.eof = true,
                    Poll::Ready(Ok(n)) => (down.pos, down.len) = (0, n),
                    Poll::Ready(Err(_)) => return Poll::Ready(End::Reset),
                    Poll::Pending => break,
                }
            }
        }
        if up.done && down.done { Poll::Ready(End::Done) } else { Poll::Pending }
    })
    .await;
    match end {
        End::Done | End::Abort => {
            drop(s);
            drop(g);
        }
        End::Reset => {
            drop(s);
            g.reset();
        }
    }
}
