//! The runtime's half of the kernel's socket impersonation (arch/lkl/kernel/tsi.c): the `net_*`
//! host ops, the guest's end of a connection as an async byte stream ([`GuestSocket`]), the copy
//! between it and a hook's stream ([`splice`]), the resolver, and readiness for passed fds
//! (`hostfd_poll`). The hooks themselves ([`Hooks`]) are exobox's, type-erased here.
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
use core::cell::RefCell;
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

// ---- what the hooks give back ----

/// A hook's byte stream, both directions (exobox adapts futures-io's and tokio's traits).
pub trait ByteStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>>;
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>>;
    /// Flush, then shut down writing: the peer reads EOF.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>>;
}

pub type BoxStream = Pin<Box<dyn ByteStream>>;
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T>>>;

/// A `listen` hook's inbound connections: each its peer and its stream; `None` when it stops.
pub trait Incoming {
    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<(SocketAddrV4, BoxStream)>>;
}

pub type BoxIncoming = Pin<Box<dyn Incoming>>;

/// What a `connect` hook gives for a connection it accepts.
pub enum Conn {
    /// A stream: [`splice`]d with the guest's socket.
    Stream(BoxStream),
    /// The provider drives the guest's socket itself: called once it is connected.
    Drive(Box<dyn FnOnce(GuestSocket)>),
}

/// The `connect` hook: `(cx, pid, addr)` to a connection or the connect's errno.
pub type ConnectFn = Box<dyn FnMut(Cx, i32, SocketAddrV4) -> BoxFuture<Result<Conn, Errno>>>;
/// The `listen` hook: `(cx, pid, addr)` to the inbound connections, or an errno (the listen stays
/// the guest's).
pub type ListenFn = Box<dyn FnMut(Cx, i32, SocketAddrV4) -> BoxFuture<Result<BoxIncoming, Errno>>>;
/// The `resolve` hook: `(cx, pid, name)` to its IPv4 addresses or the resolver's answer code.
pub type ResolveFn = Box<dyn FnMut(Cx, i32, String) -> BoxFuture<Result<Vec<Ipv4Addr>, Rcode>>>;

/// The hooks, type-erased: exobox's `Hooks` with its errors already errnos (connect) and
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

static R: Registry = Registry { hooks: RefCell::new(Hooks { connect: None, listen: None, resolve: None }), objs: RefCell::new(Vec::new()) };

/// Install the hooks (exobox's `Sandbox::run`, before the program starts).
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
    register(sock);
    executor::spawn(connect_task(sock, pid, addr));
    0
}

async fn connect_task(sock: usize, pid: i32, addr: SocketAddrV4) {
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
    match r {
        // The program closed its socket meanwhile: the attempt is dropped, the reference given back.
        None => {
            done(sock, neg(Errno::CANCELED));
        }
        Some(Err(e)) => {
            done(sock, neg(e));
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
    register(sock);
    executor::spawn(listen_task(sock, pid, addr));
    0
}

async fn listen_task(sock: usize, pid: i32, addr: SocketAddrV4) {
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
        let Some((peer, stream)) = next else { break };
        let a = sockaddr(peer);
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
    let msg = unsafe { core::slice::from_raw_parts(buf as *const u8, size as usize) }.to_vec();
    executor::spawn(resolve_task(sock as usize, pid, to, msg));
    0
}

async fn resolve_task(sock: usize, pid: i32, ns: SocketAddrV4, msg: Vec<u8>) {
    let reply = match dns::parse(&msg) {
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

/// An end's readiness changed, or a lent sock was closed: whoever waits on it looks again.
///
/// # Safety
/// A host op: called by the kernel, with its pointers valid for the call.
pub unsafe extern "C" fn net_ready(obj: *mut c_void) {
    let wake = with_obj(obj as usize, |o| {
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
/// (`executor::watch_hostfd`), and the kernel told when it may be ready.
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
