//! Pluggable networking: the hooks a sandbox runs for the program's network (README plan item 9).
//!
//! The program's AF_INET sockets are its own for loopback (127.0.0.0/8, 0.0.0.0): connects, binds
//! and listens there are the guest kernel's, as always. Everything else goes to the hooks given
//! to the guest (`unsharek::Guest::on_connect` and the rest):
//!
//! - **`on_connect(cx, pid, addr)`**: a program's `connect` to `addr`. `Ok(stream)`: the program's
//!   connect succeeds, and unsharek copies both ways between its socket and `stream` (who closes
//!   what: below). `Err(e)`: the connect fails with `e`'s errno. A blocking connect waits for the
//!   hook; a nonblocking one is `EINPROGRESS`, then poll/epoll and `SO_ERROR` say how it went. If
//!   the program closes the socket first, the hook's future is dropped.
//! - **`on_listen(cx, pid, addr)`**: a program's `listen` on `addr` (not bound to loopback: the
//!   guest's own clients connect first, locally, whatever the hook says). `Ok(incoming)`: each
//!   `(peer, stream)` it yields is a connection the program accepts, `peer` its getpeername;
//!   until the stream ends or the program closes the listener (the stream is dropped then). An
//!   error leaves the listen the guest's alone (the program's `listen` succeeded already).
//! - **`on_resolve(cx, pid, name)`**: a name lookup. The guest's `/etc/resolv.conf` names
//!   10.0.2.3, the guest's libc asks it over UDP, and unsharek answers from this hook: A records
//!   for its IPv4 addresses (IPv6 ones are left out). Only A queries reach the hook: any other
//!   (glibc's AAAA beside each A) is answered with no data, NOERROR, at once.
//! - **No `on_resolve`, but an `on_connect`**: every name resolves, to an address of its own
//!   that unsharek picks (10.64.0.0/10, one per name, for the sandbox's life), and `on_connect`
//!   learns which name an address came from with [`Cx::name_of`]: name-based policy with no
//!   resolver of the provider's. (With an `on_resolve`, `name_of` names its addresses too.)
//! - **`on_start(cx)`** (`unsharek::Guest::on_start`): a task started at
//!   lockdown, before the program: a provider's session, up before the first connect.
//!
//! With no hook, everything but loopback is unreachable (`ENETUNREACH`, and lookups fail).
//!
//! **Templates.** The hooks are given at build, once for every instance a template forks; each
//! instance holds its own provider's fd under a name
//! (`unsharek::Guest::hold_fd_as`), which a hook finds with [`Cx::held`].
//!
//! **Errors** ([`NetError`]), as the program sees them: for a connect, `Denied` EACCES,
//! `Refused` ECONNREFUSED, `Unreachable` ENETUNREACH, `Timeout` ETIMEDOUT, `NoName` ENETUNREACH,
//! `Unsupported` EAFNOSUPPORT, `Io` EIO. For a lookup (getaddrinfo's codes, through glibc's
//! resolver): `NoName` NXDOMAIN (EAI_NONAME); `Denied` and `Unsupported` NOTAUTH, a failure
//! not to retry (musl's EAI_FAIL; glibc folds it into EAI_NONAME: it would have retried REFUSED
//! and NOTIMP, as a server's trouble, into EAI_AGAIN); the rest SERVFAIL (EAI_AGAIN).
//!
//! **Who closes what**, between the program's socket and a hook's stream (each direction a byte
//! stream of its own):
//! - The program's `shutdown(SHUT_WR)`: the stream is closed for writing (`poll_close`, a
//!   half-close, after everything the program wrote); the program may go on reading.
//! - The program's `close()`: the same close, then the stream is dropped: nothing more is read.
//! - The program's close with data it hadn't read (TCP's RST): the stream is dropped without a
//!   close (an abort).
//! - The stream's EOF (a read of 0): the program reads EOF; it may go on writing.
//! - An error from the stream (a read, write or close): the program's socket is reset (its next
//!   call fails with ECONNRESET) and the stream is dropped.
//! - Both directions done: the stream is dropped, the program's socket closed.
//!
//! **Where the hooks run, and the authority rule: a hook is not a policy point.** The hooks run
//! inside the sandbox, after lockdown, on its executor ([`Cx`]): in the program's address space,
//! on one of its coroutines. A compromised program can read and write their memory, skip any
//! check they make, and drive whatever connection a provider holds (a [`HeldFd`]) as it likes.
//! None of this module is unsharek's trusted computing base: the network's only part of that is
//! the held fds themselves (which ones the sandbox holds, and the filter allowing
//! `read` and `write` on exactly those). So a held connection must carry no more authority than
//! the program's own channel would: policy (which addresses, which names) is enforced at its far
//! end, in the provider's own process, which unsharek leaves agnostic, never in a hook. A hook is
//! plumbing, not a guard: anything it decides, a compromised program can skip.
//!
//! What the hooks may do: compute, allocate (unsharek's allocator serves the sandbox after
//! lockdown), spawn tasks ([`Cx::spawn`]), wait on time and on the host fds held for them
//! (`unsharek::Guest::hold_fd`, [`Cx::readable`]), and use streams opened
//! before lockdown (a `TcpStream` connected before `run`, held). Not: make syscalls (they would
//! be the guest's, as init's: a thread of the program's process, which an exec waits for), open
//! host sockets or files (no host syscall is left for that), or block (the executor is one of
//! the sandbox's coroutines: a blocking call stops the program too).
//!
//! Every hook and task runs on that one executor, in every mode: in threaded mode only while it
//! holds the guest's CPU, so never on two host threads at once; in fork mode only in init's
//! process. So `std::sync::Mutex` and thread-locals are fine (one lock owner at a time, one TLS),
//! with the usual async rule held strictly: never keep a std lock across an `.await`. A task
//! contending a lock another task holds blocks in `futex`, which parks the executor itself: a
//! deadlock.

use std::future::Future;
use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use unsharek_rt::dns::Rcode;
use unsharek_rt::executor::{self, POLLIN, POLLOUT};
use unsharek_rt::tsi::{self, ByteStream, Conn};
use futures_io::{AsyncRead, AsyncWrite};
use rustix::io::Errno;

pub use unsharek_rt::executor::{FdReady, Sleep};


/// Why a hook refused (see the module comment for each one's errno).
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum NetError {
    #[error("denied")]
    Denied,
    #[error("refused")]
    Refused,
    #[error("unreachable")]
    Unreachable,
    #[error("timed out")]
    Timeout,
    #[error("no such name")]
    NoName,
    #[error("not supported")]
    Unsupported,
    #[error("I/O error")]
    Io,
}

impl NetError {
    /// What a program's `connect` fails with.
    pub fn connect_errno(self) -> i32 {
        match self {
            NetError::Denied => libc::EACCES,
            NetError::Refused => libc::ECONNREFUSED,
            NetError::Unreachable | NetError::NoName => libc::ENETUNREACH,
            NetError::Timeout => libc::ETIMEDOUT,
            NetError::Unsupported => libc::EAFNOSUPPORT,
            NetError::Io => libc::EIO,
        }
    }

    /// The resolver's answer for a lookup that failed so.
    fn rcode(self) -> Rcode {
        match self {
            NetError::NoName => Rcode::NxDomain,
            NetError::Denied | NetError::Unsupported => Rcode::NotAuth,
            _ => Rcode::ServFail,
        }
    }
}

/// An I/O error by its kind: refused, denied, timed out, unreachable; anything else `Io`.
impl From<io::Error> for NetError {
    fn from(e: io::Error) -> Self {
        match e.kind() {
            io::ErrorKind::ConnectionRefused => NetError::Refused,
            io::ErrorKind::PermissionDenied => NetError::Denied,
            io::ErrorKind::TimedOut => NetError::Timeout,
            io::ErrorKind::NetworkUnreachable | io::ErrorKind::HostUnreachable => NetError::Unreachable,
            io::ErrorKind::Unsupported => NetError::Unsupported,
            _ => NetError::Io,
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The hooks.

#[doc(hidden)]
pub type StartFn = Box<dyn FnOnce(Cx) -> Pin<Box<dyn Future<Output = ()>>>>;

/// What a sandbox runs for its program's network (module comment): the builder's.
#[doc(hidden)]
#[derive(Default)]
pub struct Hooks {
    pub on_connect: OnConnect,
    pub on_listen: OnListen,
    pub on_resolve: OnResolve,
    pub on_start: Option<StartFn>,
}

use tsi::{ConnectFn, ListenFn, ResolveFn};

/// The program's connects to anything but loopback: `async |cx, pid, addr| -> Result<stream,
/// NetError>`, the stream any `AsyncRead + AsyncWrite` (futures-io's; tokio's with
/// [`OnConnect::tokio`]).
///
/// **Not a policy point.** It runs after lockdown, in the program's address space: anything it
/// decides (refusing an address, a name), a compromised program can skip, by calling the
/// provider's held fd itself. Enforce policy at the far end of the held fd, in the provider's
/// own process.
#[derive(Default)]
pub struct OnConnect(pub(crate) Option<ConnectFn>);

fn errno(e: NetError) -> Errno {
    Errno::from_raw_os_error(e.connect_errno())
}

impl OnConnect {
    pub fn new<F, Fut, S>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<S, NetError>> + 'static,
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move { fut.await.map(|s| Conn::Stream(Box::pin(Io(s)))).map_err(errno) })
        })))
    }

    /// For a provider that hands over a host fd, the connection itself: the guest's socket is
    /// backed by it, nothing copied ([`FdConn`]: its shutdown and close).
    pub fn fd<F, Fut, C>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<(RawFd, C), NetError>> + 'static,
        C: FdConn + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move { fut.await.map(|(fd, c)| Conn::Fd(fd, Box::new(c))).map_err(errno) })
        })))
    }

    /// For a provider that drives the program's socket itself: `Ok(drive)` connects it, and
    /// `drive` is called with the program's end ([`GuestSocket`]) once connected.
    pub fn drive<F, Fut, D>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<D, NetError>> + 'static,
        D: FnOnce(GuestSocket) + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|d| Conn::Drive(Box::new(move |g: tsi::GuestSocket| d(GuestSocket(Some(g))))))
                    .map_err(errno)
            })
        })))
    }

    /// As [`OnConnect::new`], for streams with tokio's `AsyncRead + AsyncWrite`.
    #[cfg(feature = "tokio")]
    pub fn tokio<F, Fut, S>(mut f: F) -> OnConnect
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<S, NetError>> + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    {
        OnConnect(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move { fut.await.map(|s| Conn::Stream(Box::pin(TokioIo(s)))).map_err(errno) })
        })))
    }
}

/// A connection a host fd backs, from [`OnConnect::fd`] or [`OnListen::fd`]: the guest's socket
/// reads and writes the fd itself (no copy). The program's `shutdown(how)` is this object's (it
/// must not block: spawn on [`Cx`]); its close is this object's drop, which must close the fd.
pub use unsharek_rt::tsi::FdConn;

/// [`OnListen::fd`]'s connections: a published port's, by fd.
struct FdIncoming<St>(St);

impl<St, C> tsi::Incoming for FdIncoming<St>
where
    St: futures_core::Stream<Item = (SocketAddr, (RawFd, C))> + Unpin,
    C: FdConn + 'static,
{
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<(SocketAddrV4, tsi::Conn)>> {
        loop {
            match Pin::new(&mut self.0).poll_next(cx) {
                Poll::Ready(Some((SocketAddr::V4(peer), (fd, c)))) => return Poll::Ready(Some((peer, tsi::Conn::Fd(fd, Box::new(c))))),
                // (dropped: closes it)
                Poll::Ready(Some((SocketAddr::V6(_), _))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// The program's listens on anything but loopback: `async |cx, pid, addr| -> Result<incoming,
/// NetError>`, `incoming` a `Stream` of `(peer, stream)`.
///
/// **Not a policy point.** It runs after lockdown, in the program's address space: anything it
/// decides (refusing an address, a name), a compromised program can skip, by calling the
/// provider's held fd itself. Enforce policy at the far end of the held fd, in the provider's
/// own process.
#[derive(Default)]
pub struct OnListen(pub(crate) Option<ListenFn>);

impl OnListen {
    /// As [`OnListen::new`], each inbound connection a host fd ([`OnConnect::fd`]).
    pub fn fd<F, Fut, St, C>(mut f: F) -> OnListen
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<St, NetError>> + 'static,
        St: futures_core::Stream<Item = (SocketAddr, (RawFd, C))> + Unpin + 'static,
        C: FdConn + 'static,
    {
        OnListen(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|st| {
                        let b: tsi::BoxIncoming = Box::pin(FdIncoming(st));
                        b
                    })
                    .map_err(errno)
            })
        })))
    }

    pub fn new<F, Fut, St, S>(mut f: F) -> OnListen
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<St, NetError>> + 'static,
        St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Unpin + 'static,
    {
        OnListen(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|st| {
                        let b: tsi::BoxIncoming =
                            Box::pin(IncomingOf(st, |s| -> tsi::BoxStream { Box::pin(Io(s)) }));
                        b
                    })
                    .map_err(errno)
            })
        })))
    }

    /// As [`OnListen::new`], for streams with tokio's `AsyncRead + AsyncWrite`.
    #[cfg(feature = "tokio")]
    pub fn tokio<F, Fut, St, S>(mut f: F) -> OnListen
    where
        F: FnMut(Cx, i32, SocketAddr) -> Fut + 'static,
        Fut: Future<Output = Result<St, NetError>> + 'static,
        St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin + 'static,
        S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + 'static,
    {
        OnListen(Some(Box::new(move |_, pid, a| {
            let fut = f(Cx, pid, SocketAddr::V4(a));
            Box::pin(async move {
                fut.await
                    .map(|st| {
                        let b: tsi::BoxIncoming =
                            Box::pin(IncomingOf(st, |s| -> tsi::BoxStream { Box::pin(TokioIo(s)) }));
                        b
                    })
                    .map_err(errno)
            })
        })))
    }
}

/// The program's name lookups: `async |cx, pid, name| -> Result<Vec<IpAddr>, NetError>`. `name`
/// is lowercased, without a trailing dot.
///
/// **Not a policy point.** It runs after lockdown, in the program's address space: anything it
/// decides (refusing an address, a name), a compromised program can skip, by calling the
/// provider's held fd itself. Enforce policy at the far end of the held fd, in the provider's
/// own process.
#[derive(Default)]
pub struct OnResolve(pub(crate) Option<ResolveFn>);

impl OnResolve {
    pub fn new<F, Fut>(mut f: F) -> OnResolve
    where
        F: FnMut(Cx, i32, String) -> Fut + 'static,
        Fut: Future<Output = Result<Vec<IpAddr>, NetError>> + 'static,
    {
        OnResolve(Some(Box::new(move |_, pid, name| {
            let fut = f(Cx, pid, name.clone());
            Box::pin(async move {
                match fut.await {
                    Ok(ips) => {
                        let v4: Vec<_> = ips
                            .into_iter()
                            .filter_map(|ip| match ip {
                                IpAddr::V4(v4) => Some(v4),
                                IpAddr::V6(_) => None,
                            })
                            .collect();
                        let mut n = names();
                        for a in &v4 {
                            n.by_addr.insert(*a, name.clone());
                        }
                        Ok(v4)
                    }
                    Err(e) => Err(e.rcode()),
                }
            })
        })))
    }
}

impl Hooks {
    /// Whether the program's names resolve: an `on_resolve`, or an `on_connect` (names then
    /// resolve to addresses of their own, [`Cx::address_for`]). The guest's resolver files are
    /// written for it at build (`setup::resolver`).
    pub fn resolves(&self) -> bool {
        self.on_resolve.0.is_some() || self.on_connect.0.is_some()
    }

    /// The network hooks, given to the runtime: the task to start at lockdown.
    pub fn install(self) -> Option<StartFn> {
        let resolve = match (self.on_resolve.0, &self.on_connect.0) {
            (Some(r), _) => Some(r),
            (None, Some(_)) => OnResolve::new(|cx: Cx, _, name: String| {
                let a = cx.address_for(&name);
                async move { Ok(vec![a]) }
            })
            .0,
            (None, None) => None,
        };
        tsi::set_hooks(tsi::Hooks { connect: self.on_connect.0, listen: self.on_listen.0, resolve });
        self.on_start
    }
}

// ------------------------------------------------------------------------------------------------
// Names: held fds by name, addresses by the name they were resolved from.

/// What the hooks look up by name. Written by host code before lockdown and by the executor
/// after: one thread at a time, so the lock is never contended (a contended `std` lock would
/// park in a futex: module comment).
struct Names {
    held: Vec<(String, HeldFd)>,
    /// Each name a lookup answered, by address (the hook's addresses, or unsharek's own).
    by_addr: std::collections::BTreeMap<std::net::Ipv4Addr, String>,
    /// unsharek's own addresses, by name.
    own: std::collections::BTreeMap<String, std::net::Ipv4Addr>,
}

static NAMES: std::sync::Mutex<Names> = std::sync::Mutex::new(Names {
    held: Vec::new(),
    by_addr: std::collections::BTreeMap::new(),
    own: std::collections::BTreeMap::new(),
});

fn names() -> std::sync::MutexGuard<'static, Names> {
    NAMES.lock().unwrap_or_else(|e| e.into_inner())
}

#[doc(hidden)]
pub fn name_held(name: &str, fd: HeldFd) {
    let mut n = names();
    n.held.retain(|(k, _)| k != name);
    n.held.push((name.to_owned(), fd));
}

/// The first of unsharek's own addresses (10.64.0.0/10): far from loopback, from the nameserver's
/// 10.0.2.3 and from a provider's usual 10.0.0.N.
const OWN_BASE: u32 = u32::from_be_bytes([10, 64, 0, 1]);
const OWN_COUNT: u32 = (1 << 22) - 2;

// ------------------------------------------------------------------------------------------------
// The adapters: a hook's streams as the runtime's.

fn to_errno(e: io::Error) -> Errno {
    Errno::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO))
}

/// A futures-io stream as the runtime's `ByteStream`.
struct Io<S>(S);

impl<S: AsyncRead + AsyncWrite + Unpin> ByteStream for Io<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_read(cx, buf).map_err(to_errno)
    }
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(to_errno)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>> {
        Pin::new(&mut self.0).poll_close(cx).map_err(to_errno)
    }
}

/// A tokio stream as the runtime's `ByteStream`.
#[cfg(feature = "tokio")]
struct TokioIo<S>(S);

#[cfg(feature = "tokio")]
impl<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin> ByteStream for TokioIo<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<Result<usize, Errno>> {
        let mut rb = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(rb.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(to_errno(e))),
            Poll::Pending => Poll::Pending,
        }
    }
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize, Errno>> {
        Pin::new(&mut self.0).poll_write(cx, buf).map_err(to_errno)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Errno>> {
        Pin::new(&mut self.0).poll_shutdown(cx).map_err(to_errno)
    }
}

/// A `Stream` of `(peer, stream)` as the runtime's `Incoming` (IPv6 peers are left out: the
/// program's socket is AF_INET).
struct IncomingOf<St, F>(St, F);

impl<St, S, F> tsi::Incoming for IncomingOf<St, F>
where
    St: futures_core::Stream<Item = (SocketAddr, S)> + Unpin,
    F: Fn(S) -> tsi::BoxStream + Unpin,
{
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<(SocketAddrV4, tsi::Conn)>> {
        loop {
            match Pin::new(&mut self.0).poll_next(cx) {
                Poll::Ready(Some((SocketAddr::V4(peer), s))) => return Poll::Ready(Some((peer, tsi::Conn::Stream((self.1)(s))))),
                Poll::Ready(Some((SocketAddr::V6(_), _))) => continue,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

// ------------------------------------------------------------------------------------------------
// The executor's handle, held fds, the guest's socket.

/// The hooks' handle on the sandbox's executor: spawn a task, the clock, timers, held fds. A
/// token (`Copy`, `Send`, `Sync`: one executor per sandbox), so a no_std protocol core's runtime
/// is a newtype over it (capnweb's `Runtime { spawn, now, sleep_until }`: `spawn(task)` is
/// `cx.spawn(task)`, `now()` is `cx.now()`, `sleep_until(d)` is `Box::pin(cx.sleep_until(d))`).
///
/// What runs on it is the program's to corrupt (it shares the address space): see the module
/// comment's authority rule.
#[derive(Clone, Copy, Debug, Default)]
pub struct Cx;

impl Cx {
    /// The fd held under `name` (`unsharek::Guest::hold_fd_as`).
    pub fn held(&self, name: &str) -> Option<HeldFd> {
        names().held.iter().find(|(k, _)| k == name).map(|&(_, fd)| fd)
    }

    /// The name a lookup of the program's resolved to `addr` (the latest, if several), if any:
    /// for an `on_connect` that decides by name.
    pub fn name_of(&self, addr: IpAddr) -> Option<String> {
        let IpAddr::V4(a) = addr else { return None };
        names().by_addr.get(&a).cloned()
    }

    /// An address of `name`'s own, the same for the sandbox's life: what names resolve to when
    /// there is no `on_resolve` (an `on_resolve` may answer with it too). 10.64.0.0/10.
    pub fn address_for(&self, name: &str) -> IpAddr {
        let mut n = names();
        if let Some(a) = n.own.get(name) {
            return IpAddr::V4(*a);
        }
        let k = n.own.len() as u32 % OWN_COUNT;
        let a = std::net::Ipv4Addr::from(OWN_BASE + k);
        n.own.insert(name.to_owned(), a);
        IpAddr::V4(a)
    }

    /// Run `f` in the background on the executor, to completion (a provider's session, say).
    pub fn spawn(&self, f: impl Future<Output = ()> + 'static) {
        executor::spawn(f)
    }

    /// Monotonic time since an arbitrary origin (CLOCK_MONOTONIC).
    pub fn now(&self) -> Duration {
        executor::Cx.now()
    }

    /// Ready once [`Cx::now`] reaches `deadline`.
    pub fn sleep_until(&self, deadline: Duration) -> Sleep {
        executor::Cx.sleep_until(deadline)
    }

    /// Ready once `fd` is readable (or has an error or hangup).
    pub fn readable(&self, fd: &HeldFd) -> FdReady {
        executor::Cx.readable(fd.fd)
    }

    /// Ready once `fd` is writable (or has an error or hangup).
    pub fn writable(&self, fd: &HeldFd) -> FdReady {
        executor::Cx.writable(fd.fd)
    }
}

/// A host fd held for the hooks (`unsharek::Guest::hold_fd`): a provider's
/// connection, made before lockdown. Nonblocking; read and written through the runtime's gate,
/// the filter allowing `read` and `write` on exactly this fd; waited on by the executor
/// ([`Cx::readable`]). As `AsyncRead + AsyncWrite` it is a provider's stream. Open for the
/// sandbox's life (`Copy`: a handle).
#[derive(Clone, Copy, Debug)]
pub struct HeldFd {
    pub(crate) fd: RawFd,
}

impl AsRawFd for HeldFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

fn io_err(e: Errno) -> io::Error {
    io::Error::from_raw_os_error(e.raw_os_error())
}

impl HeldFd {
    /// The handle of a host fd the sandbox holds (unsharek's `Guest::hold_fd`).
    #[doc(hidden)]
    pub fn from_raw(fd: RawFd) -> HeldFd {
        HeldFd { fd }
    }

    /// One `read`; `WouldBlock` if nothing is there.
    pub fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        unsharek_rt::trap::read(self.fd as u32, buf).map_err(io_err)
    }

    /// One `write`; `WouldBlock` if there's no room.
    pub fn write(&self, buf: &[u8]) -> io::Result<usize> {
        unsharek_rt::trap::write(self.fd as u32, buf).map_err(io_err)
    }

    /// Read what is there, waiting (on the executor) until something is: `Ok(0)` is EOF. (As
    /// `AsyncRead`, futures' `AsyncReadExt` works on it too.)
    pub async fn read_async(&self, buf: &mut [u8]) -> io::Result<usize> {
        std::future::poll_fn(|cx| self.poll_io(cx, POLLIN, || self.read(buf))).await
    }

    /// Write all of `buf`, waiting (on the executor) for room.
    pub async fn write_all_async(&self, mut buf: &[u8]) -> io::Result<()> {
        while !buf.is_empty() {
            let n = std::future::poll_fn(|cx| self.poll_io(cx, POLLOUT, || self.write(buf))).await?;
            if n == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            buf = &buf[n..];
        }
        Ok(())
    }

    fn poll_io(&self, cx: &mut Context<'_>, events: i16, mut f: impl FnMut() -> io::Result<usize>) -> Poll<io::Result<usize>> {
        loop {
            match f() {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                    if executor::poll_fd(self.fd, events, cx).is_pending() {
                        return Poll::Pending;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                r => return Poll::Ready(r),
            }
        }
    }
}

impl AsyncRead for HeldFd {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLIN, || fd.read(buf))
    }
}

impl AsyncWrite for HeldFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLOUT, || fd.write(buf))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    /// A held fd stays open for the sandbox's life (no host `shutdown` is allowed): nothing.
    fn poll_close(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for HeldFd {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let fd = *self;
        let dst = buf.initialize_unfilled();
        match fd.poll_io(cx, POLLIN, || fd.read(dst)) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for HeldFd {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let fd = *self;
        fd.poll_io(cx, POLLOUT, || fd.write(buf))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// The host's end of one of the program's connections, for a provider that drives it itself
/// ([`OnConnect::drive`]): what the program writes is read here, what is written here it reads.
/// `poll_close` is a half-close (the program reads EOF, and may still write); dropped, the
/// program's socket is closed (EOF); [`GuestSocket::reset`] resets it (ECONNRESET). A read of 0
/// is the program's shutdown of its writing or its close; an error `ConnectionReset` its close
/// with data unread.
#[derive(Debug)]
pub struct GuestSocket(Option<tsi::GuestSocket>);

impl GuestSocket {
    fn inner(&mut self) -> &mut tsi::GuestSocket {
        self.0.as_mut().expect("GuestSocket used after reset")
    }

    /// Close with a reset: the program's next call on its socket fails with ECONNRESET.
    pub fn reset(mut self) {
        if let Some(g) = self.0.take() {
            g.reset();
        }
    }
}

impl AsyncRead for GuestSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<io::Result<usize>> {
        match self.inner().poll_read(cx, buf) {
            // The program's close: an EOF, as its shutdown is.
            Poll::Ready(Err(Errno::PIPE)) => Poll::Ready(Ok(0)),
            p => p.map_err(io_err),
        }
    }
}

impl AsyncWrite for GuestSocket {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        self.inner().poll_write(cx, buf).map_err(io_err)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(self.inner().shutdown().map_err(io_err))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for GuestSocket {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut tokio::io::ReadBuf<'_>) -> Poll<io::Result<()>> {
        let dst = buf.initialize_unfilled();
        match AsyncRead::poll_read(self.as_mut(), cx, dst) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for GuestSocket {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(self, cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(self, cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_close(self, cx)
    }
}
