//! Plugin (experimental): the network through a provider process ([`unsharek_net`]). Everything
//! the plugin does on the sandbox's side is here, in one place: [`spawn`] forks the provider
//! before the guest boots; [`install`] holds the control socket and sets the hooks, which call the
//! provider over it. The CLI's cli/net.rs grants the control socket at lockdown (`recv_fds`).
//!
//! The hooks run on the sandbox's executor, as every hook does, and decide nothing: `connect` and
//! `listen` ask the provider, whose policy holds, and the socket it passes in becomes the stream
//! the guest's socket is copied to and from (a [`HeldFd`] over the received fd). Not trusted:
//! a compromised program can make the same calls itself, and gets only what the provider allows.

use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use capnweb::packet::PacketSocket;
use capnweb::runtime::{Runtime, Task};
use unsharek_net::client::{Client, Rejection};
use unsharek_net::protocol;
pub use unsharek_net::{Policy, Publish};
use unsharek_rt::executor::{self, POLLIN, POLLOUT};

use crate::net::{Cx, HeldFd, NetError, OnConnect, OnListen, OnResolve};
use crate::{Error, Guest};

/// The network the CLI's `--net` and `--publish` ask for.
#[derive(Clone, Debug, Default)]
pub struct NetConfig {
    /// None: no network beyond loopback (the default).
    pub policy: Option<Policy>,
    /// Ports published to the guest's listeners.
    pub publish: Vec<Publish>,
}

impl NetConfig {
    pub fn enabled(&self) -> bool {
        self.policy.is_some() || !self.publish.is_empty()
    }
}

/// Fork the provider (before the guest boots: one thread, no guest yet) with `net`'s policy and
/// published ports; the sandbox's end of the control socket. The provider ends when that end
/// closes (the sandbox's end).
pub fn spawn(net: &NetConfig) -> Result<OwnedFd, Error> {
    let io = Error::io("the network provider");
    let listeners = unsharek_net::bind_published(&net.publish).map_err(Error::io("a published port"))?;
    let mut sv = [0; 2];
    // SAFETY: socketpair into a local.
    if unsafe { libc::socketpair(libc::AF_UNIX, libc::SOCK_SEQPACKET | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC, 0, sv.as_mut_ptr()) } < 0 {
        return Err(io(std::io::Error::last_os_error()));
    }
    // No `--net`: the provider dials nothing (a compromised program calling `connect` itself
    // gets Denied), and only serves the published ports.
    let policy = net.policy.unwrap_or(Policy::Deny);
    // SAFETY: the child serves and exits (`serve` never returns); the parent goes on.
    match unsafe { libc::fork() } {
        -1 => Err(io(std::io::Error::last_os_error())),
        0 => {
            // SAFETY: the sandbox's end is not the provider's.
            unsafe { libc::close(sv[0]) };
            unsharek_net::serve(sv[1], policy, listeners)
        }
        _ => {
            // SAFETY: the provider's end, and the listeners, are the provider's.
            unsafe { libc::close(sv[1]) };
            drop(listeners);
            // SAFETY: ours, just made.
            Ok(unsafe { OwnedFd::from_raw_fd(sv[0]) })
        }
    }
}

/// Hold `ctl` and set the hooks: connects (if `dials`) and resolves through the provider, listens
/// for published ports. Returns the control socket's fd, for [`grant`].
pub fn install(g: &mut Guest, ctl: OwnedFd, dials: bool) -> Result<RawFd, Error> {
    let held = g.hold_fd(ctl)?;
    let fd = held.as_raw_fd();
    // The sandbox's executor as capnweb-rs's runtime everywhere, even where none is entered (a
    // stub dropped by the copier, its release message): its fallback is a thread of its own,
    // which the filter can't make. Set once; a second sandbox in this process keeps the first.
    let runtime: Arc<dyn Runtime> = Arc::new(ExecutorRuntime);
    let _ = capnweb::runtime::set_default(Arc::clone(&runtime));
    let client = Client::new(runtime, GateCtl(fd));
    if dials {
        let c = Arc::clone(&client);
        g.on_connect(OnConnect::new(move |_cx, _pid, addr: SocketAddr| {
            let call = c.connect(addr.ip(), addr.port());
            let c = Arc::clone(&c);
            async move { call.await.map(|(fd, conn)| Conn::new(c, fd, conn)).map_err(net_error) }
        }))?;
        let c = Arc::clone(&client);
        g.on_resolve(OnResolve::new(move |_cx, _pid, name| {
            let call = c.resolve(name);
            async move { call.await.map(|ips| ips.into_iter().map(IpAddr::V4).collect()).map_err(net_error) }
        }))?;
    }
    let c = Arc::clone(&client);
    g.on_listen(OnListen::new(move |_cx, _pid, addr: SocketAddr| {
        let c = Arc::clone(&c);
        async move {
            let listener = c.listen(addr.port()).await.map_err(net_error)?;
            Ok(Incoming { client: c, listener, next: None })
        }
    }));
    Ok(fd)
}

fn net_error(r: Rejection) -> NetError {
    match r {
        Some(protocol::DENIED) => NetError::Denied,
        Some(protocol::REFUSED) => NetError::Refused,
        Some(protocol::UNREACHABLE) => NetError::Unreachable,
        Some(protocol::TIMEOUT) => NetError::Timeout,
        Some(protocol::NO_NAME) => NetError::NoName,
        _ => NetError::Io,
    }
}

type Accept = Pin<Box<dyn Future<Output = Result<(RawFd, SocketAddr, capnweb::RpcStub), Rejection>> + Send>>;

/// A connection the provider passed in: its bytes are the received fd's (a [`HeldFd`]); its
/// half-close is the provider's (`conn.shutdownWrite()`, the sandbox can't `shutdown` its own
/// fd), and its drop releases `conn`, which the provider shuts down both ways. The fd itself
/// stays open (no `close` is allowed after lockdown).
pub struct Conn {
    client: Arc<Client<GateCtl>>,
    fd: HeldFd,
    conn: Option<capnweb::RpcStub>,
    closing: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Conn {
    fn new(client: Arc<Client<GateCtl>>, fd: RawFd, conn: capnweb::RpcStub) -> Conn {
        Conn { client, fd: HeldFd::from_raw(fd), conn: Some(conn), closing: None }
    }
}

impl futures_io::AsyncRead for Conn {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut [u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.fd).poll_read(cx, buf)
    }
}

impl futures_io::AsyncWrite for Conn {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.fd).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    /// The half-close, by the provider: done once it has shut its copy down.
    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        if this.closing.is_none() {
            let Some(conn) = &this.conn else { return Poll::Ready(Ok(())) };
            this.closing = Some(Box::pin(this.client.shutdown_write(conn)));
        }
        let done = this.closing.as_mut().expect("closing").as_mut().poll(cx);
        done.map(Ok)
    }
}

impl Drop for Conn {
    /// The close: `conn` released (the provider shuts the socket down both ways), with the
    /// executor's runtime entered for the release message.
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            let rt: Arc<dyn Runtime> = Arc::new(ExecutorRuntime);
            capnweb::runtime::enter(&rt, || drop(conn));
        }
        // Our copy of the socket: a received fd, the one kind the filter lets us close.
        let _ = unsharek_rt::trap::close(self.fd.as_raw_fd() as u32);
    }
}

/// A published port's connections, one `accept()` call each, as the listen hook's stream.
struct Incoming {
    client: Arc<Client<GateCtl>>,
    listener: capnweb::RpcStub,
    next: Option<Accept>,
}

impl futures_core::Stream for Incoming {
    type Item = (SocketAddr, Conn);
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = &mut *self;
        let next = this.next.get_or_insert_with(|| Box::pin(this.client.accept(&this.listener)));
        match next.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(r) => {
                this.next = None;
                // A failed accept ends the listen (the provider's listener is gone).
                Poll::Ready(r.ok().map(|(fd, peer, conn)| (peer, Conn::new(Arc::clone(&this.client), fd, conn))))
            }
        }
    }
}

/// The control socket on the sandbox's side: plain `write`s, `recvmsg` (the gate's, with
/// `MSG_CMSG_CLOEXEC`: the one call unsharek-tcb's row allows, on this fd only), readiness on the
/// executor.
struct GateCtl(RawFd);

impl PacketSocket for GateCtl {
    fn send(&self, bytes: &[u8]) -> std::io::Result<usize> {
        unsharek_rt::trap::write(self.0 as u32, bytes).map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))
    }
    fn recv(&self, buf: &mut [u8]) -> std::io::Result<(usize, Vec<RawFd>)> {
        let mut fds = [0; unsharek_rt::trap::RECV_FDS_MAX];
        let (n, got) = unsharek_rt::trap::recv_fds(self.0 as u32, buf, &mut fds)
            .map_err(|e| std::io::Error::from_raw_os_error(e.raw_os_error()))?;
        Ok((n, fds[..got].to_vec()))
    }
    fn poll_ready(&self, cx: &mut Context<'_>, write: bool) -> Poll<()> {
        executor::poll_fd(self.0, if write { POLLOUT } else { POLLIN }, cx)
    }
}

/// capnweb-rs's runtime on the sandbox's executor ([`Cx`]).
struct ExecutorRuntime;

impl Runtime for ExecutorRuntime {
    fn spawn(&self, task: Task) {
        Cx.spawn(task);
    }
    fn now(&self) -> Duration {
        Cx.now()
    }
    fn sleep_until(&self, deadline: Duration) -> Task {
        Box::pin(Cx.sleep_until(deadline))
    }
}
