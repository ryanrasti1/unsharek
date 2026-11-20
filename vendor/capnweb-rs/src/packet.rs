//! A message-oriented transport over any packet socket, for embedders that drive their own I/O
//! (no tokio, no syscalls of capnweb-rs's own): the [`UdsTransport`](crate::UdsTransport) wire
//! format (one JSON message per packet, SCM_RIGHTS descriptors as `["fd", index]`), with the
//! socket's sends, receives and readiness the embedder's [`PacketSocket`].
//!
//! Descriptors are [`Fd`]s, numbers: a peer's `["fd", i]` decodes to one, which this transport
//! never closes (an embedder that can't make a `close`, such as a sandbox after lockdown, keeps or
//! drops the number itself); an `Fd` in a sent value goes with the packet
//! ([`PacketSocket::send_fds`]), borrowed (the sender closes its own when the send is done). A
//! message without descriptors is sent as a plain packet ([`PacketSocket::send`]): on a
//! `SOCK_SEQPACKET` socket a `write(2)`, so an embedder that only receives fds needs no `sendmsg`.

use std::any::{Any, TypeId};
use std::future::Future;
use std::io;
use std::os::fd::RawFd;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use crate::core::{
    CapnwebValue, CustomMessageCodec, CustomMessageContext, CustomTypeHandler, CustomTypeRegistry,
    CustomValue, Error, Result,
};
use crate::rpc::{AnyRpcTransport, TransportMessage, TransportSend};
use crate::send_queue::SendQueue;
use crate::serialize::{EncodingLevel, capnweb_to_json, json_to_capnweb};

const MAX_MESSAGE_BYTES: usize = 256 * 1024;

/// The embedder's packet socket: nonblocking sends and receives (`WouldBlock` when not ready),
/// and readiness through its own executor.
pub trait PacketSocket: Send + Sync + 'static {
    /// One packet, no descriptors (`write` on a seqpacket socket).
    fn send(&self, bytes: &[u8]) -> io::Result<usize>;
    /// One packet and `fds` with it (SCM_RIGHTS). Unsupported unless the embedder sends fds.
    fn send_fds(&self, _bytes: &[u8], _fds: &[RawFd]) -> io::Result<usize> {
        Err(io::Error::from(io::ErrorKind::Unsupported))
    }
    /// One packet into `buf` and the descriptors sent with it: `(length, fds)`. A truncated
    /// packet or descriptor list is an error.
    fn recv(&self, buf: &mut [u8]) -> io::Result<(usize, Vec<RawFd>)>;
    /// Ready to `send` (`write`) or to `recv` (`!write`): `Ready` when it may be, the waker
    /// registered otherwise.
    fn poll_ready(&self, cx: &mut Context<'_>, write: bool) -> Poll<()>;
}

/// A descriptor, by number: received (a peer's, now this process's) or to send (borrowed). Never
/// closed here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fd(pub RawFd);

/// A [`PacketSocket`] as an RPC transport (see the module comment).
pub struct PacketTransport<S: PacketSocket> {
    socket: Arc<S>,
    registry: Arc<CustomTypeRegistry>,
    send_queue: Arc<SendQueue<(Vec<u8>, Vec<RawFd>)>>,
}

impl<S: PacketSocket> PacketTransport<S> {
    pub fn new(socket: S) -> Result<Self> {
        let mut registry = CustomTypeRegistry::new();
        registry.register(Arc::new(FdHandler))?;
        Ok(Self { socket: Arc::new(socket), registry: Arc::new(registry), send_queue: SendQueue::new() })
    }
}

async fn ready<S: PacketSocket>(socket: &S, write: bool) {
    std::future::poll_fn(|cx| socket.poll_ready(cx, write)).await
}

impl<S: PacketSocket> AnyRpcTransport for PacketTransport<S> {
    fn encoding_level(&self) -> EncodingLevel {
        EncodingLevel::JsonCompatible
    }

    fn new_custom_codec(&self) -> Option<Box<CustomMessageCodec>> {
        Some(Box::new(CustomMessageCodec::new(Arc::clone(&self.registry), Box::new(FdContext::Out(Vec::new())))))
    }

    fn send(&self, message: TransportMessage) -> Result<TransportSend> {
        let TransportMessage::Value { value, mut codec } = message else {
            return Err(Error::Type("packet transport expected a structured value tree".to_owned()));
        };
        let json = capnweb_to_json(&value)?;
        let bytes = serde_json::to_vec(&json)
            .map_err(|error| Error::Message(format!("failed to encode packet message: {error}")))?;
        if bytes.len() > MAX_MESSAGE_BYTES {
            return Err(Error::Message(format!("packet message exceeds {MAX_MESSAGE_BYTES} bytes")));
        }
        let fds = match codec.as_deref_mut().and_then(|c| c.context_mut::<FdContext>()) {
            Some(FdContext::Out(fds)) => std::mem::take(fds),
            _ => Vec::new(),
        };
        let size = Some(bytes.len());
        // Queued now so the wire order is the `send()` order.
        let sequence = self.send_queue.push((bytes, fds));
        let socket = Arc::clone(&self.socket);
        let send_queue = Arc::clone(&self.send_queue);
        let sent = Box::pin(async move {
            while let Some(packet) = send_queue.pop()? {
                let (bytes, fds) = packet.frame();
                loop {
                    let sent = if fds.is_empty() { socket.send(bytes) } else { socket.send_fds(bytes, fds) };
                    match sent {
                        Ok(n) if n == bytes.len() => break,
                        Ok(_) => return Err(Error::Message("packet send was truncated".to_owned())),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => ready(&*socket, true).await,
                        Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                        Err(e) => return Err(Error::Message(format!("packet send failed: {e}"))),
                    }
                }
                packet.written();
            }
            send_queue.finish(sequence)
        });
        Ok(TransportSend::Pending { size, sent })
    }

    fn receive(self: Arc<Self>) -> Pin<Box<dyn Future<Output = Result<TransportMessage>> + Send + 'static>> {
        Box::pin(async move {
            let mut buf = vec![0u8; MAX_MESSAGE_BYTES];
            let (n, fds) = loop {
                match self.socket.recv(&mut buf) {
                    Ok(r) => break r,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => ready(&*self.socket, false).await,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                    Err(e) => return Err(Error::Message(format!("packet receive failed: {e}"))),
                }
            };
            if n == 0 && fds.is_empty() {
                return Err(Error::Message("packet transport closed by its peer".to_owned()));
            }
            let json: serde_json::Value = serde_json::from_slice(&buf[..n])
                .map_err(|error| Error::Type(format!("invalid packet message: {error}")))?;
            let value = json_to_capnweb(json)?;
            let codec = CustomMessageCodec::new(
                Arc::clone(&self.registry),
                Box::new(FdContext::In(fds.into_iter().map(Some).collect())),
            );
            Ok(TransportMessage::Value { value, codec: Some(Box::new(codec)) })
        })
    }
}

/// A message's descriptors: a received one's, each taken once by its `["fd", i]`; a sent one's,
/// in `["fd", i]` order.
enum FdContext {
    In(Vec<Option<RawFd>>),
    Out(Vec<RawFd>),
}

impl CustomMessageContext for FdContext {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

struct FdHandler;

impl CustomTypeHandler for FdHandler {
    fn value_type_id(&self) -> TypeId {
        TypeId::of::<Fd>()
    }

    fn wire_tag(&self) -> &'static str {
        "fd"
    }

    fn encode_fields(&self, value: &CustomValue, context: &mut dyn CustomMessageContext) -> Result<Vec<CapnwebValue>> {
        let fd = value.downcast::<Fd>()?;
        let Some(FdContext::Out(fds)) = context.as_any_mut().downcast_mut::<FdContext>() else {
            return Err(Error::Type("fd handler received the wrong context".to_owned()));
        };
        fds.push(fd.0);
        Ok(vec![CapnwebValue::Number((fds.len() - 1) as f64)])
    }

    fn decode_fields(&self, fields: &[CapnwebValue], context: &mut dyn CustomMessageContext) -> Result<CustomValue> {
        let [index] = fields else {
            return Err(Error::Type("invalid fd marker".to_owned()));
        };
        let index = index
            .as_i64()
            .filter(|index| *index >= 0)
            .map(|index| index as usize)
            .ok_or_else(|| Error::Type("invalid fd marker index".to_owned()))?;
        let Some(FdContext::In(fds)) = context.as_any_mut().downcast_mut::<FdContext>() else {
            return Err(Error::Type("fd handler received the wrong context".to_owned()));
        };
        let fd = fds
            .get_mut(index)
            .ok_or_else(|| Error::Type("fd index is out of range".to_owned()))?
            .take()
            .ok_or_else(|| Error::Type("fd index was used twice".to_owned()))?;
        Ok(CustomValue::new(Fd(fd)))
    }
}
