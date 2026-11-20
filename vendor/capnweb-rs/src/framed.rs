//! Bounded length-prefixed Cap'n Web transport over any [`ByteRead`] and [`ByteWrite`] pair.
//!
//! Each frame is a four-byte big-endian length and that many bytes of JSON. This is the runtime-
//! and std-independent core of [`crate::FramedStreamTransport`] (which adds tokio streams and byte
//! channels on top); it needs only a [`crate::runtime::Runtime`] for closing the stream after an
//! abort.

use core::any::Any;
use core::future::Future;
use core::pin::Pin;

use crate::core::{
    CustomMessageCodec, CustomMessageContext, CustomTypeHandler, CustomTypeRegistry, Error, Result,
};
use crate::io::{BoxByteRead, BoxByteWrite, ByteRead, ByteReadExt, ByteWrite, ByteWriteExt};
use crate::platform::{Arc, Mutex};
#[cfg(not(feature = "std"))]
use crate::prelude::*;
use crate::rpc::{AnyRpcTransport, TransportMessage, TransportSend};
use crate::send_queue::SendQueue;
use crate::serialize::{EncodingLevel, capnweb_to_json, json_to_capnweb};
use crate::sync::{AsyncMutex, Signal, abortable};

/// Default maximum encoded frame size: one MiB.
pub const DEFAULT_MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Receives notification when a control transport becomes unusable.
pub trait TransportAbortHandler: Send + Sync + 'static {
    /// Aborts resources whose lifetime is bounded by the control transport.
    fn transport_aborted(&self, reason: Error);
}

/// Builder for a [`FramedTransport`].
pub struct FramedTransportBuilder {
    pub(crate) max_frame_bytes: usize,
    pub(crate) registry: CustomTypeRegistry,
    pub(crate) abort_handlers: Vec<Arc<dyn TransportAbortHandler>>,
}

impl Default for FramedTransportBuilder {
    fn default() -> Self {
        Self {
            max_frame_bytes: DEFAULT_MAX_FRAME_BYTES,
            registry: CustomTypeRegistry::new(),
            abort_handlers: Vec::new(),
        }
    }
}

impl FramedTransportBuilder {
    /// Creates a builder with the default one-MiB frame limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum JSON payload size, excluding the four-byte prefix.
    pub fn max_frame_bytes(mut self, max_frame_bytes: usize) -> Self {
        self.max_frame_bytes = max_frame_bytes;
        self
    }

    /// Registers a transport-defined custom value handler.
    pub fn custom_type(mut self, handler: Arc<dyn CustomTypeHandler>) -> Result<Self> {
        self.registry.register(handler)?;
        Ok(self)
    }

    /// Registers a resource owner that must be aborted with this transport.
    pub fn abort_handler(mut self, handler: Arc<dyn TransportAbortHandler>) -> Self {
        self.abort_handlers.push(handler);
        self
    }

    /// Builds the transport over a stream's two halves.
    pub fn build(
        self,
        reader: impl ByteRead + 'static,
        writer: impl ByteWrite + 'static,
    ) -> Result<FramedTransport> {
        self.build_boxed(Box::pin(reader), Box::pin(writer))
    }

    pub(crate) fn build_boxed(
        self,
        reader: BoxByteRead,
        writer: BoxByteWrite,
    ) -> Result<FramedTransport> {
        if self.max_frame_bytes == 0 || self.max_frame_bytes > u32::MAX as usize {
            return Err(Error::Type(
                "framed stream maximum must be in 1..=u32::MAX".to_owned(),
            ));
        }
        Ok(FramedTransport {
            state: Arc::new(FramedState {
                reader: AsyncMutex::new(Some(reader)),
                writer: AsyncMutex::new(Some(writer)),
                send_queue: SendQueue::new(),
                abort: Signal::new(),
                abort_handlers: Mutex::new(Some(self.abort_handlers)),
            }),
            registry: Arc::new(self.registry),
            max_frame_bytes: self.max_frame_bytes,
        })
    }
}

struct EmptyMessageContext;

impl CustomMessageContext for EmptyMessageContext {
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

struct FramedState {
    reader: AsyncMutex<Option<BoxByteRead>>,
    writer: AsyncMutex<Option<BoxByteWrite>>,
    /// Length-prefixed frames in `send()` order, written by whichever send holds `writer`.
    send_queue: Arc<SendQueue<Vec<u8>>>,
    abort: Signal<Error>,
    abort_handlers: Mutex<Option<Vec<Arc<dyn TransportAbortHandler>>>>,
}

impl FramedState {
    fn abort(self: &Arc<Self>, reason: Error) {
        let handlers = self
            .abort_handlers
            .lock()
            .expect("framed stream abort mutex poisoned")
            .take();
        let Some(handlers) = handlers else {
            return;
        };
        self.abort.set(reason.clone());
        for handler in handlers {
            handler.transport_aborted(reason.clone());
        }

        // (the stream closed once the pending reads and writes, woken by the abort, let go of it)
        let state = Arc::clone(self);
        let _ = crate::runtime::try_spawn(async move {
            state.reader.lock().await.take();
            if let Some(mut writer) = state.writer.lock().await.take() {
                let _ = writer.close().await;
            }
        });
    }

    fn reason(&self) -> Option<Error> {
        self.abort.get()
    }
}

/// A bounded `u32`-length-prefixed JSON transport over a [`ByteRead`] and a [`ByteWrite`].
///
/// Frames leave in `send()` order. Explicit abort, malformed or truncated frames, end of stream,
/// and send or receive failures abort it: pending sends and receives fail with the reason, the
/// abort handlers run, and the stream is closed. Dropping it aborts it.
pub struct FramedTransport {
    state: Arc<FramedState>,
    registry: Arc<CustomTypeRegistry>,
    max_frame_bytes: usize,
}

impl FramedTransport {
    /// Starts configuring a framed transport.
    pub fn builder() -> FramedTransportBuilder {
        FramedTransportBuilder::new()
    }

    /// Wraps a stream's halves with default limits and no custom values.
    pub fn new(reader: impl ByteRead + 'static, writer: impl ByteWrite + 'static) -> Result<Self> {
        Self::builder().build(reader, writer)
    }
}

impl Drop for FramedTransport {
    fn drop(&mut self) {
        self.state.abort(Error::Message(
            "framed stream control transport was dropped".to_owned(),
        ));
    }
}

impl AnyRpcTransport for FramedTransport {
    fn encoding_level(&self) -> EncodingLevel {
        EncodingLevel::JsonCompatible
    }

    fn new_custom_codec(&self) -> Option<Box<CustomMessageCodec>> {
        Some(Box::new(CustomMessageCodec::new(
            Arc::clone(&self.registry),
            Box::new(EmptyMessageContext),
        )))
    }

    fn send(&self, message: TransportMessage) -> Result<TransportSend> {
        if let Some(reason) = self.state.reason() {
            return Err(reason);
        }
        let TransportMessage::Value { value, codec } = message else {
            return Err(Error::Type(
                "framed stream transport expected a structured value tree".to_owned(),
            ));
        };
        let json = capnweb_to_json(&value)?;
        let payload = serde_json::to_vec(&json)
            .map_err(|error| Error::Message(format!("failed to encode RPC frame: {error}")))?;
        if payload.len() > self.max_frame_bytes {
            return Err(Error::Message(format!(
                "RPC frame exceeds maximum size of {} bytes",
                self.max_frame_bytes
            )));
        }
        let length = u32::try_from(payload.len())
            .expect("frame limit guarantees that its length fits in u32")
            .to_be_bytes();
        let mut frame = Vec::with_capacity(length.len() + payload.len());
        frame.extend_from_slice(&length);
        frame.extend_from_slice(&payload);
        // Queue the frame now so the wire order is the `send()` order.
        let sequence = self.state.send_queue.push(frame);
        let state = Arc::clone(&self.state);
        let size = Some(length.len() + payload.len());
        let sent = Box::pin(async move {
            let _codec = codec;
            let result = abortable(&state.abort, async {
                let mut writer = state.writer.lock().await;
                let writer = writer.as_mut().ok_or_else(|| {
                    Error::Message("framed stream transport is closed".to_owned())
                })?;
                while let Some(frame) = state.send_queue.pop()? {
                    writer.write_all(frame.frame()).await.map_err(|error| {
                        Error::Message(format!("failed to write RPC frame: {error}"))
                    })?;
                    frame.written();
                }
                writer.flush().await.map_err(|error| {
                    Error::Message(format!("failed to flush RPC frame: {error}"))
                })?;
                state.send_queue.finish(sequence)
            })
            .await;
            if let Err(error) = &result {
                state.abort(error.clone());
            }
            result
        });
        Ok(TransportSend::Pending { size, sent })
    }

    fn receive(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Result<TransportMessage>> + Send + 'static>> {
        // (the transport kept alive while it receives: dropping it aborts it)
        Box::pin(async move { self.receive_shared().await })
    }

    fn abort(&self, reason: Error) {
        self.state.abort(reason);
    }
}

impl FramedTransport {
    /// [`AnyRpcTransport::receive`] without the `Arc`: the future holds what it needs.
    pub(crate) fn receive_shared(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<TransportMessage>> + Send + 'static>> {
        let state = Arc::clone(&self.state);
        let registry = Arc::clone(&self.registry);
        let max_frame_bytes = self.max_frame_bytes;
        Box::pin(async move {
            if let Some(reason) = state.reason() {
                return Err(reason);
            }
            let result = abortable(&state.abort, async {
                let mut reader = state.reader.lock().await;
                let reader = reader.as_mut().ok_or_else(|| {
                    Error::Message("framed stream transport is closed".to_owned())
                })?;
                read_frame(reader, registry, max_frame_bytes).await
            })
            .await;
            if let Err(error) = &result {
                state.abort(error.clone());
            }
            result
        })
    }
}

async fn read_frame(
    reader: &mut BoxByteRead,
    registry: Arc<CustomTypeRegistry>,
    max_frame_bytes: usize,
) -> Result<TransportMessage> {
    let mut length = [0u8; 4];
    reader
        .read_exact(&mut length)
        .await
        .map_err(|error| Error::Message(format!("failed to read RPC frame length: {error}")))?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 {
        return Err(Error::Message("invalid RPC frame size 0".to_owned()));
    }
    if length > max_frame_bytes {
        // (a push or stream message, by its first bytes, read past unbuffered: its call fails
        // alone; anything else ends the session)
        let mut head = [0u8; 10];
        let seen = head.len().min(length);
        reader
            .read_exact(&mut head[..seen])
            .await
            .map_err(|error| Error::Message(format!("failed to read RPC frame: {error}")))?;
        let stream = if head[..seen].starts_with(br#"["push","#) {
            false
        } else if head[..seen].starts_with(br#"["stream","#) {
            true
        } else {
            return Err(Error::Message(format!(
                "invalid RPC frame size {length}; maximum is {max_frame_bytes}"
            )));
        };
        let mut rest = length - seen;
        let mut scratch = vec![0u8; rest.min(64 * 1024)];
        while rest > 0 {
            let want = rest.min(scratch.len());
            let n = reader
                .read(&mut scratch[..want])
                .await
                .map_err(|error| Error::Message(format!("failed to read RPC frame: {error}")))?;
            if n == 0 {
                return Err(Error::Message("the RPC frame ended early".to_owned()));
            }
            rest -= n;
        }
        return Ok(TransportMessage::Oversized {
            stream,
            error: Error::Type(format!(
                "an RPC message of {length} bytes is over the frame limit of {max_frame_bytes} bytes"
            )),
        });
    }
    let mut payload = vec![0; length];
    reader
        .read_exact(&mut payload)
        .await
        .map_err(|error| Error::Message(format!("failed to read RPC frame: {error}")))?;
    let json: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|error| Error::Type(format!("invalid RPC frame JSON: {error}")))?;
    Ok(TransportMessage::Value {
        value: json_to_capnweb(json)?,
        codec: Some(Box::new(CustomMessageCodec::new(
            registry,
            Box::new(EmptyMessageContext),
        ))),
    })
}
