//! Bounded length-prefixed Cap'n Web transport over a Tokio duplex stream.
//!
//! The framing is [`FramedTransport`]'s; this adds Tokio streams and byte channels.

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncRead, AsyncWrite};

use crate::channel::ByteChannelSession;
use crate::core::{CustomMessageCodec, CustomTypeHandler, Error, Result};
use crate::framed::{FramedTransport, FramedTransportBuilder, TransportAbortHandler};
use crate::io::Compat;
use crate::rpc::{AnyRpcTransport, TransportMessage, TransportSend};
use crate::serialize::EncodingLevel;

impl TransportAbortHandler for ByteChannelSession {
    fn transport_aborted(&self, reason: Error) {
        ByteChannelSession::abort(self, reason);
    }
}

/// Builder for a [`FramedStreamTransport`].
#[derive(Default)]
pub struct FramedStreamTransportBuilder {
    inner: FramedTransportBuilder,
}

impl FramedStreamTransportBuilder {
    /// Creates a builder with the default one-MiB frame limit.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the maximum JSON payload size, excluding the four-byte prefix.
    pub fn max_frame_bytes(self, max_frame_bytes: usize) -> Self {
        Self {
            inner: self.inner.max_frame_bytes(max_frame_bytes),
        }
    }

    /// Registers a transport-defined custom value handler.
    pub fn custom_type(self, handler: Arc<dyn CustomTypeHandler>) -> Result<Self> {
        Ok(Self {
            inner: self.inner.custom_type(handler)?,
        })
    }

    /// Registers a resource owner that must be aborted with this transport.
    pub fn abort_handler(self, handler: Arc<dyn TransportAbortHandler>) -> Self {
        Self {
            inner: self.inner.abort_handler(handler),
        }
    }

    /// Registers byte-channel encoding and binds all channels to this control transport.
    pub fn byte_channels(self, channels: Arc<ByteChannelSession>) -> Result<Self> {
        let inner = self.inner.custom_type(channels.custom_type_handler())?;
        Ok(Self {
            inner: inner.abort_handler(channels),
        })
    }

    /// Wraps and splits a Tokio duplex stream.
    pub fn build<S>(self, stream: S) -> Result<FramedStreamTransport>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (reader, writer) = tokio::io::split(stream);
        Ok(FramedStreamTransport {
            inner: self
                .inner
                .build_boxed(Box::pin(Compat(reader)), Box::pin(Compat(writer)))?,
        })
    }
}

/// A bounded `u32`-length-prefixed JSON transport over any Tokio duplex stream.
pub struct FramedStreamTransport {
    inner: FramedTransport,
}

impl FramedStreamTransport {
    /// Starts configuring a framed stream transport.
    pub fn builder() -> FramedStreamTransportBuilder {
        FramedStreamTransportBuilder::new()
    }

    /// Wraps a stream with default limits and no custom values.
    pub fn new<S>(stream: S) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        Self::builder().build(stream)
    }
}

impl AnyRpcTransport for FramedStreamTransport {
    fn encoding_level(&self) -> EncodingLevel {
        self.inner.encoding_level()
    }

    fn new_custom_codec(&self) -> Option<Box<CustomMessageCodec>> {
        self.inner.new_custom_codec()
    }

    fn send(&self, message: TransportMessage) -> Result<TransportSend> {
        self.inner.send(message)
    }

    fn receive(
        self: Arc<Self>,
    ) -> Pin<Box<dyn Future<Output = Result<TransportMessage>> + Send + 'static>> {
        // (the transport kept alive while it receives: dropping it aborts it)
        Box::pin(async move { self.inner.receive_shared().await })
    }

    fn abort(&self, reason: Error) {
        self.inner.abort(reason);
    }
}
