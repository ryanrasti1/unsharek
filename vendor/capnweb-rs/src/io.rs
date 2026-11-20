//! Byte streams without tokio: the traits a transport's fd and a stream's bytes are read and
//! written through, plus an in-memory pipe.
//!
//! [`ByteRead`] and [`ByteWrite`] are `poll_*` traits on `core::task`, shaped like
//! `futures::io`'s but with [`crate::Error`] for errors, so they need neither std nor tokio. An
//! embedder implements them over its own I/O (a held fd that its executor reports readable or
//! writable, a guest socket end) and hands them to [`crate::FramedTransport`], to
//! [`crate::ReadableStream::from_reader`] or to [`crate::WritableStream::from_writer`].
//!
//! With the `tokio` feature, [`Compat`] adapts in both directions between these traits and
//! tokio's `AsyncRead`/`AsyncWrite`.

use alloc::collections::VecDeque;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::core::{Error, Result};
use crate::platform::{Arc, Mutex};
#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// A source of bytes.
pub trait ByteRead: Send {
    /// Reads into `buf`, returning how many bytes were read; `Ok(0)` (for a non-empty `buf`) is
    /// the end of the stream. When nothing is available, registers `context`'s waker and returns
    /// `Pending`.
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>>;
}

/// A sink for bytes.
pub trait ByteWrite: Send {
    /// Writes some of `buf`, returning how many bytes were taken (at least one for a non-empty
    /// `buf`). When it can take nothing yet, registers `context`'s waker and returns `Pending`.
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>>;

    /// Completes once every byte written so far has been handed on.
    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>>;

    /// Flushes and ends the stream: the reader sees its end after the bytes written.
    fn poll_close(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>>;
}

/// A boxed [`ByteRead`].
pub type BoxByteRead = Pin<Box<dyn ByteRead>>;
/// A boxed [`ByteWrite`].
pub type BoxByteWrite = Pin<Box<dyn ByteWrite>>;

impl<T: ByteRead + Unpin + ?Sized> ByteRead for Box<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut **self).poll_read(context, buf)
    }
}

impl<T: ByteRead + ?Sized> ByteRead for Pin<Box<T>> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        self.get_mut().as_mut().poll_read(context, buf)
    }
}

impl<T: ByteRead + Unpin + ?Sized> ByteRead for &mut T {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut **self).poll_read(context, buf)
    }
}

impl<T: ByteWrite + Unpin + ?Sized> ByteWrite for Box<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut **self).poll_write(context, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut **self).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut **self).poll_close(context)
    }
}

impl<T: ByteWrite + ?Sized> ByteWrite for Pin<Box<T>> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        self.get_mut().as_mut().poll_write(context, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        self.get_mut().as_mut().poll_flush(context)
    }

    fn poll_close(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        self.get_mut().as_mut().poll_close(context)
    }
}

impl<T: ByteWrite + Unpin + ?Sized> ByteWrite for &mut T {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut **self).poll_write(context, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut **self).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut **self).poll_close(context)
    }
}

/// `async` helpers over [`ByteRead`].
pub trait ByteReadExt: ByteRead + Unpin {
    /// Reads into `buf`; `Ok(0)` is the end of the stream.
    fn read<'a>(&'a mut self, buf: &'a mut [u8]) -> impl Future<Output = Result<usize>> + Send + 'a
    where
        Self: Sized,
    {
        core::future::poll_fn(move |context| Pin::new(&mut *self).poll_read(context, buf))
    }

    /// Fills `buf`, failing if the stream ends first.
    fn read_exact<'a>(
        &'a mut self,
        buf: &'a mut [u8],
    ) -> impl Future<Output = Result<()>> + Send + 'a
    where
        Self: Sized,
    {
        async move {
            let mut filled = 0;
            while filled < buf.len() {
                let n = self.read(&mut buf[filled..]).await?;
                if n == 0 {
                    return Err(Error::Message("early eof".to_owned()));
                }
                filled += n;
            }
            Ok(())
        }
    }
}

impl<T: ByteRead + Unpin + ?Sized> ByteReadExt for T {}

/// `async` helpers over [`ByteWrite`].
pub trait ByteWriteExt: ByteWrite + Unpin {
    /// Writes some of `buf`, returning how many bytes were taken.
    fn write<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = Result<usize>> + Send + 'a
    where
        Self: Sized,
    {
        core::future::poll_fn(move |context| Pin::new(&mut *self).poll_write(context, buf))
    }

    /// Writes all of `buf`.
    fn write_all<'a>(&'a mut self, buf: &'a [u8]) -> impl Future<Output = Result<()>> + Send + 'a
    where
        Self: Sized,
    {
        async move {
            let mut written = 0;
            while written < buf.len() {
                let n = self.write(&buf[written..]).await?;
                if n == 0 {
                    return Err(Error::Message("write took no bytes".to_owned()));
                }
                written += n;
            }
            Ok(())
        }
    }

    /// Flushes what was written.
    fn flush(&mut self) -> impl Future<Output = Result<()>> + Send + '_
    where
        Self: Sized,
    {
        core::future::poll_fn(move |context| Pin::new(&mut *self).poll_flush(context))
    }

    /// Flushes and ends the stream.
    fn close(&mut self) -> impl Future<Output = Result<()>> + Send + '_
    where
        Self: Sized,
    {
        core::future::poll_fn(move |context| Pin::new(&mut *self).poll_close(context))
    }
}

impl<T: ByteWrite + Unpin + ?Sized> ByteWriteExt for T {}

/// A one-way in-memory byte pipe holding at most `capacity` bytes (`tokio::io::simplex`, without
/// tokio).
///
/// The reader sees the end once the writer is closed or dropped and the bytes are read; a write
/// after the reader is dropped fails with "broken pipe".
pub fn pipe(capacity: usize) -> (PipeWriter, PipeReader) {
    let shared = Arc::new(Mutex::new(PipeState {
        buffer: VecDeque::new(),
        capacity: capacity.max(1),
        write_closed: false,
        read_closed: false,
        reader: None,
        writer: None,
    }));
    (
        PipeWriter {
            shared: Arc::clone(&shared),
        },
        PipeReader { shared },
    )
}

/// Two connected in-memory byte streams (`tokio::io::duplex`, without tokio): what one end writes,
/// the other reads.
pub fn duplex(capacity: usize) -> (Duplex, Duplex) {
    let (left_writer, right_reader) = pipe(capacity);
    let (right_writer, left_reader) = pipe(capacity);
    (
        Duplex {
            reader: left_reader,
            writer: left_writer,
        },
        Duplex {
            reader: right_reader,
            writer: right_writer,
        },
    )
}

struct PipeState {
    buffer: VecDeque<u8>,
    capacity: usize,
    write_closed: bool,
    read_closed: bool,
    reader: Option<Waker>,
    writer: Option<Waker>,
}

/// The writing end of a [`pipe`].
pub struct PipeWriter {
    shared: Arc<Mutex<PipeState>>,
}

/// The reading end of a [`pipe`].
pub struct PipeReader {
    shared: Arc<Mutex<PipeState>>,
}

impl ByteRead for PipeReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let waker = {
            let mut state = self.shared.lock().expect("pipe poisoned");
            if state.buffer.is_empty() {
                if state.write_closed {
                    return Poll::Ready(Ok(0));
                }
                state.reader = Some(context.waker().clone());
                return Poll::Pending;
            }
            let n = buf.len().min(state.buffer.len());
            for (slot, byte) in buf.iter_mut().zip(state.buffer.drain(..n)) {
                *slot = byte;
            }
            (state.writer.take(), n)
        };
        if let Some(writer) = waker.0 {
            writer.wake();
        }
        Poll::Ready(Ok(waker.1))
    }
}

impl Drop for PipeReader {
    fn drop(&mut self) {
        let writer = {
            let mut state = self.shared.lock().expect("pipe poisoned");
            state.read_closed = true;
            state.buffer.clear();
            state.writer.take()
        };
        if let Some(writer) = writer {
            writer.wake();
        }
    }
}

impl PipeWriter {
    fn shut(&self) {
        let reader = {
            let mut state = self.shared.lock().expect("pipe poisoned");
            state.write_closed = true;
            state.reader.take()
        };
        if let Some(reader) = reader {
            reader.wake();
        }
    }
}

impl ByteWrite for PipeWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        let (reader, n) = {
            let mut state = self.shared.lock().expect("pipe poisoned");
            if state.read_closed {
                return Poll::Ready(Err(Error::Message("broken pipe".to_owned())));
            }
            if state.write_closed {
                return Poll::Ready(Err(Error::Message("write after close".to_owned())));
            }
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let room = state.capacity - state.buffer.len();
            if room == 0 {
                state.writer = Some(context.waker().clone());
                return Poll::Pending;
            }
            let n = room.min(buf.len());
            state.buffer.extend(&buf[..n]);
            (state.reader.take(), n)
        };
        if let Some(reader) = reader {
            reader.wake();
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<Result<()>> {
        self.shut();
        Poll::Ready(Ok(()))
    }
}

impl Drop for PipeWriter {
    fn drop(&mut self) {
        self.shut();
    }
}

/// One end of a [`duplex`].
pub struct Duplex {
    reader: PipeReader,
    writer: PipeWriter,
}

impl Duplex {
    /// Splits it into its reading and writing halves.
    pub fn split(self) -> (PipeReader, PipeWriter) {
        (self.reader, self.writer)
    }
}

impl ByteRead for Duplex {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.reader).poll_read(context, buf)
    }
}

impl ByteWrite for Duplex {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.writer).poll_write(context, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.writer).poll_flush(context)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.writer).poll_close(context)
    }
}

/// Adapts between these traits and tokio's: a tokio `AsyncRead`/`AsyncWrite` inside is a
/// [`ByteRead`]/[`ByteWrite`], and a [`ByteRead`]/[`ByteWrite`] inside is a tokio
/// `AsyncRead`/`AsyncWrite`. I/O errors become [`Error::Message`] with the error's text, and back.
#[cfg(feature = "tokio")]
#[derive(Debug)]
pub struct Compat<T>(pub T);

#[cfg(feature = "tokio")]
fn from_io(error: std::io::Error) -> Error {
    Error::Message(error.to_string())
}

#[cfg(feature = "tokio")]
fn to_io(error: Error) -> std::io::Error {
    std::io::Error::other(error.to_string())
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncRead + Send + Unpin> ByteRead for Compat<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<Result<usize>> {
        let mut buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(context, &mut buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(from_io(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl<T: tokio::io::AsyncWrite + Send + Unpin> ByteWrite for Compat<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.0)
            .poll_write(context, buf)
            .map_err(from_io)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_flush(context).map_err(from_io)
    }

    fn poll_close(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0)
            .poll_shutdown(context)
            .map_err(from_io)
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for Compat<BoxByteRead> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match self.0.as_mut().poll_read(context, unfilled) {
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(to_io(error))),
            Poll::Pending => Poll::Pending,
        }
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for Compat<BoxByteWrite> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.0.as_mut().poll_write(context, buf).map_err(to_io)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_flush(context).map_err(to_io)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        self.0.as_mut().poll_close(context).map_err(to_io)
    }
}
