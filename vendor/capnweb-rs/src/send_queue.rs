//! Rust-only: keeps a stream transport's frames in the order `send()` was called.
//!
//! `AnyRpcTransport::send()` is synchronous but a stream write is not, so a transport returns
//! `TransportSend::Pending`. Pending futures are not guaranteed to reach a shared writer lock in
//! the order they were created (Tokio's cooperative budget can make a first poll return `Pending`
//! before it queues for the lock, and the retry runs on whichever worker picks it up). The RPC
//! session relies on the wire order matching the `send()` order (a push's import ID is its
//! position), so `send()` enqueues its frame here synchronously and whichever future holds the
//! writer writes every queued frame in order.

use alloc::collections::VecDeque;

use crate::core::{Error, Result};
use crate::platform::{Arc, Mutex};
#[cfg(not(feature = "std"))]
use crate::prelude::*;

pub(crate) struct SendQueue<F> {
    state: Mutex<QueueState<F>>,
}

struct QueueState<F> {
    frames: VecDeque<(u64, F)>,
    next_sequence: u64,
    written_through: u64,
    broken: Option<Error>,
}

impl<F> SendQueue<F> {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(QueueState {
                frames: VecDeque::new(),
                next_sequence: 1,
                written_through: 0,
                broken: None,
            }),
        })
    }

    fn lock(&self) -> impl core::ops::DerefMut<Target = QueueState<F>> + '_ {
        self.state.lock().expect("send queue mutex poisoned")
    }

    /// Queues a frame; returns its sequence number for `finish()`.
    pub(crate) fn push(&self, frame: F) -> u64 {
        let mut state = self.lock();
        let sequence = state.next_sequence;
        state.next_sequence += 1;
        state.frames.push_back((sequence, frame));
        sequence
    }

    /// Takes the oldest queued frame. Call only while holding the transport's writer, and write
    /// the frame before calling `pop()` again. Dropping the returned frame without `written()`
    /// (a failed or cancelled write) breaks the queue, since the stream may hold a partial frame.
    pub(crate) fn pop(self: &Arc<Self>) -> Result<Option<PoppedFrame<F>>> {
        let mut state = self.lock();
        if let Some(error) = &state.broken {
            return Err(error.clone());
        }
        Ok(state
            .frames
            .pop_front()
            .map(|(sequence, frame)| PoppedFrame {
                queue: Arc::clone(self),
                sequence,
                frame: Some(frame),
            }))
    }

    /// Reports whether the frame with `sequence` was written, after the caller drained the queue.
    pub(crate) fn finish(&self, sequence: u64) -> Result<()> {
        let state = self.lock();
        if state.written_through >= sequence {
            Ok(())
        } else {
            Err(state
                .broken
                .clone()
                .unwrap_or_else(|| Error::Message("transport frame was not written".to_owned())))
        }
    }
}

pub(crate) struct PoppedFrame<F> {
    queue: Arc<SendQueue<F>>,
    sequence: u64,
    frame: Option<F>,
}

impl<F> PoppedFrame<F> {
    pub(crate) fn frame(&self) -> &F {
        self.frame
            .as_ref()
            .expect("popped frame present until written")
    }

    pub(crate) fn written(mut self) {
        self.frame = None;
        self.queue.lock().written_through = self.sequence;
    }
}

impl<F> Drop for PoppedFrame<F> {
    fn drop(&mut self) {
        if self.frame.is_some() {
            let mut state = self.queue.lock();
            state.broken.get_or_insert_with(|| {
                Error::Message("an earlier transport frame failed to send".to_owned())
            });
        }
    }
}
