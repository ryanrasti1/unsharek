//! Small async primitives on `core::task` + `alloc`, for the parts of the core that wait on each
//! other (streams, the framed transport). Each is a [`Mutex`] around its state plus the wakers of
//! the tasks waiting on it: no executor is assumed, wakers may be called from any thread, and no
//! lock is held while a waker runs.

use alloc::collections::{BTreeMap, VecDeque};
use core::future::Future;
use core::ops::{Deref, DerefMut};
use core::pin::Pin;
use core::task::{Context, Poll, Waker};

use crate::platform::{Arc, Mutex};
#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// Wakers keyed by the waiting future, so a dropped waiter takes its waker with it.
#[derive(Default)]
struct Waiters {
    next: u64,
    wakers: BTreeMap<u64, Waker>,
}

impl Waiters {
    /// Registers (or refreshes) the waker for `slot`, allocating a key on first use.
    fn register(&mut self, slot: &mut Option<u64>, waker: &Waker) {
        let key = *slot.get_or_insert_with(|| {
            self.next += 1;
            self.next
        });
        match self.wakers.get_mut(&key) {
            Some(existing) if existing.will_wake(waker) => {}
            Some(existing) => existing.clone_from(waker),
            None => {
                self.wakers.insert(key, waker.clone());
            }
        }
    }

    fn remove(&mut self, slot: Option<u64>) {
        if let Some(key) = slot {
            self.wakers.remove(&key);
        }
    }

    fn take_all(&mut self) -> Vec<Waker> {
        core::mem::take(&mut self.wakers).into_values().collect()
    }
}

/// An async mutex: one holder at a time, the others wait without blocking the executor.
///
/// Waiters aren't served in order (an unlock wakes them all to retry); the transports that use it
/// keep their order themselves (`send_queue.rs`).
pub(crate) struct AsyncMutex<T> {
    state: Mutex<AsyncMutexState<T>>,
}

struct AsyncMutexState<T> {
    /// `None` while a guard holds it.
    value: Option<T>,
    waiters: Waiters,
}

impl<T> AsyncMutex<T> {
    pub(crate) fn new(value: T) -> Self {
        Self {
            state: Mutex::new(AsyncMutexState {
                value: Some(value),
                waiters: Waiters::default(),
            }),
        }
    }

    /// Waits until the value is free and holds it until the guard drops.
    pub(crate) fn lock(&self) -> AsyncMutexLock<'_, T> {
        AsyncMutexLock {
            mutex: self,
            slot: None,
        }
    }
}

/// The future [`AsyncMutex::lock`] returns.
pub(crate) struct AsyncMutexLock<'a, T> {
    mutex: &'a AsyncMutex<T>,
    slot: Option<u64>,
}

impl<'a, T> Future for AsyncMutexLock<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
        let this = &mut *self;
        let mut state = this.mutex.state.lock().expect("async mutex poisoned");
        if let Some(value) = state.value.take() {
            state.waiters.remove(this.slot.take());
            return Poll::Ready(AsyncMutexGuard {
                mutex: this.mutex,
                value: Some(value),
            });
        }
        state.waiters.register(&mut this.slot, context.waker());
        Poll::Pending
    }
}

impl<T> Drop for AsyncMutexLock<'_, T> {
    fn drop(&mut self) {
        if self.slot.is_some() {
            self.mutex
                .state
                .lock()
                .expect("async mutex poisoned")
                .waiters
                .remove(self.slot.take());
        }
    }
}

/// Holds an [`AsyncMutex`]'s value; dropping it frees the value and wakes the waiters.
pub(crate) struct AsyncMutexGuard<'a, T> {
    mutex: &'a AsyncMutex<T>,
    value: Option<T>,
}

impl<T> Deref for AsyncMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.value.as_ref().expect("guard holds the value")
    }
}

impl<T> DerefMut for AsyncMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        self.value.as_mut().expect("guard holds the value")
    }
}

impl<T> Drop for AsyncMutexGuard<'_, T> {
    fn drop(&mut self) {
        let wakers = {
            let mut state = self.mutex.state.lock().expect("async mutex poisoned");
            state.value = self.value.take();
            state.waiters.take_all()
        };
        for waker in wakers {
            waker.wake();
        }
    }
}

/// A value set once and seen by every waiter: a transport's abort reason.
pub(crate) struct Signal<T> {
    state: Mutex<SignalState<T>>,
}

struct SignalState<T> {
    value: Option<T>,
    waiters: Waiters,
}

impl<T: Clone> Signal<T> {
    pub(crate) fn new() -> Self {
        Self {
            state: Mutex::new(SignalState {
                value: None,
                waiters: Waiters::default(),
            }),
        }
    }

    /// Sets the value unless it is already set, and wakes every waiter. Returns whether it set it.
    pub(crate) fn set(&self, value: T) -> bool {
        let wakers = {
            let mut state = self.state.lock().expect("signal poisoned");
            if state.value.is_some() {
                return false;
            }
            state.value = Some(value);
            state.waiters.take_all()
        };
        for waker in wakers {
            waker.wake();
        }
        true
    }

    pub(crate) fn get(&self) -> Option<T> {
        self.state.lock().expect("signal poisoned").value.clone()
    }

    /// Completes with the value once it is set.
    pub(crate) fn wait(&self) -> SignalWait<'_, T> {
        SignalWait {
            signal: self,
            slot: None,
        }
    }
}

/// The future [`Signal::wait`] returns.
pub(crate) struct SignalWait<'a, T> {
    signal: &'a Signal<T>,
    slot: Option<u64>,
}

impl<T: Clone> Future for SignalWait<'_, T> {
    type Output = T;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<T> {
        let this = &mut *self;
        let mut state = this.signal.state.lock().expect("signal poisoned");
        if let Some(value) = state.value.clone() {
            state.waiters.remove(this.slot.take());
            return Poll::Ready(value);
        }
        state.waiters.register(&mut this.slot, context.waker());
        Poll::Pending
    }
}

impl<T> Drop for SignalWait<'_, T> {
    fn drop(&mut self) {
        if self.slot.is_some() {
            self.signal
                .state
                .lock()
                .expect("signal poisoned")
                .waiters
                .remove(self.slot.take());
        }
    }
}

/// Polls `abort` first, then `work`: the result of whichever is ready, `abort`'s as an `Err`.
pub(crate) async fn abortable<T, E: Clone>(
    abort: &Signal<E>,
    work: impl Future<Output = Result<T, E>>,
) -> Result<T, E> {
    let mut abort = core::pin::pin!(abort.wait());
    let mut work = core::pin::pin!(work);
    core::future::poll_fn(move |context| {
        if let Poll::Ready(reason) = abort.as_mut().poll(context) {
            return Poll::Ready(Err(reason));
        }
        work.as_mut().poll(context)
    })
    .await
}

/// An unbounded single-consumer channel (`tokio::sync::mpsc::unbounded_channel` without tokio).
pub(crate) fn unbounded<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
    let shared = Arc::new(Mutex::new(Channel {
        queue: VecDeque::new(),
        receiver: None,
        senders: 1,
        receiver_alive: true,
    }));
    (
        UnboundedSender {
            shared: Arc::clone(&shared),
        },
        UnboundedReceiver { shared },
    )
}

struct Channel<T> {
    queue: VecDeque<T>,
    receiver: Option<Waker>,
    senders: usize,
    receiver_alive: bool,
}

/// The sending half of [`unbounded`].
pub(crate) struct UnboundedSender<T> {
    shared: Arc<Mutex<Channel<T>>>,
}

impl<T> UnboundedSender<T> {
    /// Queues `value`; `Err` gives it back if the receiver is gone.
    pub(crate) fn send(&self, value: T) -> Result<(), T> {
        let waker = {
            let mut channel = self.shared.lock().expect("channel poisoned");
            if !channel.receiver_alive {
                return Err(value);
            }
            channel.queue.push_back(value);
            channel.receiver.take()
        };
        if let Some(waker) = waker {
            waker.wake();
        }
        Ok(())
    }
}

impl<T> Clone for UnboundedSender<T> {
    fn clone(&self) -> Self {
        self.shared.lock().expect("channel poisoned").senders += 1;
        Self {
            shared: Arc::clone(&self.shared),
        }
    }
}

impl<T> Drop for UnboundedSender<T> {
    fn drop(&mut self) {
        let waker = {
            let mut channel = self.shared.lock().expect("channel poisoned");
            channel.senders -= 1;
            if channel.senders == 0 {
                channel.receiver.take()
            } else {
                None
            }
        };
        if let Some(waker) = waker {
            waker.wake();
        }
    }
}

/// The receiving half of [`unbounded`].
pub(crate) struct UnboundedReceiver<T> {
    shared: Arc<Mutex<Channel<T>>>,
}

impl<T> UnboundedReceiver<T> {
    /// The next value, or `None` once every sender is gone and the queue is empty.
    pub(crate) async fn recv(&mut self) -> Option<T> {
        core::future::poll_fn(|context| {
            let mut channel = self.shared.lock().expect("channel poisoned");
            if let Some(value) = channel.queue.pop_front() {
                return Poll::Ready(Some(value));
            }
            if channel.senders == 0 {
                return Poll::Ready(None);
            }
            channel.receiver = Some(context.waker().clone());
            Poll::Pending
        })
        .await
    }
}

impl<T> Drop for UnboundedReceiver<T> {
    fn drop(&mut self) {
        // (the queued values dropped outside the lock: they may hold hooks that send on drop)
        let queue = {
            let mut channel = self.shared.lock().expect("channel poisoned");
            channel.receiver_alive = false;
            core::mem::take(&mut channel.queue)
        };
        drop(queue);
    }
}
