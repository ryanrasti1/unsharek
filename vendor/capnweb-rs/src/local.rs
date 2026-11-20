//! A single-threaded executor with a virtual clock (feature `local-runtime`).
//!
//! [`LocalRuntime`] is the smallest [`Runtime`] the protocol core runs on, with or without std:
//! a FIFO run queue, real wakers, and timers on a virtual clock. It is for tests (runs are
//! deterministic and bounded: [`LocalRuntime::run_until`] stops once nothing can progress) and a
//! reference for embedders, whose executor does the same with its own I/O readiness and clock.
//!
//! The clock starts at zero, moves forward one [`tick`](LocalRuntime::with_tick) per task poll
//! (so round trips measured by stream flow control are not zero), and jumps to the next timer's
//! deadline when nothing else is ready.

use alloc::collections::{BTreeMap, VecDeque};
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, Ordering};
use core::task::{Context, Poll, Waker};
use core::time::Duration;

use futures::task::{ArcWake, waker, waker_ref};

use crate::platform::{Arc, Mutex};
#[cfg(not(feature = "std"))]
use crate::prelude::*;
use crate::runtime::{self, Runtime, Task};

/// A single-threaded, run-to-completion executor with a virtual clock; see the module docs.
///
/// Clones share the executor. Only the thread calling [`run_until`](Self::run_until),
/// [`block_on`](Self::block_on) or [`run_until_stalled`](Self::run_until_stalled) polls; tasks
/// may be spawned and woken from anywhere.
#[derive(Clone)]
pub struct LocalRuntime {
    shared: Arc<Shared>,
}

struct Shared {
    ready: Mutex<VecDeque<Arc<LocalTask>>>,
    clock: Mutex<Clock>,
}

struct Clock {
    now: Duration,
    tick: Duration,
    next_timer: u64,
    timers: BTreeMap<(Duration, u64), Waker>,
}

struct LocalTask {
    future: Mutex<Option<Task>>,
    queued: AtomicBool,
    shared: Arc<Shared>,
}

impl ArcWake for LocalTask {
    fn wake_by_ref(task: &Arc<Self>) {
        if !task.queued.swap(true, Ordering::AcqRel) {
            task.shared
                .ready
                .lock()
                .expect("executor queue poisoned")
                .push_back(Arc::clone(task));
        }
    }
}

impl Default for LocalRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl LocalRuntime {
    /// An executor with no tasks, its clock at zero, ticking one microsecond per poll.
    pub fn new() -> Self {
        Self::with_tick(Duration::from_micros(1))
    }

    /// As [`new`](Self::new), with the clock moving `tick` per task poll.
    pub fn with_tick(tick: Duration) -> Self {
        Self {
            shared: Arc::new(Shared {
                ready: Mutex::new(VecDeque::new()),
                clock: Mutex::new(Clock {
                    now: Duration::ZERO,
                    tick,
                    next_timer: 0,
                    timers: BTreeMap::new(),
                }),
            }),
        }
    }

    /// This executor as the protocol core's [`Runtime`].
    pub fn handle(&self) -> Arc<dyn Runtime> {
        Arc::new(self.clone())
    }

    /// Queues `future` to run, with this runtime entered while it is polled.
    pub fn spawn(&self, future: impl Future<Output = ()> + Send + 'static) {
        Runtime::spawn(self, Box::pin(runtime::scope(self.handle(), future)));
    }

    /// Moves the clock forward by `duration`, waking the timers that came due.
    pub fn advance(&self, duration: Duration) {
        let due = {
            let mut clock = self.shared.clock.lock().expect("clock poisoned");
            clock.now += duration;
            clock.take_due()
        };
        for waker in due {
            waker.wake();
        }
    }

    /// The next timer's deadline, if a timer is pending.
    pub fn next_deadline(&self) -> Option<Duration> {
        let clock = self.shared.clock.lock().expect("clock poisoned");
        clock.timers.keys().next().map(|(deadline, _)| *deadline)
    }

    /// Polls ready tasks until none is ready, and returns how many polls ran.
    pub fn run_until_stalled(&self) -> usize {
        let mut polls = 0;
        loop {
            let next = self
                .shared
                .ready
                .lock()
                .expect("executor queue poisoned")
                .pop_front();
            let Some(task) = next else {
                return polls;
            };
            polls += 1;
            task.queued.store(false, Ordering::Release);
            // (taken out, so no lock is held while the task runs and wakes others)
            let future = task.future.lock().expect("task poisoned").take();
            let Some(mut future) = future else {
                continue;
            };
            let waker = waker_ref(&task);
            let mut context = Context::from_waker(&waker);
            let pending = future.as_mut().poll(&mut context).is_pending();
            if pending {
                *task.future.lock().expect("task poisoned") = Some(future);
            } else {
                drop(future);
            }
            let tick = self.shared.clock.lock().expect("clock poisoned").tick;
            self.advance(tick);
        }
    }

    /// Runs tasks until `future` completes, with this runtime entered. When nothing is ready and
    /// no timer is pending, calls `idle` (a wait for outside events, such as a `ppoll`), which
    /// returns once one may have woken a task.
    pub fn block_on<F: Future>(&self, future: F, mut idle: impl FnMut()) -> F::Output {
        self.drive(future, || {
            idle();
            true
        })
        .expect("drive stops only when idle returns false")
    }

    /// Runs tasks until `future` completes, with this runtime entered, or returns `None` once
    /// nothing can make progress: no task is ready and no timer is pending. Suits sessions whose
    /// every peer runs on this executor, such as two ends of an in-memory pipe.
    pub fn run_until<F: Future>(&self, future: F) -> Option<F::Output> {
        self.drive(future, || false)
    }

    /// Polls `future` whenever it is woken, and the ready tasks in between. When nothing is ready,
    /// jumps the clock to the next timer; with no timer, calls `idle` and stops with `None` if it
    /// returns false.
    fn drive<F: Future>(&self, future: F, mut idle: impl FnMut() -> bool) -> Option<F::Output> {
        let handle = self.handle();
        let mut future = core::pin::pin!(future);
        let flag = Arc::new(WakeFlag(AtomicBool::new(true)));
        let main_waker: Waker = waker(Arc::clone(&flag));
        loop {
            if flag.0.swap(false, Ordering::AcqRel) {
                let mut context = Context::from_waker(&main_waker);
                let poll = runtime::enter(&handle, || future.as_mut().poll(&mut context));
                if let Poll::Ready(output) = poll {
                    return Some(output);
                }
            }
            if self.run_until_stalled() > 0 || flag.0.load(Ordering::Acquire) {
                continue;
            }
            if let Some(deadline) = self.next_deadline() {
                let now = Runtime::now(self);
                self.advance(deadline.saturating_sub(now));
                continue;
            }
            if !idle() {
                return None;
            }
        }
    }
}

impl Clock {
    fn take_due(&mut self) -> Vec<Waker> {
        let mut due = Vec::new();
        while let Some(entry) = self.timers.first_entry() {
            if entry.key().0 > self.now {
                break;
            }
            due.push(entry.remove());
        }
        due
    }
}

impl Runtime for LocalRuntime {
    fn spawn(&self, task: Task) {
        let task = Arc::new(LocalTask {
            future: Mutex::new(Some(task)),
            queued: AtomicBool::new(false),
            shared: Arc::clone(&self.shared),
        });
        ArcWake::wake_by_ref(&task);
    }

    fn now(&self) -> Duration {
        self.shared.clock.lock().expect("clock poisoned").now
    }

    fn sleep_until(&self, deadline: Duration) -> Task {
        Box::pin(Sleep {
            shared: Arc::clone(&self.shared),
            deadline,
            key: None,
        })
    }
}

/// A timer on the virtual clock.
struct Sleep {
    shared: Arc<Shared>,
    deadline: Duration,
    key: Option<u64>,
}

impl Future for Sleep {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        let this = &mut *self;
        let mut clock = this.shared.clock.lock().expect("clock poisoned");
        if clock.now >= this.deadline {
            if let Some(key) = this.key.take() {
                clock.timers.remove(&(this.deadline, key));
            }
            return Poll::Ready(());
        }
        let key = *this.key.get_or_insert_with(|| {
            clock.next_timer += 1;
            clock.next_timer
        });
        clock
            .timers
            .insert((this.deadline, key), context.waker().clone());
        Poll::Pending
    }
}

impl Drop for Sleep {
    fn drop(&mut self) {
        if let Some(key) = self.key.take() {
            self.shared
                .clock
                .lock()
                .expect("clock poisoned")
                .timers
                .remove(&(self.deadline, key));
        }
    }
}

struct WakeFlag(AtomicBool);

impl ArcWake for WakeFlag {
    fn wake_by_ref(flag: &Arc<Self>) {
        flag.0.store(true, Ordering::Release);
    }
}
