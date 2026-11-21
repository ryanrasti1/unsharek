//! The async runtime the protocol core runs on: a pluggable [`Runtime`].
//!
//! The core needs three things from an executor:
//!
//! - **spawn**: each session's read loop, the continuations that give promises JavaScript's
//!   ordering, and the pumps and writers of byte streams run as background tasks;
//! - **a clock**: the stream flow controller measures round trips with [`Runtime::now`];
//! - **timers**: [`Runtime::sleep_until`], for embedders' deadlines (the core itself sets none).
//!
//! It also yields where JavaScript resumes in a later microtask: a yield wakes its own task once
//! and returns `Pending`, so the executor must queue a task that wakes itself behind the tasks
//! already ready (any FIFO run queue does).
//!
//! # Which runtime runs a task
//!
//! The core spawns onto the *current* runtime, found in this order:
//!
//! 1. the runtime [`enter`]ed on this thread (or, without std, on the program's one executor
//!    thread). Every task the core spawns on a [`Runtime`] is entered while it is polled, so work
//!    a session starts stays on the runtime it was created on. Create a session inside
//!    [`enter`] or [`scope`], or from a task spawned with [`spawn`];
//! 2. with the `tokio` feature, the ambient Tokio runtime (`Handle::try_current()`), which is
//!    today's behavior: a std user who never names a runtime gets tokio;
//! 3. the process-wide default set once with [`set_default`].
//!
//! # Threads
//!
//! With std the entered runtime is thread-local, and a [`Runtime`] may poll tasks on any number of
//! threads. Without std there are no thread-locals: the entered runtime is one global, so all of
//! the core's work must be polled on one thread at a time (a single-threaded executor; wakers may
//! still be called from anywhere). The core's locks are spin locks there, and no lock is held
//! across an `.await` or while a waker runs, so on one thread they never spin.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;

use crate::core::{Error, Result};
use crate::platform::{Arc, OnceLock};
#[cfg(not(feature = "std"))]
use crate::prelude::*;

/// A boxed background task, as handed to [`Runtime::spawn`].
pub type Task = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

/// An executor and clock the protocol core runs on.
///
/// `Send` and `Sync` are required because the core's values are shared with the multi-threaded
/// std build; a single-threaded executor satisfies them with a `Send` queue of tasks.
pub trait Runtime: Send + Sync + 'static {
    /// Polls `task` to completion in the background, waking it through real [`Waker`]s.
    ///
    /// A task that wakes itself and returns `Pending` must run again only after the tasks that
    /// were already ready (see the module docs).
    ///
    /// [`Waker`]: core::task::Waker
    fn spawn(&self, task: Task);

    /// Monotonic time since an arbitrary fixed origin.
    fn now(&self) -> Duration;

    /// A future that completes once [`now`](Self::now) reaches `deadline`.
    fn sleep_until(&self, deadline: Duration) -> Task;
}

/// The runtime a task is polled on, as the core finds it (see the module docs).
#[derive(Clone)]
enum Current {
    Runtime(Arc<dyn Runtime>),
    #[cfg(feature = "tokio")]
    Tokio(tokio::runtime::Handle),
}

#[cfg(feature = "std")]
std::thread_local! {
    static ENTERED: core::cell::RefCell<Option<Arc<dyn Runtime>>> =
        const { core::cell::RefCell::new(None) };
}

#[cfg(not(feature = "std"))]
static ENTERED: crate::platform::Mutex<Option<Arc<dyn Runtime>>> =
    crate::platform::Mutex::new(None);

fn replace_entered(runtime: Option<Arc<dyn Runtime>>) -> Option<Arc<dyn Runtime>> {
    #[cfg(feature = "std")]
    {
        ENTERED.with(|slot| slot.replace(runtime))
    }
    #[cfg(not(feature = "std"))]
    {
        core::mem::replace(&mut *ENTERED.lock().expect("never poisoned"), runtime)
    }
}

fn entered() -> Option<Arc<dyn Runtime>> {
    #[cfg(feature = "std")]
    {
        ENTERED.with(|slot| slot.borrow().clone())
    }
    #[cfg(not(feature = "std"))]
    {
        ENTERED.lock().expect("never poisoned").clone()
    }
}

static DEFAULT: OnceLock<Arc<dyn Runtime>> = OnceLock::new();

fn current() -> Option<Current> {
    if let Some(runtime) = entered() {
        return Some(Current::Runtime(runtime));
    }
    #[cfg(feature = "tokio")]
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        return Some(Current::Tokio(handle));
    }
    DEFAULT
        .get()
        .map(|runtime| Current::Runtime(Arc::clone(runtime)))
}

/// Sets the process-wide runtime used when none is entered (and, with `tokio`, outside Tokio).
/// Once: a second call fails and keeps the first.
pub fn set_default(runtime: Arc<dyn Runtime>) -> Result<()> {
    DEFAULT
        .set(runtime)
        .map_err(|_| Error::Message("a default capnweb runtime is already set".into()))
}

/// Runs `callback` with `runtime` as the current runtime, then restores the previous one.
pub fn enter<R>(runtime: &Arc<dyn Runtime>, callback: impl FnOnce() -> R) -> R {
    struct Restore(Option<Option<Arc<dyn Runtime>>>);
    impl Drop for Restore {
        fn drop(&mut self) {
            if let Some(previous) = self.0.take() {
                replace_entered(previous);
            }
        }
    }
    let _restore = Restore(Some(replace_entered(Some(Arc::clone(runtime)))));
    callback()
}

/// Wraps `future` so that `runtime` is entered (see [`enter`]) whenever it is polled.
pub fn scope<F: Future>(runtime: Arc<dyn Runtime>, future: F) -> Scoped<F> {
    Scoped {
        runtime,
        future: Box::pin(future),
    }
}

/// A future polled with its runtime entered; see [`scope`].
pub struct Scoped<F> {
    runtime: Arc<dyn Runtime>,
    future: Pin<Box<F>>,
}

impl<F: Future> Future for Scoped<F> {
    type Output = F::Output;

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<F::Output> {
        let this = &mut *self;
        enter(&this.runtime, || this.future.as_mut().poll(context))
    }
}

/// Spawns `future` on the current runtime, entered while it is polled. Panics if there is none,
/// as `tokio::spawn` does outside a runtime.
pub fn spawn(future: impl Future<Output = ()> + Send + 'static) {
    if try_spawn(future).is_err() {
        panic!("{NO_RUNTIME}");
    }
}

/// The message for work that needs a runtime when none is current.
#[cfg(feature = "tokio")]
pub(crate) const NO_RUNTIME: &str = "pending eager promise requires an active Tokio runtime";
/// The message for work that needs a runtime when none is current.
#[cfg(not(feature = "tokio"))]
pub(crate) const NO_RUNTIME: &str = "pending eager promise requires a capnweb runtime: enter one \
     with capnweb::runtime::enter() or set one with capnweb::runtime::set_default()";

/// Spawns `future` on the current runtime, or gives it back when there is none.
pub(crate) fn try_spawn<F: Future<Output = ()> + Send + 'static>(
    future: F,
) -> core::result::Result<(), F> {
    match current() {
        Some(Current::Runtime(runtime)) => {
            let task = scope(Arc::clone(&runtime), future);
            runtime.spawn(Box::pin(task));
            Ok(())
        }
        #[cfg(feature = "tokio")]
        Some(Current::Tokio(handle)) => {
            handle.spawn(future);
            Ok(())
        }
        None => Err(future),
    }
}

/// Runs `callback` in the background: on the current runtime if there is one, otherwise on a new
/// thread (std) or right away (no_std).
pub(crate) fn run_detached(callback: impl FnOnce() + Send + 'static) {
    let Err(future) = try_spawn(async move { callback() }) else {
        return;
    };
    // (polled once: it never waits, `callback` being synchronous)
    let run = move || {
        let mut future = core::pin::pin!(future);
        let _ = future
            .as_mut()
            .poll(&mut Context::from_waker(futures::task::noop_waker_ref()));
    };
    #[cfg(feature = "std")]
    std::thread::spawn(run);
    #[cfg(not(feature = "std"))]
    run();
}

/// The current runtime's clock; `Duration::ZERO` when there is no runtime.
pub fn now() -> Duration {
    match current() {
        Some(Current::Runtime(runtime)) => runtime.now(),
        #[cfg(feature = "tokio")]
        Some(Current::Tokio(_)) => TokioRuntime::clock(),
        None => Duration::ZERO,
    }
}

/// Completes once the current runtime's clock reaches `deadline`. Fails with no runtime.
pub async fn sleep_until(deadline: Duration) -> Result<()> {
    match current() {
        Some(Current::Runtime(runtime)) => {
            runtime.sleep_until(deadline).await;
            Ok(())
        }
        #[cfg(feature = "tokio")]
        Some(Current::Tokio(_)) => {
            tokio::time::sleep_until(TokioRuntime::instant(deadline)).await;
            Ok(())
        }
        None => Err(Error::Message(NO_RUNTIME.into())),
    }
}

/// Completes after `duration` on the current runtime's clock.
pub async fn sleep(duration: Duration) -> Result<()> {
    sleep_until(now() + duration).await
}

/// Lets other ready tasks run before resuming, like a JavaScript `await` of a settled promise.
pub(crate) async fn yield_now() {
    #[cfg(feature = "tokio")]
    if !matches!(current(), Some(Current::Runtime(_))) {
        tokio::task::yield_now().await;
        return;
    }
    YieldNow(false).await;
}

/// Wakes its own task once, so a FIFO executor resumes it after the tasks already ready.
struct YieldNow(bool);

impl Future for YieldNow {
    type Output = ();

    fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<()> {
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            context.waker().wake_by_ref();
            Poll::Pending
        }
    }
}

/// Tokio as a [`Runtime`]: spawns on a runtime handle and keeps time with its timers.
///
/// Sessions on Tokio don't need it (the ambient runtime is used when none is entered); it is the
/// abstraction's Tokio implementation, for code written against [`Runtime`].
#[cfg(feature = "tokio")]
#[derive(Clone, Debug)]
pub struct TokioRuntime {
    handle: tokio::runtime::Handle,
}

#[cfg(feature = "tokio")]
impl TokioRuntime {
    /// Spawns on `handle`.
    pub fn new(handle: tokio::runtime::Handle) -> Self {
        Self { handle }
    }

    /// Spawns on the ambient Tokio runtime. Panics outside one, as `Handle::current()` does.
    pub fn current() -> Self {
        Self::new(tokio::runtime::Handle::current())
    }

    fn origin() -> std::time::Instant {
        static ORIGIN: OnceLock<std::time::Instant> = OnceLock::new();
        *ORIGIN.get_or_init(std::time::Instant::now)
    }

    fn clock() -> Duration {
        Self::origin().elapsed()
    }

    fn instant(deadline: Duration) -> tokio::time::Instant {
        tokio::time::Instant::from_std(Self::origin() + deadline)
    }
}

#[cfg(feature = "tokio")]
impl Runtime for TokioRuntime {
    fn spawn(&self, task: Task) {
        self.handle.spawn(task);
    }

    fn now(&self) -> Duration {
        Self::clock()
    }

    fn sleep_until(&self, deadline: Duration) -> Task {
        let _guard = self.handle.enter();
        Box::pin(tokio::time::sleep_until(Self::instant(deadline)))
    }
}
