//! The std facilities the protocol core uses, each with a `no_std` + `alloc` form.
//!
//! With the `std` feature every item here is the std item itself, so the std build behaves as it
//! did before the split. Without it:
//!
//! - `HashMap` is hashbrown's.
//! - `Mutex` is a spin lock with `std::sync::Mutex`'s `lock()` signature; it is never poisoned.
//! - `OnceLock` is `spin::Once` behind `std::sync::OnceLock`'s `set()`/`get()`.
//! - A [`ContextLocal`] is one global instead of one per thread: the `no_std` core runs on one
//!   executor thread at a time (see `runtime.md`).
//! - [`catch_unwind`] calls its closure directly: without std a panic can't be caught, and the
//!   embedder's panic handler decides what happens.
//! - Deep JSON is bounded by serde_json's recursion limit instead of a growing stack.

use core::future::Future;

pub(crate) use alloc::sync::{Arc, Weak};

#[cfg(not(feature = "std"))]
pub(crate) use hashbrown::HashMap;
#[cfg(feature = "std")]
pub(crate) use std::collections::HashMap;

#[cfg(feature = "std")]
pub(crate) use std::sync::{Mutex, OnceLock};

#[cfg(not(feature = "std"))]
pub(crate) use spin_lock::{Mutex, OnceLock};

#[cfg(not(feature = "std"))]
mod spin_lock {
    use core::convert::Infallible;

    /// A spin lock with `std::sync::Mutex`'s `lock()` signature, so call sites are shared.
    ///
    /// No guard is held across an `.await` (std's guard isn't `Send`, so the shared code can't),
    /// so on one executor thread it never spins; locking a mutex the same thread holds deadlocks,
    /// as it does with std.
    #[derive(Default)]
    pub(crate) struct Mutex<T: ?Sized>(spin::Mutex<T>);

    impl<T> Mutex<T> {
        pub(crate) const fn new(value: T) -> Self {
            Self(spin::Mutex::new(value))
        }
    }

    impl<T: ?Sized> Mutex<T> {
        /// Spins until the lock is free. A spin lock is never poisoned, so this never fails.
        pub(crate) fn lock(&self) -> Result<spin::MutexGuard<'_, T>, Infallible> {
            Ok(self.0.lock())
        }
    }

    impl<T: ?Sized + core::fmt::Debug> core::fmt::Debug for Mutex<T> {
        fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            formatter.write_str("Mutex")
        }
    }

    /// `std::sync::OnceLock`'s `set()` and `get()` over `spin::Once`.
    pub(crate) struct OnceLock<T>(spin::Once<T>);

    impl<T> OnceLock<T> {
        pub(crate) const fn new() -> Self {
            Self(spin::Once::new())
        }

        pub(crate) fn set(&self, value: T) -> Result<(), T> {
            let mut value = Some(value);
            self.0
                .call_once(|| value.take().expect("value is taken once"));
            match value {
                None => Ok(()),
                Some(value) => Err(value),
            }
        }

        pub(crate) fn get(&self) -> Option<&T> {
            self.0.get()
        }
    }
}

/// A value scoped to the current thread (std) or to the program (no_std), read by cloning.
///
/// Declare one with [`context_local!`]. Reads clone the value out, so nothing stays borrowed while
/// the caller runs code that might replace it.
#[cfg(feature = "std")]
pub(crate) struct ContextLocal<T: 'static>(&'static std::thread::LocalKey<core::cell::RefCell<T>>);

#[cfg(feature = "std")]
impl<T: Clone> ContextLocal<T> {
    pub(crate) const fn new(key: &'static std::thread::LocalKey<core::cell::RefCell<T>>) -> Self {
        Self(key)
    }

    pub(crate) fn get(&'static self) -> T {
        self.0.with(|value| value.borrow().clone())
    }

    pub(crate) fn replace(&'static self, value: T) -> T {
        self.0.with(|slot| slot.replace(value))
    }
}

/// A value scoped to the current thread (std) or to the program (no_std), read by cloning.
#[cfg(not(feature = "std"))]
pub(crate) struct ContextLocal<T>(Mutex<T>);

#[cfg(not(feature = "std"))]
impl<T: Clone> ContextLocal<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(Mutex::new(value))
    }

    pub(crate) fn get(&'static self) -> T {
        self.0.lock().expect("never poisoned").clone()
    }

    pub(crate) fn replace(&'static self, value: T) -> T {
        core::mem::replace(&mut *self.0.lock().expect("never poisoned"), value)
    }
}

/// Declares a [`ContextLocal`] with a `const` initial value.
macro_rules! context_local {
    (static $name:ident: $ty:ty = $init:expr;) => {
        #[cfg(feature = "std")]
        static $name: $crate::platform::ContextLocal<$ty> = {
            std::thread_local! {
                static KEY: ::core::cell::RefCell<$ty> = const { ::core::cell::RefCell::new($init) };
            }
            $crate::platform::ContextLocal::new(&KEY)
        };
        #[cfg(not(feature = "std"))]
        static $name: $crate::platform::ContextLocal<$ty> =
            $crate::platform::ContextLocal::new($init);
    };
}
pub(crate) use context_local;

/// Runs `callback`, turning a panic into `Err` where panics can be caught (std only).
#[cfg(feature = "std")]
pub(crate) fn catch_unwind<R>(callback: impl FnOnce() -> R) -> Result<R, ()> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(callback)).map_err(drop)
}

/// Runs `callback`. Without std a panic can't be caught; the embedder's panic handler runs.
#[cfg(not(feature = "std"))]
pub(crate) fn catch_unwind<R>(callback: impl FnOnce() -> R) -> Result<R, ()> {
    Ok(callback())
}

/// Awaits `future`, turning a panic into `Err` where panics can be caught (std only).
pub(crate) fn catch_unwind_future<T>(
    future: impl Future<Output = T>,
) -> impl Future<Output = Result<T, ()>> {
    use futures::FutureExt as _;
    #[cfg(feature = "std")]
    {
        std::panic::AssertUnwindSafe(future)
            .catch_unwind()
            .map(|result| result.map_err(drop))
    }
    #[cfg(not(feature = "std"))]
    {
        future.map(Ok)
    }
}

/// `value.fract()`, which `core` lacks.
pub(crate) fn fract(value: f64) -> f64 {
    #[cfg(feature = "std")]
    {
        value.fract()
    }
    #[cfg(not(feature = "std"))]
    {
        value - libm::trunc(value)
    }
}

/// Runs `callback`, growing the stack first if less than `red_zone` bytes remain (the
/// `stack-growth` feature).
///
/// Without it the stack doesn't grow (that maps a segment: `mmap`, `mprotect`, `munmap`), so deep
/// values are bounded by [`parse_json_value`]'s fixed depth limit and `RpcLimits::max_depth`
/// instead.
pub(crate) fn maybe_grow<R>(
    red_zone: usize,
    stack_segment: usize,
    callback: impl FnOnce() -> R,
) -> R {
    #[cfg(feature = "stack-growth")]
    {
        stacker::maybe_grow(red_zone, stack_segment, callback)
    }
    #[cfg(not(feature = "stack-growth"))]
    {
        let _ = (red_zone, stack_segment);
        callback()
    }
}

/// The deepest JSON nesting parsed without the `stack-growth` feature (and so without std):
/// serde_json's built-in recursion limit. A deeper message fails to parse, with an error.
///
/// With `stack-growth` there is no limit here; JSON is parsed with `serde_stacker`, which grows
/// the stack, and depth is bounded later with [`crate::RpcLimits::max_depth`].
#[cfg(not(feature = "stack-growth"))]
pub const MAX_JSON_DEPTH: usize = 128;

/// Reads one JSON value from `deserializer`, at any depth (`stack-growth`) or up to
/// [`MAX_JSON_DEPTH`] (without it).
pub(crate) fn parse_json_value<'de, R: serde_json::de::Read<'de>>(
    deserializer: &mut serde_json::Deserializer<R>,
) -> serde_json::Result<serde_json::Value> {
    #[cfg(feature = "stack-growth")]
    {
        deserializer.disable_recursion_limit();
        serde::Deserialize::deserialize(serde_stacker::Deserializer::new(deserializer))
    }
    #[cfg(not(feature = "stack-growth"))]
    {
        serde::Deserialize::deserialize(deserializer)
    }
}
