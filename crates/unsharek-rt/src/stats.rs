//! Measurement counters, for bench/PERF.md: where a sandboxed program's time goes. Built with
//! the cargo feature `stats` (`unsharek/stats`; `bench/run --variant stats` and
//! `cargo xtask vs-native --variant stats` build it). Without it every call here is empty, its guard
//! a zero-sized value without a destructor: the shipped binary has no trace of them.
//!
//! Each event is one line where it happens: `let _t = stats::timed(K::Exec, 0);` times the rest of
//! the scope, [`count`] and [`bytes`] add to a counter, [`syscall`], [`contended`] and
//! [`wait_token`] are the dispatcher's and the CPU token's accounts, and [`Owner`] (the token's
//! owner word) times each holder. Counts and TSC cycles in relaxed atomics, in the shared section
//! (fork mode's processes add to the same counters); [`report`] prints them to stderr at the
//! sandbox's end as `UNSHAREK_STATS` lines, which bench/build_bench.py summarises.
//!
//! What is counted:
//! - per trapped syscall number: calls, and cycles in the dispatcher (threaded and fork mode:
//!   from before taking the token to after giving it back, so including any block inside it, e.g.
//!   a futex wait or a pipe read), and of those the cycles waiting for the token;
//! - the CPU token: acquires (free, already held, contended, from the idler), cycles each holder
//!   held it (program slots, the kernel idler), the idler's ppoll while holding it, hand-offs
//!   (eventfd writes), eventfd waits and their latency from being made the owner to running;
//! - inside LKL (`lkl_syscall`, inclusive of blocks), scheduler context switches;
//! - arena: high-water clearing and mremap copies (bytes and cycles), file-mapping copies; exec's
//!   load; host forks (the parent's clone).

use core::sync::atomic::{AtomicU32, Ordering};

#[cfg(feature = "stats")]
mod on {
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

    pub const NR: usize = 512;
    pub struct Pair {
        pub n: AtomicU64,
        pub cyc: AtomicU64,
    }
    impl Pair {
        pub const fn new() -> Self {
            Pair { n: AtomicU64::new(0), cyc: AtomicU64::new(0) }
        }
        #[inline]
        pub fn add(&self, cyc: u64) {
            self.n.fetch_add(1, Relaxed);
            self.cyc.fetch_add(cyc, Relaxed);
        }
    }
    #[unsafe(link_section = "unsharek_shared")]
    pub static SYS: [Pair; NR] = [const { Pair::new() }; NR];
    #[unsafe(link_section = "unsharek_shared")]
    pub static SYS_TOKEN_WAIT: [AtomicU64; NR] = [const { AtomicU64::new(0) }; NR];
    #[unsafe(link_section = "unsharek_shared")]
    pub static C: [Pair; super::NAMES.len()] = [const { Pair::new() }; super::NAMES.len()];
    #[unsafe(link_section = "unsharek_shared")]
    pub static BYTES: [AtomicU64; super::NAMES.len()] = [const { AtomicU64::new(0) }; super::NAMES.len()];
    #[unsafe(link_section = "unsharek_shared")]
    pub static T0: AtomicU64 = AtomicU64::new(0);
    #[unsafe(link_section = "unsharek_shared")]
    pub static NS0: AtomicU64 = AtomicU64::new(0);
    /// When the token last changed hands (under par's spinlock).
    #[unsafe(link_section = "unsharek_shared")]
    pub static OWNER_SINCE: AtomicU64 = AtomicU64::new(0);
    /// The last contended acquire's wait (cycles), for the dispatcher's per-call account: set
    /// holding the token, read by the same thread before giving it back.
    #[unsafe(link_section = "unsharek_shared")]
    pub static LAST_WAIT: AtomicU64 = AtomicU64::new(0);
}

/// Counter kinds ([`count`], [`bytes`], [`timed`]).
#[derive(Clone, Copy)]
#[repr(usize)]
pub enum K {
    /// acquire: the token was free.
    AcqFree,
    /// acquire: already held by the caller.
    AcqHeld,
    /// acquire: queued behind another holder (cycles: the wait).
    AcqContended,
    /// ... of which the holder was the kernel/idler thread.
    AcqFromKernel,
    /// The token held by a program slot (cycles: held time).
    HeldProgram,
    /// The token held by the kernel thread (including its ppoll holding it, `KernelPpoll`).
    HeldKernel,
    /// The kernel thread's ppoll to a deadline, token held (cycles).
    KernelPpoll,
    /// Hand-offs: eventfd writes.
    Poke,
    /// Waits for the token that blocked (cycles).
    WaitToken,
    /// A program slot's scheduler loop giving the token away to wait (nothing runnable here).
    SchedIdle,
    /// lkl_syscall calls (cycles inclusive).
    Lkl,
    /// Scheduler context switches.
    Switch,
    /// High-water clearing (bytes written; cycles in zero_nonzero incl. scanning).
    Zero,
    /// mremap's copy (bytes; cycles).
    MremapCopy,
    /// File mappings filled by copy (bytes; cycles).
    FileCopy,
    /// exec's load (cycles).
    Exec,
    /// Host forks (cycles in the parent's clone).
    Fork,
    /// A hand-off's latency: from the owner set to this slot to the slot running (cycles).
    Handoff,
}

/// [`K`]'s names in the report, in order.
#[cfg(feature = "stats")]
const NAMES: [&str; 18] = [
    "acq_free", "acq_held", "acq_contended", "acq_from_kernel", "held_program", "held_kernel",
    "kernel_ppoll", "poke", "wait_token", "sched_idle", "lkl", "switch", "zero", "mremap_copy",
    "file_copy", "exec", "fork", "handoff",
];

#[cfg(feature = "stats")]
#[inline(always)]
fn tsc() -> u64 {
    // SAFETY: rdtsc has no preconditions.
    unsafe { core::arch::x86_64::_rdtsc() }
}

/// One `k` event of `cyc` cycles.
#[inline(always)]
pub fn count(_k: K, _cyc: u64) {
    #[cfg(feature = "stats")]
    on::C[_k as usize].add(_cyc);
}

/// `n` bytes to `k`'s byte count.
#[inline(always)]
pub fn bytes(_k: K, _n: usize) {
    #[cfg(feature = "stats")]
    on::BYTES[_k as usize].fetch_add(_n as u64, Ordering::Relaxed);
}

/// The rest of the scope is one `k` event (its cycles counted when the guard drops), of `n` bytes.
#[inline(always)]
pub fn timed(_k: K, _n: usize) -> Timer {
    bytes(_k, _n);
    Timer {
        #[cfg(feature = "stats")]
        k: _k,
        #[cfg(feature = "stats")]
        t: tsc(),
    }
}

/// [`timed`]'s guard.
#[must_use]
pub struct Timer {
    #[cfg(feature = "stats")]
    k: K,
    #[cfg(feature = "stats")]
    t: u64,
}

#[cfg(feature = "stats")]
impl Drop for Timer {
    fn drop(&mut self) {
        count(self.k, tsc() - self.t);
    }
}

/// `f()` as one `k` event.
#[inline(always)]
pub fn time<R>(k: K, f: impl FnOnce() -> R) -> R {
    let _t = timed(k, 0);
    f()
}

/// The rest of the scope serves trapped syscall `nr` ([`Syscall::end`] where it ends sooner).
#[inline(always)]
pub fn syscall(_nr: usize) -> Syscall {
    #[cfg(feature = "stats")]
    on::LAST_WAIT.store(0, Ordering::Relaxed);
    Syscall {
        #[cfg(feature = "stats")]
        nr: _nr,
        #[cfg(feature = "stats")]
        t: tsc(),
    }
}

/// [`syscall`]'s guard.
#[must_use]
pub struct Syscall {
    #[cfg(feature = "stats")]
    nr: usize,
    #[cfg(feature = "stats")]
    t: u64,
}

impl Syscall {
    /// The call is served.
    #[inline(always)]
    pub fn end(self) {}
}

#[cfg(feature = "stats")]
impl Drop for Syscall {
    fn drop(&mut self) {
        if self.nr < on::NR {
            on::SYS[self.nr].add(tsc() - self.t);
            on::SYS_TOKEN_WAIT[self.nr].fetch_add(on::LAST_WAIT.load(Ordering::Relaxed), Ordering::Relaxed);
        }
    }
}

/// The rest of the scope is a contended acquire of the token (held by the idler: `from_kernel`).
#[inline(always)]
pub fn contended(_from_kernel: bool) -> Contended {
    Contended {
        #[cfg(feature = "stats")]
        from_kernel: _from_kernel,
        #[cfg(feature = "stats")]
        t: tsc(),
    }
}

/// [`contended`]'s guard.
#[must_use]
pub struct Contended {
    #[cfg(feature = "stats")]
    from_kernel: bool,
    #[cfg(feature = "stats")]
    t: u64,
}

#[cfg(feature = "stats")]
impl Drop for Contended {
    fn drop(&mut self) {
        let w = tsc() - self.t;
        count(K::AcqContended, w);
        if self.from_kernel {
            count(K::AcqFromKernel, 0);
        }
        on::LAST_WAIT.store(w, Ordering::Relaxed);
    }
}

/// The rest of the scope waits for the token, if `blocks()` (not yet the owner; not evaluated
/// without the feature): the wait, and the latency from being made the owner to running.
#[inline(always)]
pub fn wait_token(_blocks: impl FnOnce() -> bool) -> Wait {
    Wait {
        #[cfg(feature = "stats")]
        t: if _blocks() { tsc() } else { 0 },
    }
}

/// [`wait_token`]'s guard.
#[must_use]
pub struct Wait {
    #[cfg(feature = "stats")]
    t: u64,
}

#[cfg(feature = "stats")]
impl Drop for Wait {
    fn drop(&mut self) {
        if self.t == 0 {
            return;
        }
        let now = tsc();
        count(K::WaitToken, now - self.t);
        let since = on::OWNER_SINCE.load(Ordering::Relaxed);
        if since != 0 && now > since {
            count(K::Handoff, now - since);
        }
    }
}

/// The CPU token's owner word (par's `owner`: a slot, or `u32::MAX` for none): an `AtomicU32`
/// whose stores time the holder they end (slot `KERNEL`: the idler, `HeldKernel`; any other,
/// `HeldProgram`).
#[repr(transparent)]
pub struct Owner<const KERNEL: u32>(AtomicU32);

impl<const KERNEL: u32> Owner<KERNEL> {
    pub const fn new(v: u32) -> Self {
        Owner(AtomicU32::new(v))
    }

    #[inline(always)]
    pub fn load(&self, o: Ordering) -> u32 {
        self.0.load(o)
    }

    /// (Under par's spinlock, like every change of owner.)
    #[inline(always)]
    pub fn store(&self, v: u32, o: Ordering) {
        #[cfg(feature = "stats")]
        {
            let (old, now) = (self.0.load(Ordering::Relaxed), tsc());
            let since = on::OWNER_SINCE.swap(now, Ordering::Relaxed);
            if old != u32::MAX && since != 0 {
                count(if old == KERNEL { K::HeldKernel } else { K::HeldProgram }, now - since);
            }
        }
        self.0.store(v, o)
    }
}

/// The clocks at the start (TSC and CLOCK_MONOTONIC ns, `mono_ns()`), for converting cycles.
/// (The closures here are not called without the feature.)
#[inline(always)]
pub fn start(_mono_ns: impl FnOnce() -> u64) {
    #[cfg(feature = "stats")]
    {
        on::T0.store(tsc(), Ordering::Relaxed);
        on::NS0.store(_mono_ns(), Ordering::Relaxed);
    }
}

/// Print every counter to stderr (a gate write: after lockdown). `mono_ns()` is the clock now;
/// `arena()`, the arena's account, if there is one.
#[inline(always)]
pub fn report(_mono_ns: impl FnOnce() -> u64, _arena: impl FnOnce() -> Option<crate::arena::Stats>) {
    #[cfg(feature = "stats")]
    {
        use alloc::format;
        use core::sync::atomic::Ordering::Relaxed;
        let _mono_ns = _mono_ns();
        let mut s = alloc::string::String::new();
        if let Some(st) = _arena() {
            s += &format!("UNSHAREK_STATS arena high_water={} mapped={} extents={}\n", st.high_water, st.mapped, st.extents);
        }
        let (t0, ns0) = (on::T0.load(Relaxed), on::NS0.load(Relaxed));
        let cyc = tsc().saturating_sub(t0).max(1);
        let ns = _mono_ns.saturating_sub(ns0).max(1);
        let ghz = cyc as f64 / ns as f64;
        let us = |c: u64| c as f64 / ghz / 1000.0;
        s += &format!("UNSHAREK_STATS wall_us={:.0} tsc_ghz={:.3}\n", ns as f64 / 1000.0, ghz);
        for (i, name) in NAMES.iter().enumerate() {
            let (n, c, b) = (on::C[i].n.load(Relaxed), on::C[i].cyc.load(Relaxed), on::BYTES[i].load(Relaxed));
            if n != 0 || b != 0 {
                s += &format!("UNSHAREK_STATS k {name} n={n} us={:.0} bytes={b}\n", us(c));
            }
        }
        for nr in 0..on::NR {
            let (n, c) = (on::SYS[nr].n.load(Relaxed), on::SYS[nr].cyc.load(Relaxed));
            if n != 0 {
                let w = on::SYS_TOKEN_WAIT[nr].load(Relaxed);
                s += &format!("UNSHAREK_STATS sys {nr} n={n} us={:.0} token_wait_us={:.0}\n", us(c), us(w));
            }
        }
        let _ = crate::trap::write(2, s.as_bytes());
    }
}
