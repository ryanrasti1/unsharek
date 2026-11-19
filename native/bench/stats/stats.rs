//! Measurement counters (cargo feature `stats`; without it every call here is empty and inlined
//! away). Counts and TSC cycles, relaxed atomics; printed to stderr at the sandbox's end
//! ([`report`]). For native/PERF.md: where a sandboxed program's time goes.
//!
//! What is counted:
//! - per trapped syscall number: calls, and cycles in the dispatcher (`served`: including any
//!   block inside it, e.g. a futex wait or a pipe read);
//! - the CPU token (threaded/fork): acquires (free, already held, contended), cycles waiting to
//!   acquire in a dispatch, cycles each slot held it (busy) and the kernel thread's ppoll while
//!   holding it, hand-offs (eventfd writes) and eventfd waits;
//! - inside LKL (`lkl_syscall`, inclusive of blocks), scheduler context switches;
//! - arena: high-water clearing and mremap copies (bytes and cycles), file-mapping copies vs
//!   in place, exec's load.

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
    #[unsafe(link_section = "exobox_shared")]
    pub static SYS: [Pair; NR] = [const { Pair::new() }; NR];
    #[unsafe(link_section = "exobox_shared")]
    pub static SYS_TOKEN_WAIT: [AtomicU64; NR] = [const { AtomicU64::new(0) }; NR];
    #[unsafe(link_section = "exobox_shared")]
    pub static C: [Pair; K_N] = [const { Pair::new() }; K_N];
    #[unsafe(link_section = "exobox_shared")]
    pub static BYTES: [AtomicU64; K_N] = [const { AtomicU64::new(0) }; K_N];
    #[unsafe(link_section = "exobox_shared")]
    pub static T0: AtomicU64 = AtomicU64::new(0);
    #[unsafe(link_section = "exobox_shared")]
    pub static NS0: AtomicU64 = AtomicU64::new(0);
    // Token ownership accounting (under par's spinlock).
    #[unsafe(link_section = "exobox_shared")]
    pub static OWNER_SINCE: AtomicU64 = AtomicU64::new(0);
    pub const K_N: usize = 24;
}

/// Counter kinds ([`count`], [`bytes`]).
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
    /// The token held by the kernel thread, not in its idle ppoll.
    HeldKernel,
    /// The kernel thread's ppoll to a deadline, token held (cycles).
    KernelPpoll,
    /// Hand-offs: eventfd writes.
    Poke,
    /// Blocking eventfd reads waiting for the token (cycles).
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
    /// File mappings answered in place (bytes).
    FileInPlace,
    /// exec's load (cycles).
    Exec,
    /// Released to the host (madvise), bytes.
    Release,
    /// Emulated futex waits that blocked / wakes.
    FutexWait,
    FutexWake,
    /// Coroutine-mode idle waits (host ppoll; cycles).
    Idle,
    /// Host forks (cycles in the parent's clone).
    Fork,
    /// A hand-off's latency: from the owner set to this slot to the slot running (cycles).
    Handoff,
}

const NAMES: [&str; 23] = [
    "acq_free", "acq_held", "acq_contended", "acq_from_kernel", "held_program", "held_kernel",
    "kernel_ppoll", "poke", "wait_token", "sched_idle", "lkl", "switch", "zero", "mremap_copy",
    "file_copy", "file_in_place", "exec", "release", "futex_wait", "futex_wake", "idle", "fork", "handoff",
];

#[inline(always)]
pub fn tsc() -> u64 {
    #[cfg(feature = "stats")]
    {
        // SAFETY: rdtsc has no preconditions.
        unsafe { core::arch::x86_64::_rdtsc() }
    }
    #[cfg(not(feature = "stats"))]
    0
}

#[inline(always)]
pub fn count(_k: K, _cyc: u64) {
    #[cfg(feature = "stats")]
    on::C[_k as usize].add(_cyc);
}

#[inline(always)]
pub fn bytes(_k: K, _n: u64) {
    #[cfg(feature = "stats")]
    on::BYTES[_k as usize].fetch_add(_n, core::sync::atomic::Ordering::Relaxed);
}

#[inline(always)]
pub fn syscall(_nr: usize, _cyc: u64, _token_wait: u64) {
    #[cfg(feature = "stats")]
    if _nr < on::NR {
        on::SYS[_nr].add(_cyc);
        on::SYS_TOKEN_WAIT[_nr].fetch_add(_token_wait, core::sync::atomic::Ordering::Relaxed);
    }
}

/// The token changes hands (called under par's spinlock with the old and new owner).
#[inline(always)]
pub fn owner_change(_old: u32, _new: u32, _kernel: u32) {
    #[cfg(feature = "stats")]
    {
        use core::sync::atomic::Ordering::Relaxed;
        let now = tsc();
        let since = on::OWNER_SINCE.swap(now, Relaxed);
        if _old != u32::MAX && since != 0 {
            count(if _old == _kernel { K::HeldKernel } else { K::HeldProgram }, now - since);
        }
    }
}

/// A waiter got the token: the latency since it was made the owner.
#[inline(always)]
pub fn handed() {
    #[cfg(feature = "stats")]
    {
        let since = on::OWNER_SINCE.load(core::sync::atomic::Ordering::Relaxed);
        let now = tsc();
        if since != 0 && now > since {
            count(K::Handoff, now - since);
        }
    }
}

/// The clocks at the start (TSC and CLOCK_MONOTONIC ns), for converting cycles.
pub fn start(_mono_ns: u64) {
    #[cfg(feature = "stats")]
    {
        on::T0.store(tsc(), core::sync::atomic::Ordering::Relaxed);
        on::NS0.store(_mono_ns, core::sync::atomic::Ordering::Relaxed);
    }
}

pub const ENABLED: bool = cfg!(feature = "stats");

/// Print every counter to stderr through `write` (a gate write in the sandbox). `mono_ns` now.
pub fn report(_mono_ns: u64, _write: &dyn Fn(&[u8])) {
    #[cfg(feature = "stats")]
    {
        use alloc::format;
        use core::sync::atomic::Ordering::Relaxed;
        let (t0, ns0) = (on::T0.load(Relaxed), on::NS0.load(Relaxed));
        let cyc = tsc().saturating_sub(t0).max(1);
        let ns = _mono_ns.saturating_sub(ns0).max(1);
        let ghz = cyc as f64 / ns as f64;
        let us = |c: u64| c as f64 / ghz / 1000.0;
        let mut s = format!("EXOBOX_STATS wall_us={:.0} tsc_ghz={:.3}\n", ns as f64 / 1000.0, ghz);
        for (i, name) in NAMES.iter().enumerate() {
            let (n, c, b) = (on::C[i].n.load(Relaxed), on::C[i].cyc.load(Relaxed), on::BYTES[i].load(Relaxed));
            if n != 0 || b != 0 {
                s += &format!("EXOBOX_STATS k {name} n={n} us={:.0} bytes={b}\n", us(c));
            }
        }
        for nr in 0..on::NR {
            let (n, c) = (on::SYS[nr].n.load(Relaxed), on::SYS[nr].cyc.load(Relaxed));
            if n != 0 {
                let w = on::SYS_TOKEN_WAIT[nr].load(Relaxed);
                s += &format!("EXOBOX_STATS sys {nr} n={n} us={:.0} token_wait_us={:.0}\n", us(c), us(w));
            }
        }
        _write(s.as_bytes());
    }
}
