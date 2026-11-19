# EXPERIMENT (measurement only): the kernel idler sleeps (to its deadline, watching the host fds)
# without the CPU token, and a return to user mode hands the token to it only when a deadline is
# due, earlier than the one it sleeps to, or a host fd wait began while it watched none. (A new fd
# wait while it already watches others is seen at its next wake: good enough to measure, not to
# ship.) Applied after apply.py to the tree in argv[1].
import sys
p = sys.argv[1] + '/native/rt/src/par.rs'
s = open(p).read()


def rep(a, b):
    global s
    assert s.count(a) == 1, a
    s = s.replace(a, b)


rep("""    } else if !allow_none || sched().par_next_deadline().is_some() || idle_watching() {
        KERNEL as u32
    } else {""", """    } else if !allow_none {
        KERNEL as u32
    } else if sched().par_next_deadline().is_some_and(|d| d <= sched().now() || d < IDLER_UNTIL.load(Ordering::Relaxed))
        || (idle_watching() && !IDLER_WATCHING.load(Ordering::Relaxed))
    {
        KERNEL as u32
    } else {""")
rep("""fn give(id: u16, allow_none: bool) -> u32 {""", """/// The deadline the idler sleeps to without the token (u64::MAX: none, or it holds the token).
static IDLER_UNTIL: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(u64::MAX);
/// The idler sleeps watching host fds.
static IDLER_WATCHING: AtomicBool = AtomicBool::new(false);

fn give(id: u16, allow_none: bool) -> u32 {""")
rep("""        // Keep the token and ppoll to the deadline on our eventfd (woken early by an acquirer's
        // poke) and the watched fds. On return, loop: fire due timers, run what an fd woke.
        unlock();
        fds[0] = PollFd { fd: h.efd as i32, events: POLLIN, revents: 0 };
        let n = 1 + crate::host::idle_fds(&mut fds[1..]);""", """        // EXPERIMENT: free the token, ppoll to the deadline and the fds, then take it back.
        fds[0] = PollFd { fd: h.efd as i32, events: POLLIN, revents: 0 };
        let n = 1 + crate::host::idle_fds(&mut fds[1..]);
        set_owner(NONE_SLOT, Ordering::Release);
        IDLER_UNTIL.store(deadline.unwrap_or(u64::MAX), Ordering::Relaxed);
        IDLER_WATCHING.store(n > 1, Ordering::Relaxed);
        unlock();""")
rep("""            LAST_LOOK.0.set(s.now());
            crate::host::idle_ready(&fds[1..n]);
        }
    }
}""", """            LAST_LOOK.0.set(s.now());
            lock();
            IDLER_UNTIL.store(u64::MAX, Ordering::Relaxed);
            IDLER_WATCHING.store(false, Ordering::Relaxed);
            unlock();
            acquire(id);
            crate::host::idle_ready(&fds[1..n]);
            continue;
        }
        lock();
        IDLER_UNTIL.store(u64::MAX, Ordering::Relaxed);
        IDLER_WATCHING.store(false, Ordering::Relaxed);
        unlock();
        acquire(id);
    }
}""")
open(p, 'w').write(s)
print('ok')
