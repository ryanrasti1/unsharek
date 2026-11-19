//! What the suite checks from the host, tried from inside: a CPU budget, and how a test that
//! fails (an assert, an abort, a hang) is reported.

use std::time::Duration;

fn cpu() -> Duration {
    // SAFETY: a zeroed out-struct.
    let ru = unsafe {
        let mut ru: libc::rusage = std::mem::zeroed();
        assert_eq!(libc::getrusage(libc::RUSAGE_SELF, &mut ru), 0);
        ru
    };
    let tv = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    tv(ru.ru_utime) + tv(ru.ru_stime)
}

/// idle.c: 300 ms of sleeping in each way programs sleep, under a CPU budget. In the guest this is
/// the guest kernel's accounting, not the host's: the bug idle.c caught (~700k timer fires a
/// second in the guest kernel's idle) burned host CPU the guest may not count as this process's.
pub fn idle_cpu() {
    let before = cpu();
    // SAFETY: sleeps of each kind, on objects of our own.
    unsafe {
        let ts = libc::timespec { tv_sec: 0, tv_nsec: 60_000_000 };
        assert_eq!(libc::nanosleep(&ts, std::ptr::null_mut()), 0);
        assert_eq!(libc::poll(std::ptr::null_mut(), 0, 60), 0);
        let ep = libc::epoll_create1(0);
        let mut ev = libc::epoll_event { events: 0, u64: 0 };
        assert_eq!(libc::epoll_wait(ep, &mut ev, 1, 60), 0);
    }
    let (m, cv) = (std::sync::Mutex::new(()), std::sync::Condvar::new());
    let r = cv.wait_timeout(m.lock().unwrap(), Duration::from_millis(60)).unwrap();
    assert!(r.1.timed_out());
    std::thread::sleep(Duration::from_millis(60));
    let used = cpu() - before;
    println!("idle: {used:?} of CPU (getrusage) over 300 ms of sleeping");
    assert!(used < Duration::from_millis(100), "used {used:?} of CPU, over the budget of 100 ms");
}

/// Under the workspace's panic = "abort" a #[should_panic] test can't work; this shows whether it
/// does (cargo builds test harnesses with unwinding).
pub fn should_panic() {
    panic!("boom");
}

pub fn demo_assert_fails() {
    let v = vec![1, 2, 3];
    println!("some output before the failure");
    assert_eq!(v.len(), 4, "a failing assert in mode {}", crate::mode());
}

pub fn demo_abort() {
    println!("about to abort");
    std::process::abort();
}

pub fn demo_hang() {
    std::thread::sleep(Duration::from_secs(3600));
}
