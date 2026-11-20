//! The kernel boots on unsharek's own host operations (`unsharek_rt::host`), in coroutine mode: every
//! kernel thread a coroutine on this one host thread, idle a host `ppoll`. Then guest syscalls
//! from the booting coroutine, a guest sleep (timers and idle: it must cost no CPU), and a halt.
//!
//! The kernel runs in a forked child, bounded by a timeout, so a hang or a crash fails the test
//! in seconds instead of taking the harness down (and one kernel per process stays true).

use core::ffi::{CStr, c_long};
use std::time::{Duration, Instant};

use unsharek_rt::host;
use unsharek_rt::sched::{Config, Sched, Stacks};
use lkl_sys::*;

/// The whole child: boot, syscalls, the sleep, halt. Boot is tens of ms at HZ=100.
const TIMEOUT: Duration = Duration::from_secs(5);
/// Each coroutine's stack. Kernel code runs on these (LKL's THREAD_SIZE is moot: its threads run
/// on host stacks), and so does lkl_printf's vsnprintf; generous, with a guard page.
const STACK: usize = 128 * 1024;
/// Coroutines: the kernel makes a few dozen threads at boot.
const COROUTINES: usize = 128;
/// The kernel's memory: `mem=16M`, and a page of slack.
const MEM: usize = 16 << 20;
const SLEEP_NS: i64 = 50_000_000;

static SCHED: Sched = Sched::new();
static SYS: host::SysHost = host::SysHost;

fn syscall(nr: c_long, args: &[c_long]) -> c_long {
    let mut params = [0; 6];
    params[..args.len()].copy_from_slice(args);
    // SAFETY: the kernel is running, and each caller's arguments are valid for its syscall.
    unsafe { lkl_syscall(nr, params.as_mut_ptr()) }
}

fn cpu_ns() -> u64 {
    let mut ru: libc::rusage = unsafe { core::mem::zeroed() };
    unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut ru) };
    let us = |t: libc::timeval| t.tv_sec as u64 * 1_000_000 + t.tv_usec as u64;
    (us(ru.ru_utime) + us(ru.ru_stime)) * 1000
}

fn reserve(len: usize) -> *mut u8 {
    // Reserved, not committed: the kernel and the stacks cost only what they touch.
    let p = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
            -1,
            0,
        )
    };
    assert_ne!(p, libc::MAP_FAILED);
    p as *mut u8
}

/// The booting coroutine. Asserts; a failure panics, which aborts the child (panic=abort).
fn boot(_: usize) -> usize {
    let (t0, bc0) = (Instant::now(), cpu_ns());
    // SAFETY: one kernel per process (this child); the table and its scheduler are installed.
    unsafe {
        assert_eq!(lkl_init(host::ops()), 0);
        assert_eq!(lkl_start_kernel(c"mem=16M loglevel=4".as_ptr()), 0);
    }
    let (boot, boot_cpu) = (t0.elapsed(), cpu_ns() - bc0);

    assert!(syscall(__lkl__NR_getpid as c_long, &[]) > 0);
    let mut uts = [0u8; 6 * 65];
    assert_eq!(syscall(__lkl__NR_uname as c_long, &[uts.as_mut_ptr() as c_long]), 0);
    assert_eq!(CStr::from_bytes_until_nul(&uts[..65]).unwrap(), c"Linux");

    // A file in the guest's root (rootfs): made, written, read back.
    const AT_FDCWD: c_long = -100;
    const O_RDWR: c_long = 2;
    const O_CREAT: c_long = 0o100;
    assert_eq!(syscall(__lkl__NR_mkdirat as c_long, &[AT_FDCWD, c"/box".as_ptr() as c_long, 0o755]), 0);
    let fd = syscall(
        __lkl__NR_openat as c_long,
        &[AT_FDCWD, c"/box/f".as_ptr() as c_long, O_RDWR | O_CREAT, 0o644],
    );
    assert!(fd >= 0, "openat: {fd}");
    let msg = b"hello from the guest";
    assert_eq!(syscall(__lkl__NR_write as c_long, &[fd, msg.as_ptr() as c_long, msg.len() as c_long]), msg.len() as c_long);
    assert_eq!(syscall(__lkl__NR_lseek as c_long, &[fd, 0, 0]), 0);
    let mut back = [0u8; 64];
    let n = syscall(__lkl__NR_read as c_long, &[fd, back.as_mut_ptr() as c_long, back.len() as c_long]);
    assert_eq!(&back[..n as usize], msg);
    assert_eq!(syscall(__lkl__NR_close as c_long, &[fd]), 0);

    // The guest sleeps: its timer is a host-op timer, and with nothing to run the scheduler idles
    // in ppoll. The process must stay (nearly) off the CPU for it.
    let ts = [0i64, SLEEP_NS];
    let (w0, c0) = (Instant::now(), cpu_ns());
    assert_eq!(syscall(__lkl__NR_nanosleep as c_long, &[ts.as_ptr() as c_long, 0]), 0);
    let (wall, cpu) = (w0.elapsed(), cpu_ns() - c0);

    // SAFETY: the kernel is running; nothing uses it after.
    let t1 = Instant::now();
    unsafe { assert_eq!(lkl_sys_halt(), 0) };
    let halt = t1.elapsed();

    eprintln!(
        "lkl_boot: boot (lkl_init + lkl_start_kernel) {:.1} ms, CPU {:.1} ms; nanosleep 50 ms: wall {:.1} ms, CPU {:.2} ms; halt {:.1} ms",
        boot.as_secs_f64() * 1e3,
        boot_cpu as f64 / 1e6,
        wall.as_secs_f64() * 1e3,
        cpu as f64 / 1e6,
        halt.as_secs_f64() * 1e3,
    );
    assert!(wall >= Duration::from_nanos(SLEEP_NS as u64), "woke early: {wall:?}");
    // Generous for a loaded machine; a spinning idle would be ~50 ms.
    assert!(cpu < 10_000_000, "the sleep used {cpu} ns of CPU: idle spins?");
    0
}

fn child() -> ! {
    let stacks = Stacks { base: reserve(COROUTINES * STACK), len: COROUTINES * STACK, size: STACK, guard: true };
    let heap = reserve(MEM + 4096);
    // SAFETY: the regions are this scheduler's and the kernel's; this thread runs them.
    unsafe {
        // switch_fs off: the kernel's coroutines share this thread's TLS (std's, here).
        SCHED.init(Config { stacks, switch_fs: false, host: &SYS }).unwrap();
        host::install(&SCHED, heap, MEM + 4096);
    }
    // Boot from a coroutine, not the root: the kernel's threads may thread_exit, and the root
    // (this host thread) can't.
    let t = SCHED.spawn(boot, 0).unwrap();
    assert_eq!(SCHED.join(t), Ok(0));
    unsafe { libc::_exit(0) }
}

#[test]
fn boot_on_coroutines() {
    // SAFETY: the child only runs `child`, then _exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        child();
    }
    let start = Instant::now();
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(r >= 0);
        if r == pid {
            break;
        }
        if start.elapsed() > TIMEOUT {
            unsafe {
                libc::kill(pid, libc::SIGKILL);
                libc::waitpid(pid, &mut status, 0);
            }
            panic!("the kernel didn't boot, run and halt within {TIMEOUT:?} (hung)");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(
        libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0,
        "the child failed: status {status:#x} (signal {})",
        if libc::WIFSIGNALED(status) { libc::WTERMSIG(status) } else { 0 }
    );
}
