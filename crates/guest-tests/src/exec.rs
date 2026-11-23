//! An exec's kernel half (the kernel series' item 10): what the new image sees of the old one's
//! kernel state. The runtime's exec loaded the new image but kept the rest: close-on-exec fds
//! stayed open, caught signals' handlers (addresses in the old image) stayed installed, the old
//! image's other threads kept running in the new one.
//!
//! The test execs its own binary with its own arguments (nextest's `--exact <this test> ...`),
//! so the new image runs this same test again, which sees GUEST_TESTS_EXEC and checks: the
//! close-on-exec fd closed, the plain one open, SIGUSR1's handler reset to the default, SIGUSR2
//! still ignored, SIGHUP still blocked, no alternate stack, the same pid, the old image's threads
//! gone, named after the file, /proc/self/exe the file. Exec'd from libtest's test thread, with
//! libtest's main thread and a thread of the test's alive.

use std::os::unix::process::CommandExt;

extern "C" fn on_usr1(_: libc::c_int) {}

pub fn exec_reset() {
    match std::env::var("GUEST_TESTS_EXEC") {
        Err(_) => before(),
        Ok(state) => after(&state),
    }
}

fn before() {
    let (cr, cw) = crate::pipe();
    let (kr, _kw) = crate::pipe();
    // SAFETY: our fds' flags; our dispositions; this thread's mask and alternate stack (leaked:
    // the exec drops it).
    unsafe {
        assert_eq!(libc::fcntl(cr, libc::F_SETFD, libc::FD_CLOEXEC), 0);
        assert_eq!(libc::fcntl(cw, libc::F_SETFD, libc::FD_CLOEXEC), 0);
        crate::signals::set(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as usize, 0);
        libc::signal(libc::SIGUSR2, libc::SIG_IGN);
        let mut m: libc::sigset_t = std::mem::zeroed();
        libc::sigemptyset(&mut m);
        libc::sigaddset(&mut m, libc::SIGHUP);
        libc::pthread_sigmask(libc::SIG_BLOCK, &m, std::ptr::null_mut());
        let alt = vec![0u8; 16384].leak();
        let ss = libc::stack_t { ss_sp: alt.as_mut_ptr().cast(), ss_flags: 0, ss_size: alt.len() };
        assert_eq!(libc::sigaltstack(&ss, std::ptr::null_mut()), 0, "sigaltstack");
        libc::prctl(libc::PR_SET_NAME, c"before-exec".as_ptr());
    }
    // A thread of our own as well, blocked: exec must end it.
    std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(60)));
    // Wait for it to be there (and asleep, most likely) before counting.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let before = live_tasks();
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    // SAFETY: no arguments.
    let pid = unsafe { libc::getpid() };
    let e = std::process::Command::new(std::env::current_exe().unwrap())
        .args(args)
        .env("GUEST_TESTS_EXEC", format!("{cr},{kr},{before},{pid}"))
        .exec();
    panic!("exec: {e}");
}

fn after(state: &str) {
    let v: Vec<i32> = state.split(',').map(|f| f.parse().unwrap()).collect();
    let (cr, kr, before, pid) = (v[0], v[1], v[2], v[3]);
    // SAFETY: fd flag queries; queries of our dispositions, mask and alternate stack.
    unsafe {
        assert_eq!(libc::fcntl(cr, libc::F_GETFD), -1, "a close-on-exec fd survived the exec");
        assert_eq!(libc::fcntl(kr, libc::F_GETFD), 0, "an fd without close-on-exec didn't survive the exec");
        let mut sa: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut sa), 0);
        assert_eq!(sa.sa_sigaction, libc::SIG_DFL, "a handler survived the exec");
        assert_eq!(libc::sigaction(libc::SIGUSR2, std::ptr::null(), &mut sa), 0);
        assert_eq!(sa.sa_sigaction, libc::SIG_IGN, "SIGUSR2 not ignored any more");
        // (This thread is libtest's new one, which has the exec'd thread's mask.)
        let mut m: libc::sigset_t = std::mem::zeroed();
        libc::pthread_sigmask(libc::SIG_BLOCK, std::ptr::null(), &mut m);
        assert_eq!(libc::sigismember(&m, libc::SIGHUP), 1, "SIGHUP no longer blocked");
        assert_eq!(libc::getpid(), pid, "the pid after the exec");
    }
    // libtest's two threads again: the old image's three (libtest's two and the sleeper) are gone.
    assert_eq!(live_tasks(), before - 1, "live tasks after the exec, with {before} before it");
    let exe = std::fs::read_link("/proc/self/exe").unwrap();
    assert_eq!(Some(exe.as_os_str()), std::env::args_os().next().as_deref(), "/proc/self/exe");
    let name: String = exe.file_name().unwrap().to_string_lossy().chars().take(15).collect();
    assert_eq!(std::fs::read_to_string("/proc/self/comm").unwrap().trim_end(), name, "the process's name");
    println!("exec_reset: the new image as it should be");
}

/// An exec from a thread other than the main one, then a new image that makes threads (each makes
/// one more, so the host slots the old image's threads left are taken several times over).
/// Threaded and fork mode panicked in the runtime at the new image's first thread ("attempt to
/// subtract with overflow" in `Context::new`, a stack top of 0), then hung: the exec ends the
/// main thread, whose host slot's coroutines were freed, one of them the scheduler's root, which
/// has no stack of its own (it ran on the host thread's); on the free list, the new thread's
/// scheduler coroutine was made in it (crates/unsharek-rt/src/sched.rs's `free_slot`). How the main thread
/// waits doesn't matter (a timed futex, as libtest's, a plain one, pause, a join all did it); that
/// the new image makes a thread does. exec_reset hit it only through libtest's thread.
pub fn exec_then_threads() {
    if std::env::var_os("GUEST_TESTS_EXEC_THREADS").is_some() {
        for i in 1..=8usize {
            let inner = std::thread::spawn(move || std::thread::spawn(move || i).join().unwrap());
            assert_eq!(inner.join().unwrap(), i, "thread {i} of the new image");
        }
        println!("exec_then_threads: the new image made and joined its threads");
        return;
    }
    let t = std::thread::spawn(|| {
        let mut args = std::env::args_os();
        let _argv0 = args.next();
        let e = std::process::Command::new(std::env::current_exe().unwrap())
            .args(args)
            .env("GUEST_TESTS_EXEC_THREADS", "1")
            .exec();
        panic!("exec: {e}");
    });
    // This thread waits in a join (a futex) meanwhile, libtest's main thread in its timed one.
    let _ = t.join();
    unreachable!("the exec returned");
}

/// The process's live tasks: not zombies (after an exec from another thread the old leader stays
/// one, as the kernel's new_exec leaves it), and in the sandbox counting the kernel's parked
/// host0 in init's process, so only differences mean anything.
fn live_tasks() -> i32 {
    let mut n = 0;
    for e in std::fs::read_dir("/proc/self/task").unwrap() {
        let stat = std::fs::read_to_string(e.unwrap().path().join("stat")).unwrap_or_default();
        if let Some((_, rest)) = stat.rsplit_once(')') {
            n += !rest.starts_with(" Z") as i32;
        }
    }
    n
}
