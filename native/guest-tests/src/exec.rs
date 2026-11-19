//! Exec's kernel half (exec_reset.c), in every mode: the test execs its own binary with its own
//! arguments (nextest's `--exact <this test> ...`), so the new image runs this same test again,
//! which sees GUEST_TESTS_EXEC and checks what the exec kept and dropped. Exec'd from libtest's
//! test thread, with libtest's main thread alive: exec_reset's `threads` variant too.

use std::os::unix::process::CommandExt;
use std::sync::atomic::{AtomicI32, Ordering};

static GOT: AtomicI32 = AtomicI32::new(0);
extern "C" fn on_usr1(_: libc::c_int) {
    GOT.fetch_add(1, Ordering::SeqCst);
}

pub fn exec_reset() {
    match std::env::var("GUEST_TESTS_EXEC") {
        Err(_) => before(),
        Ok(fds) => after(&fds),
    }
}

fn before() {
    let (cr, cw) = crate::pipe();
    let (kr, kw) = crate::pipe();
    // SAFETY: flags of our own fds.
    unsafe {
        assert_eq!(libc::fcntl(cr, libc::F_SETFD, libc::FD_CLOEXEC), 0);
        assert_eq!(libc::fcntl(cw, libc::F_SETFD, libc::FD_CLOEXEC), 0);
        let _ = (kr, kw);
    }
    crate::signals::set(libc::SIGUSR1, on_usr1 as extern "C" fn(libc::c_int) as usize, 0);
    // A thread of our own as well, blocked: exec must end it.
    std::thread::spawn(|| std::thread::sleep(std::time::Duration::from_secs(60)));
    // Wait for it to be there (and asleep, most likely) before counting.
    std::thread::sleep(std::time::Duration::from_millis(10));
    let before = live_tasks();
    let mut args = std::env::args_os();
    let _argv0 = args.next();
    let e = std::process::Command::new(std::env::current_exe().unwrap())
        .args(args)
        .env("GUEST_TESTS_EXEC", format!("{cr},{kr},{before}"))
        .exec();
    panic!("exec: {e}");
}

fn after(fds: &str) {
    let v: Vec<i32> = fds.split(',').map(|f| f.parse().unwrap()).collect();
    let (cr, kr, before) = (v[0], v[1], v[2]);
    // SAFETY: fd flag queries; a query of our disposition.
    unsafe {
        assert_eq!(libc::fcntl(cr, libc::F_GETFD), -1, "a close-on-exec fd survived the exec");
        assert_eq!(libc::fcntl(kr, libc::F_GETFD), 0, "an fd without close-on-exec didn't survive the exec");
        let mut sa: libc::sigaction = std::mem::zeroed();
        assert_eq!(libc::sigaction(libc::SIGUSR1, std::ptr::null(), &mut sa), 0);
        assert_eq!(sa.sa_sigaction, libc::SIG_DFL, "a handler survived the exec");
    }
    // libtest's two threads again: the old image's three (libtest's two and the sleeper) are gone.
    assert_eq!(live_tasks(), before - 1, "live tasks after the exec, with {before} before it");
    println!("exec_reset: after the exec, fds and handlers as they should be");
}

/// The process's live tasks: not zombies (after an exec from another thread the old leader stays
/// one, as the kernel's new_exec leaves it), and in the sandbox counting the kernel's parked
/// host0 in init's process (exec_reset.c's threads_of_self), so only differences mean anything.
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
