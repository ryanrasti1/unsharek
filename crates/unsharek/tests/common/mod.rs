//! What the test binaries share: running a command under a timeout, with its CPU time.

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use libtest_mimic::Failed;

/// Runs `cmd` to its end or `timeout` (then kills it), returning its status, the CPU time it and
/// its reaped descendants used (the host's accounting, from wait4), and its output.
#[allow(dead_code)] // (a test binary may use only `spawn_bounded_with`)
pub fn spawn_bounded(
    cmd: Command,
    stdin: Option<&'static str>,
    timeout: Duration,
) -> Result<(ExitStatus, Duration, String, String), Failed> {
    spawn_bounded_with(cmd, stdin, Duration::ZERO, timeout)
}

/// [`spawn_bounded`], reading the child's stdout only after `stdout_delay` (a slow reader: a
/// pipe the child fills).
pub fn spawn_bounded_with(
    mut cmd: Command,
    stdin: Option<&'static str>,
    stdout_delay: Duration,
    timeout: Duration,
) -> Result<(ExitStatus, Duration, String, String), Failed> {
    let mut child = cmd.spawn().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    let pid = child.id() as libc::pid_t;
    // With input, written and closed; with none, a piped stdin is held open (and silent) until the
    // child has ended: `take` in the pattern dropped it at once, and a reader the case meant to
    // block saw EOF.
    let held = match stdin {
        Some(input) => {
            if let Some(mut w) = child.stdin.take() {
                thread::spawn(move || w.write_all(input.as_bytes()));
            }
            None
        }
        None => child.stdin.take(),
    };
    let drain = |r: Option<Box<dyn Read + Send>>, delay: Duration| {
        thread::spawn(move || {
            thread::sleep(delay);
            let mut s = String::new();
            if let Some(mut r) = r {
                let mut b = vec![];
                let _ = r.read_to_end(&mut b);
                s = String::from_utf8_lossy(&b).into_owned();
            }
            s
        })
    };
    let out = drain(child.stdout.take().map(|r| Box::new(r) as _), stdout_delay);
    let err = drain(child.stderr.take().map(|r| Box::new(r) as _), Duration::ZERO);

    let start = Instant::now();
    let mut timed_out = false;
    let (raw, ru) = loop {
        let mut raw = 0;
        let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
        // SAFETY: plain wait4 on our own child, into locals.
        let r = unsafe { libc::wait4(pid, &mut raw, libc::WNOHANG, &mut ru) };
        if r == pid {
            break (raw, ru);
        }
        if r < 0 {
            return Err(format!("wait4: {}", std::io::Error::last_os_error()).into());
        }
        if !timed_out && start.elapsed() > timeout {
            timed_out = true;
            // SAFETY: our own child, not yet reaped.
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        thread::sleep(Duration::from_millis(2));
    };
    drop(held);
    let cpu = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    let used = cpu(ru.ru_utime) + cpu(ru.ru_stime);
    let (stdout, stderr) = (out.join().unwrap(), err.join().unwrap());
    if timed_out {
        return Err(format!("timed out after {timeout:?}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}").into());
    }
    Ok((ExitStatus::from_raw(raw), used, stdout, stderr))
}
