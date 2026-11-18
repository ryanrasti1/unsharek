//! What the test binaries share: running a command under a timeout, with its CPU time.

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::process::{Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

use libtest_mimic::Failed;

/// Runs `cmd` to its end or `timeout` (then kills it), returning its status, the CPU time it and
/// its reaped descendants used (the host's accounting, from wait4), and its output.
pub fn spawn_bounded(
    mut cmd: Command,
    stdin: Option<&'static str>,
    timeout: Duration,
) -> Result<(ExitStatus, Duration, String, String), Failed> {
    let mut child = cmd.spawn().map_err(|e| format!("spawn {cmd:?}: {e}"))?;
    let pid = child.id() as libc::pid_t;
    if let (Some(input), Some(mut w)) = (stdin, child.stdin.take()) {
        thread::spawn(move || w.write_all(input.as_bytes()));
    }
    let drain = |r: Option<Box<dyn Read + Send>>| {
        thread::spawn(move || {
            let mut s = String::new();
            if let Some(mut r) = r {
                let mut b = vec![];
                let _ = r.read_to_end(&mut b);
                s = String::from_utf8_lossy(&b).into_owned();
            }
            s
        })
    };
    let out = drain(child.stdout.take().map(|r| Box::new(r) as _));
    let err = drain(child.stderr.take().map(|r| Box::new(r) as _));

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
    let cpu = |t: libc::timeval| Duration::new(t.tv_sec as u64, t.tv_usec as u32 * 1000);
    let used = cpu(ru.ru_utime) + cpu(ru.ru_stime);
    let (stdout, stderr) = (out.join().unwrap(), err.join().unwrap());
    if timed_out {
        return Err(format!("timed out after {timeout:?}\n--- stdout:\n{stdout}\n--- stderr:\n{stderr}").into());
    }
    Ok((ExitStatus::from_raw(raw), used, stdout, stderr))
}
