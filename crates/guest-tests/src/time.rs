//! The guest's clocks.

use std::io::Write;
use std::os::unix::fs::MetadataExt;

fn secs(t: libc::timespec) -> f64 {
    t.tv_sec as f64 + t.tv_nsec as f64 / 1e9
}

/// What `clock` checks, in whichever process: Err(why).
fn check(who: &str) -> Result<(), String> {
    // SAFETY: out-structs.
    let (vdso, raw) = unsafe {
        let mut vdso: libc::timespec = std::mem::zeroed();
        let mut raw: libc::timespec = std::mem::zeroed();
        libc::clock_gettime(libc::CLOCK_REALTIME, &mut vdso);
        libc::syscall(libc::SYS_clock_gettime, libc::CLOCK_REALTIME, &mut raw);
        (vdso, raw)
    };
    let off = secs(raw) - secs(vdso);
    if off.abs() >= 1.0 {
        return Err(format!("{who}: the kernel's realtime is {off:.3} s off the host's"));
    }
    let p = crate::tmp(&format!("clock-{}", std::process::id()));
    let mut f = std::fs::File::create(&p).map_err(|e| format!("{who}: create {p:?}: {e}"))?;
    f.write_all(b"x").map_err(|e| e.to_string())?;
    let md = f.metadata().map_err(|e| e.to_string())?;
    let _ = std::fs::remove_file(&p);
    let d = md.mtime() as f64 + md.mtime_nsec() as f64 / 1e9 - secs(vdso);
    if d.abs() >= 3.0 {
        return Err(format!("{who}: a new file's mtime is {d:.3} s off the host's time"));
    }
    println!("{who}: kernel {off:+.3} s, a new file's mtime {d:+.3} s off the host's clock");
    Ok(())
}

/// The guest kernel's clock against the host's: a file made now has today's mtime, and the
/// kernel's CLOCK_REALTIME (a raw syscall, which the sandbox serves from the guest kernel) is the
/// vDSO's (the host's). The guest's realtime started at the host's uptime (its clock is the host's
/// CLOCK_MONOTONIC), so files got 1970 mtimes while `date` said today, and autoconf stopped:
/// "newly created file is older than distributed files" (capnix building nixpkgs' hello). Where
/// there are processes a forked child checks the same.
pub fn clock() {
    check("the test").unwrap();
    if crate::forks() {
        // SAFETY: the child checks (allocating: a copy of a multi-threaded process, but libtest's
        // main thread holds no lock while it waits) and _exits.
        unsafe {
            let c = libc::fork();
            assert!(c >= 0, "fork");
            if c == 0 {
                let r = check("a forked child");
                if let Err(why) = &r {
                    println!("{why}");
                }
                let _ = std::io::stdout().flush();
                libc::_exit(r.is_err() as i32);
            }
            let mut st = 0;
            assert_eq!(libc::waitpid(c, &mut st, 0), c);
            assert!(libc::WIFEXITED(st) && libc::WEXITSTATUS(st) == 0, "the child's checks: status {st:#x}");
        }
    }
}
