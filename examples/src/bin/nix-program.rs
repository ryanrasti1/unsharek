//! Run a nixpkgs program in a sandbox, with its Nix closure, from the library: the CLI's
//! `exobox run` spelled out. The parent measures the sandbox from outside: startup, wall time,
//! memory.
//!
//!     cargo run -p exobox-examples --bin nix-program                       # python -c 'print(6*7)'
//!     cargo run -p exobox-examples --bin nix-program -- "$(which hello)" --greeting=hi
//!
//! The program must be a store path (or inside one): its closure is what the guest sees.

use std::ffi::OsString;
use std::io::Read;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use exobox::{Mode, Sandbox, setup, store};
use exobox_examples as ex;

/// The sandbox, in a child process of its own: `run` takes the process over.
fn sandbox(argv: Vec<OsString>) -> ! {
    let t = Instant::now();
    // 1. Host work, before anything is locked down. The closure (every store path the program
    //    references, transitively, from `nix-store`) and an erofs image per store path, both
    //    cached: only the first run of a program builds anything.
    //    (`Sandbox::map_closure` is these steps and the next in one call.)
    let cache = store::Cache::open_default().unwrap_or_else(|e| ex::fail(e.into()));
    let images = cache.store(Path::new(&argv[0]), &[]).unwrap_or_else(|e| ex::fail(e.into()));
    let closure_t = t.elapsed();
    // 2. Boot the guest kernel in this process (default mode: coroutines on this one thread).
    let mut sb = Sandbox::builder().mode(Mode::Coroutine).build().unwrap_or_else(|e| ex::fail(e));
    // 3. Map each image: a host mmap now, a read-only block device in the guest. After lockdown
    //    there is no host `open` or `mmap` left to do it with.
    let mounts = sb.map_store(&images).unwrap_or_else(|e| ex::fail(e));
    eprintln!(
        "[sandbox] {} store paths ({} images built): {:?} for the closure, {:?} to boot and map",
        mounts.len(),
        cache.builds(),
        closure_t,
        t.elapsed() - closure_t,
    );
    // 4. In a guard this thread's syscalls are the guest's, as its init: the mounts happen inside.
    {
        let _g = sb.intercept().unwrap_or_else(|e| ex::fail(e));
        setup::mount_closure(&mounts).unwrap_or_else(|e| ex::fail(e));
    }
    // 5. The program is exec'd from the guest's files, behind the mode's filter. `run` returns
    //    only if the program couldn't be started.
    let env = ex::os(&["PATH=/bin", "LANG=C.UTF-8"]);
    let Err(e) = sb.run(&argv, &env);
    ex::fail(e)
}

fn main() {
    let mut args: Vec<OsString> = std::env::args_os().skip(1).collect();
    if ex::role().as_deref() == Some("sandbox") {
        sandbox(args);
    }
    if args.is_empty() {
        let py = ex::nix_program("EXOBOX_TEST_PYTHON");
        args = vec![py.into(), "-c".into(), "print(6*7)".into()];
    }
    println!("running {:?} in a sandbox", args);

    let start = Instant::now();
    let mut cmd = ex::self_command("sandbox");
    cmd.args(&args).stdout(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn");
    let pid = child.id();
    // The program's output through a thread, noting when the first of it came: startup, as the
    // caller sees it (boot, mounts, exec, the program's own start).
    let mut out = child.stdout.take().unwrap();
    let reader = std::thread::spawn(move || {
        let (mut all, mut buf, mut first) = (Vec::new(), [0u8; 4096], None);
        while let Ok(n @ 1..) = out.read(&mut buf) {
            first.get_or_insert_with(|| start.elapsed());
            all.extend_from_slice(&buf[..n]);
        }
        (all, first)
    });
    // PSS (the process's share of every page it maps: the store's pages are the host's page
    // cache, shared) sampled while it runs; max RSS from the kernel's accounting at the end.
    let mut peak_pss = 0;
    let (status, rusage) = wait_sampling(pid, |kb| peak_pss = peak_pss.max(kb));
    let wall = start.elapsed();
    let (output, first) = reader.join().unwrap();
    print!("{}", String::from_utf8_lossy(&output));
    println!("--- {}", ex::describe(status));
    if let Some(f) = first {
        println!("first output after {f:.1?}");
    }
    println!("wall time {wall:.1?}; peak PSS {peak_pss} KB (sampled), max RSS {} KB", rusage.ru_maxrss);
    std::process::exit(status.code().unwrap_or(1));
}

/// Waits for child `pid`, calling `sample` with its PSS every millisecond until it exits.
fn wait_sampling(pid: u32, mut sample: impl FnMut(u64)) -> (ExitStatus, libc::rusage) {
    loop {
        let (mut raw, mut ru) = (0, unsafe { std::mem::zeroed::<libc::rusage>() });
        // SAFETY: wait4 on our own child, into locals.
        if unsafe { libc::wait4(pid as i32, &mut raw, libc::WNOHANG, &mut ru) } == pid as i32 {
            return (ExitStatus::from_raw(raw), ru);
        }
        if let Some(kb) = ex::pss_kb(pid) {
            sample(kb);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
}
