//! Why threaded mode exists: one CPU-bound workload (four threads of pure computation, the
//! fixtures' `par_compute`) natively, in `Mode::Coroutine` and in `Mode::Threaded`.
//!
//!     cargo run -p exobox-examples --release --bin threads
//!
//! Coroutine mode runs the guest kernel and every program thread as coroutines on one host
//! thread: the smallest filter (no `clone` at all), but four threads take four times as long.
//! Threaded mode gives each program thread a host thread of its own, made through the filter by
//! one exact `clone` flag set, so they run in parallel; the guest kernel still has one CPU, passed
//! between them, which costs only when they make syscalls.

use std::process::Stdio;
use std::time::Instant;

use exobox::{Guest, GuestConfig, Mode, setup};
use exobox_examples as ex;
use exobox_fixtures as fx;

const THREADS: &str = "4";

fn iterations() -> &'static str {
    if ex::quick() { "2000000" } else { "300000000" }
}

fn sandbox(mode: Mode) -> ! {
    let run = || -> Result<std::convert::Infallible, exobox::Error> {
        let prog = fx::bin("par_compute");
        let mut g = Guest::boot(GuestConfig { mode, ..Default::default() })?;
        // The fixtures live outside the store: their directory is allowed as is, and brings the
        // closure of whatever its files reference (glibc).
        let store = g.map_closure(&prog, &[fx::bin_dir()])?;
        g.run(|| setup::mount_closure(&store))??;
        g.lockdown(exobox::stdio)?.exec(&ex::os(&[prog.to_str().unwrap(), THREADS, iterations()]), &[])
    };
    let Err(e) = run();
    ex::fail(e)
}

fn main() {
    match ex::role().as_deref() {
        Some("coroutine") => sandbox(Mode::Coroutine),
        Some("threaded") => sandbox(Mode::Threaded),
        _ => {}
    }
    println!("{THREADS} threads x {} xorshift iterations each", iterations());
    let mut native = None;
    for run in ["native", "coroutine", "threaded"] {
        let mut cmd = match run {
            "native" => std::process::Command::new(fx::bin("par_compute")),
            mode => ex::self_command(mode),
        };
        cmd.args([THREADS, iterations()]).stdout(Stdio::piped());
        let t = Instant::now();
        let out = cmd.output().expect("spawn");
        // The whole run, boot included, as the caller sees it.
        let wall = t.elapsed();
        let stdout = String::from_utf8_lossy(&out.stdout);
        // par_compute's own clock: the threads' work alone.
        let work: f64 = stdout.split_whitespace().nth(1).and_then(|v| v.parse().ok()).unwrap_or(f64::NAN);
        let vs = native.map_or(String::new(), |n: f64| format!("  ({:.1}x native)", work / n));
        println!("{run:>9}: compute {work:>7.1} ms, whole run {:>7.1} ms{vs}", wall.as_secs_f64() * 1e3);
        native.get_or_insert(work);
        if !out.status.success() {
            println!("           {} {}", ex::describe(out.status), String::from_utf8_lossy(&out.stderr));
        }
    }
}
