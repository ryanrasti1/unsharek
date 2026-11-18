//! Performance budgets: what each mode costs, checked against native measured in the same run, or
//! against an absolute budget where native has no equivalent (memory per sandbox, startup).
//! Run with `./test --perf` (its own nextest profile; not part of the default loop). Every trial
//! prints its measurements; budgets come from capnix's tier A (noted at each) with headroom for a
//! loaded machine, so a failure is a regression, not noise.

use std::ffi::OsString;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use std::{env, fs, thread};

use exobox_fixtures as fx;
use libtest_mimic::{Arguments, Failed, Trial};

mod common;
use common::spawn_bounded;

#[derive(Clone, Copy)]
enum Mode {
    Coroutine,
    Threaded,
    Fork,
}

impl Mode {
    fn name(self) -> &'static str {
        match self {
            Mode::Coroutine => "coroutine",
            Mode::Threaded => "threaded",
            Mode::Fork => "fork",
        }
    }
    fn config(self) -> exobox::Mode {
        match self {
            Mode::Coroutine => exobox::Mode::Coroutine,
            Mode::Threaded => exobox::Mode::Threaded,
            Mode::Fork => exobox::Mode::Fork,
        }
    }
}

const ALL: [Mode; 3] = [Mode::Coroutine, Mode::Threaded, Mode::Fork];

/// Per-operation budgets (ns) for syscall_bench. Tier A: an LKL-served syscall ~1.5 µs (coroutine
/// and parallel), a pipe write+read 3-30 µs, a futex ping-pong round trip 3-6 µs.
const SYSCALL_BUDGET_NS: &[(&str, f64)] =
    &[("getppid", 3_000.0), ("sigprocmask", 3_000.0), ("signal", 15_000.0), ("pingpong", 30_000.0)];
/// Start to READY, median of 5. Tier A, cold boot with the small config: ~10 ms; fork of a
/// template: 1.3-2.9 ms.
const STARTUP_BUDGET: Duration = Duration::from_millis(30);
const TEMPLATE_STARTUP_BUDGET: Duration = Duration::from_millis(10);
/// PSS per idle sandbox, 8 at once. Tier A: ~4.2 MB cold with the small config (the kernel's pool
/// and data are each sandbox's own); 1.8-2.9 MB forked from a template (fork mode the most).
const MEM_STANDALONE_BUDGET_KB: u64 = 5 * 1024;
const MEM_TEMPLATE_BUDGET_KB: u64 = 3 * 1024;
/// Wall time against native for parallel work. Tier A: xz -T4 4.9 s against 5.1 native (lazy host
/// threads); make -j4 of GNU hello 2.8 s against 0.8 (fork and exec dominate).
const PARALLEL_RATIO: f64 = 1.5;
const BUILD_RATIO: f64 = 4.0;

fn main() {
    let args = Arguments::from_args();
    let mut trials = vec![];
    for mode in ALL {
        let m = mode.name();
        trials.push(Trial::test(format!("syscalls::{m}"), move || syscalls(mode)));
        trials.push(Trial::test(format!("startup::{m}"), move || startup(mode)));
        trials.push(Trial::test(format!("mem_standalone::{m}"), move || mem_standalone(mode)));
        trials.push(Trial::test(format!("template::{m}"), move || template(mode)));
        trials.push(Trial::test(format!("compute::{m}"), move || compute(mode)));
    }
    trials.push(Trial::test("xz::threaded", || xz(Mode::Threaded)));
    trials.push(Trial::test("xz::fork", || xz(Mode::Fork)));
    trials.push(Trial::test("make::fork", make));
    libtest_mimic::run(&args, trials).exit();
}

/// `exobox run` in `mode`, the fixtures and `extra` allowed (a store path brings its closure).
fn sandboxed(mode: Mode, prog: &Path, extra: &[PathBuf]) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_exobox"));
    cmd.args(["run", "--mode", mode.name(), "--allow-path"]).arg(fx::bin_dir());
    for p in extra {
        cmd.arg("--allow-path").arg(p);
    }
    cmd.arg("--").arg(prog);
    cmd
}

fn external(var: &str) -> Result<PathBuf, Failed> {
    env::var_os(var).map(PathBuf::from).ok_or_else(|| format!("{var} unset: run in the devshell (./test --perf)").into())
}

/// The store path a program in the store belongs to (`/nix/store/<hash>-<name>`).
fn store_path(p: &Path) -> PathBuf {
    p.ancestors().find(|a| a.parent() == Some(Path::new("/nix/store"))).unwrap_or(p).to_path_buf()
}

/// Runs to the end; fails on a nonzero status. Returns stdout and the wall time.
fn run_ok(mut cmd: Command, timeout: Duration) -> Result<(String, Duration), Failed> {
    cmd.stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let t = Instant::now();
    let (status, _, out, err) = spawn_bounded(cmd, None, timeout)?;
    let wall = t.elapsed();
    if !status.success() {
        return Err(format!("{status:?}\n--- stdout:\n{out}\n--- stderr:\n{err}").into());
    }
    Ok((out, wall))
}

/// The best wall time of `n` runs.
fn best_of(n: usize, mut make: impl FnMut() -> Command, timeout: Duration) -> Result<Duration, Failed> {
    let mut best = Duration::MAX;
    for _ in 0..n {
        best = best.min(run_ok(make(), timeout)?.1);
    }
    Ok(best)
}

fn ratio_check(what: &str, sandboxed: Duration, native: Duration, budget: f64) -> Result<(), Failed> {
    let r = sandboxed.as_secs_f64() / native.as_secs_f64();
    println!("{what}: {sandboxed:?} sandboxed, {native:?} native: {r:.2}x (budget {budget}x)");
    if r > budget { Err(format!("{what}: {r:.2}x native, over {budget}x").into()) } else { Ok(()) }
}

fn syscalls(mode: Mode) -> Result<(), Failed> {
    let prog = fx::bin("syscall_bench");
    let (native, _) = run_ok(Command::new(&prog), Duration::from_secs(10))?;
    let (out, _) = run_ok(sandboxed(mode, &prog, &[]), Duration::from_secs(10))?;
    let parse = |s: &str, op: &str| -> Option<f64> {
        s.lines().find_map(|l| l.strip_prefix(op)?.strip_prefix(' ')?.parse().ok())
    };
    let mut over = vec![];
    for &(op, budget) in SYSCALL_BUDGET_NS {
        let got = parse(&out, op).ok_or_else(|| format!("no {op} line in:\n{out}"))?;
        let nat = parse(&native, op).unwrap_or(f64::NAN);
        println!("{op}: {got:.0} ns ({nat:.0} native; budget {budget:.0})");
        if got > budget {
            over.push(format!("{op} {got:.0} ns > {budget:.0}"));
        }
    }
    if over.is_empty() { Ok(()) } else { Err(over.join("; ").into()) }
}

/// Starts `cmd` (stdin and stdout piped) and waits for READY on its stdout.
fn spawn_ready(mut cmd: Command) -> Result<(Child, Duration), Failed> {
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::inherit());
    let t = Instant::now();
    let mut child = cmd.spawn().map_err(|e| format!("spawn: {e}"))?;
    let out = child.stdout.take().unwrap();
    let ready = wait_ready(out, Duration::from_secs(5));
    let elapsed = t.elapsed();
    if let Err(e) = ready {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    Ok((child, elapsed))
}

fn wait_ready(r: impl std::io::Read + Send + 'static, timeout: Duration) -> Result<(), Failed> {
    let (tx, rx) = std::sync::mpsc::channel();
    thread::spawn(move || {
        let mut line = String::new();
        let mut r = BufReader::new(r);
        let ok = loop {
            line.clear();
            match r.read_line(&mut line) {
                Ok(0) | Err(_) => break false,
                Ok(_) if line.trim() == "READY" => break true,
                Ok(_) => {}
            }
        };
        let _ = tx.send(ok);
        // Keep draining, so the program never blocks on a full pipe.
        let _ = std::io::copy(&mut r, &mut std::io::sink());
    });
    match rx.recv_timeout(timeout) {
        Ok(true) => Ok(()),
        Ok(false) => Err("exited before READY".into()),
        Err(_) => Err(format!("no READY within {timeout:?}").into()),
    }
}

fn stop(mut child: Child) {
    drop(child.stdin.take());
    let _ = child.wait();
}

fn startup(mode: Mode) -> Result<(), Failed> {
    let mut times = vec![];
    for _ in 0..5 {
        let (child, t) = spawn_ready(sandboxed(mode, &fx::bin("ready_idle"), &[]))?;
        stop(child);
        times.push(t);
    }
    times.sort();
    let median = times[2];
    println!("start to READY: median {median:?} of {times:?} (budget {STARTUP_BUDGET:?})");
    if median > STARTUP_BUDGET { Err(format!("startup {median:?} > {STARTUP_BUDGET:?}").into()) } else { Ok(()) }
}

/// Proportional set size of a process, in KB.
fn pss_kb(pid: u32) -> Result<u64, Failed> {
    let s = fs::read_to_string(format!("/proc/{pid}/smaps_rollup")).map_err(|e| format!("smaps_rollup: {e}"))?;
    s.lines()
        .find_map(|l| l.strip_prefix("Pss:")?.trim().strip_suffix("kB")?.trim().parse().ok())
        .ok_or_else(|| "no Pss line".into())
}

const N: usize = 8;

fn mem_standalone(mode: Mode) -> Result<(), Failed> {
    let measure = |make: &dyn Fn() -> Command| -> Result<u64, Failed> {
        let mut kids = vec![];
        for _ in 0..N {
            kids.push(spawn_ready(make())?.0);
        }
        thread::sleep(Duration::from_millis(200));
        let total: Result<u64, Failed> = kids.iter().map(|c| pss_kb(c.id())).sum();
        kids.into_iter().for_each(stop);
        Ok(total? / N as u64)
    };
    let native = measure(&|| Command::new(fx::bin("ready_idle")))?;
    let per = measure(&|| sandboxed(mode, &fx::bin("ready_idle"), &[]))?;
    println!("PSS per idle sandbox, {N} at once: {per} KB ({native} KB native; budget {MEM_STANDALONE_BUDGET_KB} KB)");
    if per > MEM_STANDALONE_BUDGET_KB {
        return Err(format!("{per} KB per sandbox > {MEM_STANDALONE_BUDGET_KB} KB").into());
    }
    Ok(())
}

/// Startup and memory of sandboxes forked from one template.
fn template(mode: Mode) -> Result<(), Failed> {
    let config = exobox::Config { mode: mode.config(), allow_paths: vec![fx::bin_dir()], ..Default::default() };
    let tmpl = exobox::Template::start(config).map_err(|e| e.to_string())?;
    let mut kids = vec![];
    let mut times = vec![];
    for _ in 0..N {
        let (stdin_r, stdin_w) = std::io::pipe()?;
        let (stdout_r, stdout_w) = std::io::pipe()?;
        let stderr = std::io::stderr().as_fd_owned()?;
        let t = Instant::now();
        let pid = tmpl
            .spawn(&[OsString::from(fx::bin("ready_idle"))], [stdin_r.into(), stdout_w.into(), stderr])
            .map_err(|e| e.to_string())?;
        wait_ready(stdout_r, Duration::from_secs(5))?;
        times.push(t.elapsed());
        kids.push((pid, stdin_w));
    }
    thread::sleep(Duration::from_millis(200));
    let total: Result<u64, Failed> = kids.iter().map(|(pid, _)| pss_kb(*pid)).sum();
    let per = total? / N as u64;
    drop(kids); // stdin's end: each child exits
    times.sort();
    let median = times[N / 2];
    println!("template children: start to READY median {median:?} (budget {TEMPLATE_STARTUP_BUDGET:?}); PSS {per} KB each (budget {MEM_TEMPLATE_BUDGET_KB} KB)");
    let mut over = vec![];
    if median > TEMPLATE_STARTUP_BUDGET {
        over.push(format!("startup {median:?}"));
    }
    if per > MEM_TEMPLATE_BUDGET_KB {
        over.push(format!("{per} KB per child"));
    }
    if over.is_empty() { Ok(()) } else { Err(over.join("; ").into()) }
}

trait AsFdOwned {
    fn as_fd_owned(&self) -> std::io::Result<std::os::fd::OwnedFd>;
}

impl AsFdOwned for std::io::Stderr {
    fn as_fd_owned(&self) -> std::io::Result<std::os::fd::OwnedFd> {
        use std::os::fd::AsFd;
        self.as_fd().try_clone_to_owned()
    }
}

/// Four CPU-bound threads. Host threads run them in parallel (budget against native); a
/// coroutine sandbox runs them one at a time, which is reported, not checked.
fn compute(mode: Mode) -> Result<(), Failed> {
    let prog = fx::bin("par_compute");
    let args = ["4", "100000000"];
    let native = best_of(3, || {
        let mut c = Command::new(&prog);
        c.args(args);
        c
    }, Duration::from_secs(10))?;
    let sb = best_of(3, || {
        let mut c = sandboxed(mode, &prog, &[]);
        c.args(args);
        c
    }, Duration::from_secs(20))?;
    match mode {
        Mode::Coroutine => {
            println!("4 compute threads: {sb:?} as coroutines, {native:?} native (not checked: one host thread)");
            Ok(())
        }
        _ => ratio_check("4 compute threads", sb, native, PARALLEL_RATIO),
    }
}

/// A deterministic 16 MB of compressible text, in `dir`.
fn xz_input(dir: &Path) -> Result<PathBuf, Failed> {
    let f = dir.join("input.txt");
    {
        let mut w = std::io::BufWriter::new(fs::File::create(&f)?);
        let mut x: u64 = 0x9e3779b97f4a7c15;
        let words = ["sandbox", "kernel", "seccomp", "arena", "coroutine", "thread", "fork", "store", "\n"];
        let mut n = 0;
        while n < 16 << 20 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let word = words[(x % words.len() as u64) as usize];
            w.write_all(word.as_bytes())?;
            w.write_all(b" ")?;
            n += word.len() + 1;
        }
    }
    Ok(f)
}

/// xz -T4 on 16 MB: threads that compute and make syscalls. 2 MiB blocks, so the input splits
/// across the threads (xz's default block is 3x the dictionary: 24 MB at -6, one thread here).
fn xz(mode: Mode) -> Result<(), Failed> {
    let xz = external("EXOBOX_TEST_XZ")?;
    let dir = tempfile::tempdir()?;
    let input = xz_input(dir.path())?;
    let args = |c: &mut Command| {
        c.args(["-T4", "-3", "--block-size=2MiB", "-c"]).arg(&input);
    };
    let native = best_of(2, || {
        let mut c = Command::new(&xz);
        args(&mut c);
        c
    }, Duration::from_secs(20))?;
    let sb = best_of(2, || {
        let mut c = sandboxed(mode, &xz, &[store_path(&xz), input.parent().unwrap().to_path_buf()]);
        args(&mut c);
        c
    }, Duration::from_secs(30))?;
    ratio_check("xz -T4, 16 MB", sb, native, PARALLEL_RATIO)
}

/// A C build: 16 files compiled by make -j4 (fork, exec, pipes, threads), from a copy in a
/// writable directory.
fn make() -> Result<(), Failed> {
    let (bash, make, gcc, coreutils) = (
        external("EXOBOX_TEST_BASH")?,
        external("EXOBOX_TEST_MAKE")?,
        external("EXOBOX_TEST_GCC")?,
        external("EXOBOX_TEST_COREUTILS")?,
    );
    let tmp = tempfile::tempdir()?;
    let src = tmp.path().join("src");
    fs::create_dir_all(&src)?;
    let mut objs = vec![];
    for i in 0..16 {
        let body: String = (0..40)
            .map(|j| format!("int f{i}_{j}(int x) {{ int s = 0; for (int k = 0; k < x; k++) s += k * {j} ^ {i}; return s; }}\n"))
            .collect();
        fs::write(src.join(format!("f{i}.c")), body)?;
        objs.push(format!("f{i}.o"));
    }
    fs::write(src.join("main.c"), "int main(void) { return 0; }\n")?;
    fs::write(
        src.join("Makefile"),
        format!("prog: main.o {o}\n\t$(CC) -o $@ $^\n%.o: %.c\n\t$(CC) -O2 -c -o $@ $<\n", o = objs.join(" ")),
    )?;
    let path = [&gcc, &make, &coreutils.join("bin")]
        .iter()
        .map(|p| if p.is_file() { p.parent().unwrap().display().to_string() } else { p.display().to_string() })
        .collect::<Vec<_>>()
        .join(":");
    let script = |work: &Path| {
        format!(
            "set -e; rm -rf {w}; cp -r {s} {w}; make -s -C {w} -j4 CC=gcc; {w}/prog",
            w = work.display(),
            s = src.display()
        )
    };
    let native_work = tmp.path().join("native");
    let native = best_of(2, || {
        let mut c = Command::new(&bash);
        c.env("PATH", &path).arg("-c").arg(script(&native_work));
        c
    }, Duration::from_secs(30))?;
    let extra = [&bash, &make, &gcc, &coreutils].iter().map(|p| store_path(p)).chain([src.clone()]).collect::<Vec<_>>();
    let sb = best_of(2, || {
        let mut c = sandboxed(Mode::Fork, &bash, &extra);
        c.env("PATH", &path).arg("-c").arg(script(Path::new("/tmp/build")));
        c
    }, Duration::from_secs(60))?;
    ratio_check("make -j4, 16 files", sb, native, BUILD_RATIO)
}
