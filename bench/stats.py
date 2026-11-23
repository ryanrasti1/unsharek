#!/usr/bin/env python3
"""The headline numbers (README.md's, bench/STATS.md): what a sandbox costs against native, in
memory, startup, a syscall and CPU time. `cargo xtask stats` (bench/stats builds first) prints the
table and writes bench/STATS.md.

Each number is the median of --reps runs, with the spread (min-max) beside it. Nothing new is
measured here that quick.py or perf.rs already measure: the CPU workloads and the getppid cost are
quick.py's (its setup), a template child's PSS is perf.rs's `template` trial (its
UNSHAREK_STATS_OUT report). Measures only on a quiet machine: before each section the load and
the I/O pressure are checked, and it waits (up to --wait seconds) for them to settle; past that
it stops, rather than publish numbers taken under load (--force to measure anyway, marked).
"""

import argparse
import datetime
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import build_bench as bb  # noqa: E402
import quick  # noqa: E402

MODES = ['coroutine', 'threaded', 'fork']


def io_pressure():
    try:
        line = open('/proc/pressure/io').readline()
        return float(line.split('avg10=')[1].split()[0])
    except (OSError, IndexError, ValueError):
        return 0.0


class Quiet:
    """Waits for a quiet machine: 1-minute load under `load`, I/O pressure (some, 10 s) under 5%."""

    def __init__(self, load, wait, force):
        self.load, self.wait, self.force, self.loaded = load, wait, force, False

    def __call__(self, what):
        t = time.monotonic()
        while True:
            l1, p = os.getloadavg()[0], io_pressure()
            if l1 <= self.load and p <= 5.0:
                return
            if time.monotonic() - t > self.wait:
                if self.force:
                    print(f'  {what}: measuring under load (load {l1:.1f}, I/O pressure {p:.0f}%): --force')
                    self.loaded = True
                    return
                sys.exit(f'stats: the machine is busy (load {l1:.1f}, I/O pressure {p:.0f}%) after '
                         f'{self.wait} s: not measuring ({what}); --wait longer or --force')
            print(f'  {what}: waiting for a quiet machine (load {l1:.1f}, I/O pressure {p:.0f}%)')
            time.sleep(10)


def med(v):
    """Median and spread (min-max) of `v`."""
    return statistics.median(v), min(v), max(v)


def own_userns():
    # A user namespace of the parent's own: its owner may read a sandbox's smaps_rollup, which
    # lockdown's PR_SET_DUMPABLE 0 closes (perf.rs's own_userns).
    os.unshare(os.CLONE_NEWUSER)


def proc_kb(pid, path, key):
    for line in open(f'/proc/{pid}/{path}'):
        if line.startswith(key):
            return int(line.split()[1])
    raise RuntimeError(f'no {key} in /proc/{pid}/{path}')


def idle_memory(exe, bash, n):
    """RSS and PSS (MB) per idle bash, `n` at once, natively and in each mode: `read` on a pipe
    that stays open, after READY."""
    argv = [bash, '-c', 'echo READY; read x']
    out = {}
    for m in ['native'] + MODES:
        cmd = argv if m == 'native' else bb.sandboxed(exe, m, [bb.store_path(bash)], argv)
        kids = []
        try:
            for _ in range(n):
                p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     preexec_fn=own_userns)
                if p.stdout.readline().strip() != b'READY':
                    raise RuntimeError(f'idle bash ({m}): no READY')
                kids.append(p)
            time.sleep(0.3)
            rss = [proc_kb(k.pid, 'status', 'VmRSS:') for k in kids]
            pss = [proc_kb(k.pid, 'smaps_rollup', 'Pss:') for k in kids]
            out[m] = (statistics.median(rss) / 1024, sum(pss) / n / 1024)
        finally:
            for k in kids:
                k.stdin.close()
                k.wait(timeout=10)
    return out


def template_pss(reps):
    """perf.rs's template trial, coroutine and threaded: PSS per child (MB) and start to READY (ms)."""
    got = {}
    for _ in range(reps):
        with tempfile.NamedTemporaryFile('r', suffix='.stats') as f:
            env = dict(os.environ, UNSHAREK_STATS_OUT=f.name)
            r = subprocess.run(['cargo', 'nextest', 'run', '--release', '-p', 'unsharek', '--test', 'perf',
                                '--profile', 'perf', '--no-fail-fast', '-E', 'test(/^template::(coroutine|threaded)$/)'],
                               cwd=bb.ROOT, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            if r.returncode != 0:
                raise RuntimeError('perf.rs template trials failed:\n' + r.stderr[-2000:])
            for line in f:
                key, mode, v = line.split()
                got.setdefault((key, mode), []).append(float(v))
    return got


def timed(cmd, env, reps, timeout=120):
    ws = []
    for _ in range(reps):
        st, wall, *_ = bb.run(cmd, timeout, env=env)
        if st != 0:
            raise RuntimeError(f'{cmd[:4]}...: status {st}')
        ws.append(wall)
    return ws


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--reps', type=int, default=3)
    ap.add_argument('--n', type=int, default=8, help='idle sandboxes at once (memory)')
    ap.add_argument('--unsharek', default=os.path.join(bb.TARGET, 'release', 'unsharek'))
    ap.add_argument('--load', type=float, default=4.0, help='the most 1-minute load to measure at')
    ap.add_argument('--wait', type=int, default=600, help='seconds to wait for a quiet machine')
    ap.add_argument('--force', action='store_true', help='measure even when busy (marked in the output)')
    ap.add_argument('--out', default=os.path.join(bb.ROOT, 'bench', 'STATS.md'))
    ap.add_argument('--tmp', default=os.path.join(bb.TARGET, 'vs-native'))
    a = ap.parse_args()
    quiet = Quiet(a.load, a.wait, a.force)
    os.makedirs(a.tmp, exist_ok=True)
    exe = a.unsharek
    fx = quick.fixtures()
    w = quick.setup(a.tmp, fx)
    bash = os.environ['UNSHAREK_TEST_BASH']
    xz = os.environ['UNSHAREK_TEST_XZ']
    t0 = time.monotonic()
    rows = []  # (metric, unit, native (med,lo,hi) | None, {mode: (med,lo,hi)})

    quiet('memory')
    mem = idle_memory(exe, bash, a.n)
    rows.append(('idle bash, RSS', 'MB', (mem['native'][0],) * 3, {m: (mem[m][0],) * 3 for m in MODES}))
    rows.append((f'idle bash, PSS ({a.n} at once)', 'MB', (mem['native'][1],) * 3, {m: (mem[m][1],) * 3 for m in MODES}))
    quiet('templates')
    tp = template_pss(a.reps)
    rows.append((f'template child, PSS ({perf_n()} at once)', 'MB', None,
                 {m: med([v / 1024 for v in tp[('template_pss_kb', m)]]) for m in ('coroutine', 'threaded')}))
    rows.append(('template child, start to READY', 'ms', None,
                 {m: med(tp[('template_ready_ms', m)]) for m in ('coroutine', 'threaded')}))

    quiet('startup')
    hello = [os.path.join(fx, 'hello')]
    nat = med([s * 1e3 for s in timed(hello, None, a.reps * 3)])
    rows.append(('hello, start to exit', 'ms', nat,
                 {m: med([s * 1e3 for s in timed(bb.sandboxed(exe, m, [fx], hello), None, a.reps * 3)]) for m in MODES}))

    quiet('syscalls')
    sb, _, allow = w['micro']

    def getppid(cmd):
        v = []
        for _ in range(a.reps):
            st, _, _, _, out, err, _ = bb.run(cmd, 60)
            if st != 0:
                raise RuntimeError(f'syscall_bench: status {st}: {err[-300:]}')
            v.append(quick.parse_micro(out)['getppid'] / 1e3)
        return med(v)
    rows.append(('getppid', 'µs', getppid(sb), {m: getppid(bb.sandboxed(exe, m, allow, sb)) for m in MODES}))

    quiet('CPU')
    _, _, xallow, _ = w['xz']
    inp = os.path.join(a.tmp, 'xz', 'input.txt')
    for threads in (1, 4):
        argv = [xz, f'-T{threads}', '-3', '--block-size=1MiB', '-c', inp]
        rows.append((f'xz -T{threads}, 8 MB', 's', med(timed(argv, None, a.reps)),
                     {m: med(timed(bb.sandboxed(exe, m, xallow, argv), None, a.reps)) for m in MODES}))
    native, sb_make, mallow, menv = w['make']
    sandbox_env = dict(menv, PATH=menv['PATH'] + ':' + os.environ.get('PATH', ''))
    rows.append(('make -j4, 12 C files', 's', med(timed(native(), menv, a.reps)),
                 {'fork': med(timed(bb.sandboxed(exe, 'fork', mallow, sb_make(), max_procs=32), sandbox_env, a.reps))}))
    native, sb_rustc, rallow, _ = w['rustc']
    rows.append(('rustc, 16 codegen units', 's', med(timed(native(), None, a.reps)),
                 {m: med(timed(bb.sandboxed(exe, m, rallow, sb_rustc()), None, a.reps)) for m in ('threaded', 'fork')}))

    took = time.monotonic() - t0
    table = render(rows)
    head = header(a, took, quiet.loaded)
    print(head + table)
    open(a.out, 'w').write(head + table + FOOT)


def perf_n():
    return 8  # perf.rs's N


def fmt(v, unit):
    d = 0 if unit == 'ms' and v[0] >= 10 else 2 if unit in ('s', 'µs') else 1
    m, lo, hi = v
    s = f'{m:.{d}f}'
    return s if lo == hi else f'{s} ({lo:.{d}f}-{hi:.{d}f})'


def render(rows):
    out = ['| | native | ' + ' | '.join(MODES) + ' |', '|---|---|' + '---|' * len(MODES)]
    for name, unit, nat, per in rows:
        cells = []
        for m in MODES:
            v = per.get(m)
            if not v:
                cells.append('-')
            elif nat and unit in ('s', 'µs', 'ms'):
                cells.append(f'{fmt(v, unit)} {unit}, {v[0] / nat[0]:.2f}x')
            else:
                cells.append(f'{fmt(v, unit)} {unit}')
        out.append(f'| {name} | ' + (f'{fmt(nat, unit)} {unit}' if nat else '-') + ' | ' + ' | '.join(cells) + ' |')
    return '\n'.join(out) + '\n'


def header(a, took, loaded):
    cpu = next((l.split(':', 1)[1].strip() for l in open('/proc/cpuinfo') if l.startswith('model name')), '?')
    rev = subprocess.run(['git', 'describe', '--always', '--dirty'], cwd=bb.ROOT, capture_output=True, text=True).stdout.strip()
    when = datetime.date.today().isoformat()
    note = '\n**Measured under load (--force): not for publishing.**\n' if loaded else ''
    return (f'# unsharek: headline numbers\n\n'
            f'`cargo xtask stats` ({when}, commit {rev}; {cpu}, {os.cpu_count()} CPUs, Linux '
            f'{platform.release()}; median of {a.reps}, spread in parentheses; {took:.0f} s to run). '
            f'bench/README.md says what each row measures.\n{note}\n')


FOOT = '''
Ratios are to native. Fork mode is the only one that runs `make` (it forks). A template child is
a sandbox forked from a booted, set-up one (`Guest::spawn`); fork-mode templates don't exist yet.
'''

if __name__ == '__main__':
    main()
