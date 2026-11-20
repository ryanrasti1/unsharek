//! The loader against real programs: the fixtures (a static PIE, a static non-PIE, a dynamic PIE
//! and a dynamic non-PIE with their ld.so), the devshell's bash, `#!` scripts, and broken copies.
//! Files come from the host through a fake guest filesystem; the arena is a real reservation.
//! Each image is checked against its own headers (read with `object`, independently of the
//! loader's code path), each stack is parsed back as libc would, and the static programs are run
//! for real in a forked child.

use super::*;
use crate::arena::{Extent, Mapping};
use object::read::elf::ElfFile64;
use std::collections::HashMap;
use std::ffi::{CStr, OsStr};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const MIB: usize = 1 << 20;

/// The guest's files: host files read whole at open, or in-memory ones added by a test (which
/// shadow the host's). Counts open handles so tests can check none leak.
#[derive(Default)]
struct Fs {
    files: Vec<Option<Vec<u8>>>,
    extra: HashMap<Vec<u8>, Vec<u8>>,
    open: usize,
}

impl Fs {
    fn add(&mut self, path: &[u8], data: Vec<u8>) {
        self.extra.insert(path.to_vec(), data);
    }
    fn data(&self, file: u64) -> &[u8] {
        self.files[file as usize].as_deref().expect("a closed handle")
    }
}

impl Files for Fs {
    fn open(&mut self, path: &[u8]) -> Result<u64> {
        let data = match self.extra.get(path) {
            Some(d) => d.clone(),
            None => std::fs::read(OsStr::from_bytes(path))
                .map_err(|e| Errno::from_raw_os_error(e.raw_os_error().unwrap_or(libc::EIO)))?,
        };
        self.files.push(Some(data));
        self.open += 1;
        Ok(self.files.len() as u64 - 1)
    }
    fn size(&mut self, file: u64) -> Result<u64> {
        Ok(self.data(file).len() as u64)
    }
    fn pread(&mut self, file: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let d = self.data(file);
        let at = (offset as usize).min(d.len());
        let n = buf.len().min(d.len() - at);
        buf[..n].copy_from_slice(&d[at..at + n]);
        Ok(n)
    }
    fn close_file(&mut self, file: u64) {
        assert!(self.files[file as usize].take().is_some(), "closed twice");
        self.open -= 1;
    }
}

impl Backing for Fs {
    fn read(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> Result<usize> {
        // SAFETY: the arena passes addresses inside its reservation.
        let buf = unsafe { std::slice::from_raw_parts_mut(addr as *mut u8, len) };
        self.pread(file, offset, buf)
    }
    fn write(&mut self, _: u64, _: u64, _: usize, _: usize) -> Result<usize> {
        Err(Errno::ACCESS)
    }
    fn retain(&mut self, _: u64) -> Result<u64> {
        Err(Errno::ACCESS)
    }
    fn close(&mut self, _: u64) {}
}

/// A read/write/execute reservation, as the runtime makes before lockdown; at `at` exactly if given.
struct Reservation {
    base: usize,
    len: usize,
}

impl Reservation {
    fn new(at: Option<usize>, len: usize) -> Reservation {
        let flags = libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE;
        let (hint, flags) = match at {
            Some(a) => (a, flags | libc::MAP_FIXED_NOREPLACE),
            None => (0, flags),
        };
        let prot = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
        // SAFETY: a fresh mapping; NOREPLACE never replaces anything.
        let p = unsafe { libc::mmap(hint as *mut _, len, prot, flags, -1, 0) };
        assert_ne!(p, libc::MAP_FAILED, "reserve at {at:x?}: {}", std::io::Error::last_os_error());
        Reservation { base: p as usize, len }
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: ours.
        unsafe { libc::munmap(self.base as *mut _, self.len) };
    }
}

/// Where the non-PIE fixtures are linked: the x86-64 linkers' default base.
const NOPIE_BASE: usize = 0x400000;

fn fixture(name: &str) -> PathBuf {
    exobox_fixtures::bin(name)
}

fn bytes(p: &Path) -> &[u8] {
    p.as_os_str().as_bytes()
}

fn params<'a>(execfn: &'a [u8], argv: &'a [&'a [u8]], envp: &'a [&'a [u8]]) -> StackParams<'a> {
    StackParams {
        execfn,
        argv,
        envp,
        uid: 1000,
        euid: 1001,
        gid: 100,
        egid: 101,
        random: *b"0123456789abcdef",
        // SAFETY: getauxval reads the process's own vector.
        hwcap: unsafe { libc::getauxval(libc::AT_HWCAP) },
        hwcap2: unsafe { libc::getauxval(libc::AT_HWCAP2) },
        sysinfo_ehdr: unsafe { libc::getauxval(libc::AT_SYSINFO_EHDR) },
        minsigstksz: unsafe { libc::getauxval(AT_MINSIGSTKSZ) }.max(2048),
        gate: 0xdead_beef,
    }
}

fn prot_at(a: &Arena, addr: usize) -> Option<u32> {
    a.mappings().find(|m: &Mapping| m.start <= addr && addr < m.end).map(|m| m.prot)
}

/// The PT_LOADs of `data`, read with `object`: (offset, vaddr, filesz, memsz, prot).
fn loads(data: &[u8]) -> Vec<(usize, usize, usize, usize, u32)> {
    let f = ElfFile64::<LE>::parse(data).unwrap();
    f.elf_program_headers()
        .iter()
        .filter(|p| p.p_type(LE) == elf::PT_LOAD)
        .map(|p| {
            (p.p_offset(LE) as usize, p.p_vaddr(LE) as usize, p.p_filesz(LE) as usize, p.p_memsz(LE) as usize, prot_of(p.p_flags(LE)))
        })
        .collect()
}

/// Check one image in the arena against its file: every segment's file bytes at bias + vaddr,
/// zeros after them (the .bss, and the rest of the last page when there is one), and every page
/// that belongs to this segment alone mapped with its protection. Returns the largest p_align.
fn check_image(a: &Arena, data: &[u8], bias: usize) -> u64 {
    let ls = loads(data);
    for (i, &(off, va, filesz, memsz, prot)) in ls.iter().enumerate() {
        let at = bias + va;
        // SAFETY: mapped by the loader, inside the reservation.
        let mem = unsafe { std::slice::from_raw_parts(at as *const u8, memsz) };
        assert_eq!(&mem[..filesz], &data[off..off + filesz], "segment {i} at {at:#x}: the file's bytes");
        assert!(mem[filesz..].iter().all(|&b| b == 0), "segment {i}: .bss not zero");
        if memsz > filesz {
            let end = at + filesz;
            let page_end = (end + PAGE - 1) & !(PAGE - 1);
            // SAFETY: as above (the page is mapped).
            let tail = unsafe { std::slice::from_raw_parts(end as *const u8, page_end - end) };
            assert!(tail.iter().all(|&b| b == 0), "segment {i}: last file page's tail not zero");
        }
        let shared = |p: usize| {
            ls.iter().enumerate().any(|(j, &(_, v, _, m, _))| {
                j != i && (bias + v) & !(PAGE - 1) <= p && p < bias + v + m
            })
        };
        let mut p = at & !(PAGE - 1);
        while p < at + memsz {
            if !shared(p) {
                assert_eq!(prot_at(a, p), Some(prot), "segment {i}: page {p:#x}'s protection");
            }
            p += PAGE;
        }
    }
    let f = ElfFile64::<LE>::parse(data).unwrap();
    f.elf_program_headers().iter().filter(|p| p.p_type(LE) == elf::PT_LOAD).map(|p| p.p_align(LE)).max().unwrap()
}

/// What the image must say about its file: entry, phdr, and the start (the interpreter's entry if any).
fn check_entry(img: &Image, data: &[u8], interp: Option<&[u8]>) {
    let f = ElfFile64::<LE>::parse(data).unwrap();
    let h = f.elf_header();
    assert_eq!(img.entry, img.bias + h.e_entry(LE) as usize);
    assert_eq!(img.phnum, h.e_phnum(LE) as usize);
    // The headers in memory are the file's.
    // SAFETY: AT_PHDR points into the mapped image.
    let mem = unsafe { std::slice::from_raw_parts(img.phdr as *const u8, img.phnum * PHENT) };
    let off = h.e_phoff(LE) as usize;
    assert_eq!(mem, &data[off..off + img.phnum * PHENT], "AT_PHDR");
    match interp {
        None => {
            assert_eq!(img.interp_base, 0);
            assert_eq!(img.start, img.entry);
        }
        Some(i) => {
            let ih = ElfFile64::<LE>::parse(i).unwrap();
            assert_ne!(img.interp_base, 0);
            assert_eq!(img.start, img.interp_base + ih.elf_header().e_entry(LE) as usize);
        }
    }
}

fn interp_of(data: &[u8]) -> Option<Vec<u8>> {
    let f = ElfFile64::<LE>::parse(data).unwrap();
    let ph = f.elf_program_headers().iter().find(|p| p.p_type(LE) == elf::PT_INTERP)?;
    let raw = &data[ph.p_offset(LE) as usize..][..ph.p_filesz(LE) as usize];
    Some(CStr::from_bytes_until_nul(raw).unwrap().to_bytes().to_vec())
}


/// Load `path` into `a` and check the images; also returns the interpreter's bytes, if any.
/// `fixed`: an ET_EXEC.
fn load_and_check<'s>(a: &mut Arena, fs: &mut Fs, s: &'s mut Scratch, path: &Path, fixed: bool) -> (Image<'s>, Option<Vec<u8>>) {
    let prog = Program::open(fs, s, bytes(path)).unwrap();
    let img = prog.map(a, fs).unwrap();
    assert_eq!(fs.open, 0, "files left open");
    let data = std::fs::read(path).unwrap();
    let align = check_image(a, &data, img.bias);
    if fixed {
        assert_eq!(img.bias, 0);
    } else {
        assert_eq!(img.bias % align.max(PAGE as u64) as usize, 0, "PIE base aligned to p_align");
        assert!(a.contains(img.bias, PAGE));
    }
    let interp = interp_of(&data).map(|p| std::fs::read(OsStr::from_bytes(&p)).unwrap());
    if let Some(i) = &interp {
        let ialign = check_image(a, i, img.interp_base);
        assert_eq!(img.interp_base % ialign.max(PAGE as u64) as usize, 0);
    }
    check_entry(&img, &data, interp.as_deref());
    // brk: the end of the program's highest segment, page-aligned.
    let end = loads(&data).iter().map(|l| img.bias + l.1 + l.3).max().unwrap();
    assert_eq!(img.brk, (end + PAGE - 1) & !(PAGE - 1));
    assert_eq!(a.brk(0), img.brk);
    (img, interp)
}

fn table() -> Vec<Extent> {
    vec![Extent::EMPTY; 4096]
}

fn arena<'t>(r: &Reservation, t: &'t mut [Extent]) -> Arena<'t> {
    // SAFETY: a fresh reservation, all zero, ours alone while the arena lives.
    unsafe { Arena::new(r.base, r.len, t) }.unwrap()
}

/// The stack parsed back as libc's start code does.
#[derive(Debug)]
struct Parsed {
    argv: Vec<Vec<u8>>,
    envp: Vec<Vec<u8>>,
    auxv: Vec<(u64, u64)>,
}

fn cstr(p: u64, lo: usize, top: usize) -> Vec<u8> {
    assert!((lo..top).contains(&(p as usize)), "string {p:#x} outside the stack");
    // SAFETY: inside the stack, NUL-terminated by build_stack.
    let s = unsafe { CStr::from_ptr(p as *const _) }.to_bytes().to_vec();
    assert!(p as usize + s.len() < top);
    s
}

fn parse_stack(rsp: usize, lo: usize, top: usize) -> Parsed {
    assert_eq!(rsp % 16, 0, "rsp must be 16-aligned at the entry");
    assert!(rsp >= lo && rsp < top);
    let w = |i: usize| unsafe { *((rsp + 8 * i) as *const u64) };
    let argc = w(0) as usize;
    let argv = (0..argc).map(|i| cstr(w(1 + i), lo, top)).collect();
    assert_eq!(w(1 + argc), 0, "argv's NULL");
    let mut i = 2 + argc;
    let mut envp = vec![];
    while w(i) != 0 {
        envp.push(cstr(w(i), lo, top));
        i += 1;
    }
    i += 1;
    let mut auxv = vec![];
    loop {
        let (k, v) = (w(i), w(i + 1));
        auxv.push((k, v));
        i += 2;
        if k == AT_NULL {
            break;
        }
    }
    Parsed { argv, envp, auxv }
}

fn aux(p: &Parsed, k: u64) -> u64 {
    let v: Vec<_> = p.auxv.iter().filter(|e| e.0 == k).collect();
    assert_eq!(v.len(), 1, "auxv key {k} once");
    v[0].1
}

/// Map a stack in the arena and build it; parse it back and check every auxv entry.
fn stack_and_check(a: &mut Arena, fs: &mut Fs, img: &Image, p: &StackParams, want_argv: &[&[u8]]) -> (Start, Parsed) {
    let len = 256 * 1024;
    let lo = a.mmap(fs, 0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, None).unwrap();
    let top = lo + len;
    let start = unsafe { img.build_stack(lo, top, p) }.unwrap();
    assert_eq!(start.entry, img.start);
    let parsed = parse_stack(start.rsp, lo, top);
    assert_eq!(parsed.argv, want_argv);
    assert_eq!(parsed.envp, p.envp);
    assert_eq!(parsed.auxv.last(), Some(&(AT_NULL, 0)));
    let keys: Vec<u64> = parsed.auxv.iter().map(|e| e.0).collect();
    let mut dedup = keys.clone();
    dedup.sort();
    dedup.dedup();
    assert_eq!(dedup.len(), keys.len(), "auxv keys unique: {keys:?}");
    assert_eq!(aux(&parsed, AT_PHDR), img.phdr as u64);
    assert_eq!(aux(&parsed, AT_PHENT), 56);
    assert_eq!(aux(&parsed, AT_PHNUM), img.phnum as u64);
    assert_eq!(aux(&parsed, AT_PAGESZ), 4096);
    assert_eq!(aux(&parsed, AT_BASE), img.interp_base as u64);
    assert_eq!(aux(&parsed, AT_ENTRY), img.entry as u64);
    assert_eq!(aux(&parsed, AT_FLAGS), 0);
    assert_eq!(aux(&parsed, AT_UID), 1000);
    assert_eq!(aux(&parsed, AT_EUID), 1001);
    assert_eq!(aux(&parsed, AT_GID), 100);
    assert_eq!(aux(&parsed, AT_EGID), 101);
    assert_eq!(aux(&parsed, AT_SECURE), 0);
    assert_eq!(aux(&parsed, AT_HWCAP), p.hwcap);
    assert_eq!(aux(&parsed, AT_HWCAP2), p.hwcap2);
    assert_eq!(aux(&parsed, AT_MINSIGSTKSZ), p.minsigstksz);
    assert_eq!(aux(&parsed, AT_CLKTCK), 100);
    assert_eq!(aux(&parsed, AT_EXOBOX_GATE), 0xdead_beef);
    if p.sysinfo_ehdr != 0 {
        assert_eq!(aux(&parsed, AT_SYSINFO_EHDR), p.sysinfo_ehdr);
    }
    let r = aux(&parsed, AT_RANDOM) as usize;
    assert!(r >= lo && r + 16 <= top);
    assert_eq!(unsafe { std::slice::from_raw_parts(r as *const u8, 16) }, &p.random);
    assert_eq!(cstr(aux(&parsed, AT_PLATFORM), lo, top), b"x86_64");
    assert_eq!(cstr(aux(&parsed, AT_EXECFN), lo, top), p.execfn);
    // The strings sit above the vectors, argv's first, as Linux lays them out.
    let argv0 = unsafe { *((start.rsp + 8) as *const u64) } as usize;
    let vectors_end = start.rsp + 8 * (1 + parsed.argv.len() + 1 + parsed.envp.len() + 1 + 2 * parsed.auxv.len());
    assert!(argv0 >= vectors_end, "strings above the vectors");
    (start, parsed)
}

#[test]
fn static_pie() {
    let r = Reservation::new(None, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let path = fixture("static_start");
    let (img, interp) = load_and_check(&mut a, &mut fs, &mut s, &path, false);
    assert!(interp.is_none());
    let argv: &[&[u8]] = &[b"static_start", b"one"];
    let envp: &[&[u8]] = &[b"A=1", b"PATH=/bin"];
    stack_and_check(&mut a, &mut fs, &img, &params(bytes(&path), argv, envp), argv);
}

#[test]
fn static_nopie_at_its_address() {
    let r = Reservation::new(Some(NOPIE_BASE), 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let (img, _) = load_and_check(&mut a, &mut fs, &mut s, &fixture("static_start_nopie"), true);
    assert_eq!(img.entry & !0xfffff, NOPIE_BASE, "linked at 0x400000");
}

#[test]
fn nopie_outside_the_arena_is_enoexec() {
    let r = Reservation::new(None, 64 * MIB);
    assert!(!(r.base..r.base + r.len).contains(&NOPIE_BASE));
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let prog = Program::open(&mut fs, &mut s, bytes(&fixture("static_start_nopie"))).unwrap();
    assert_eq!(prog.map(&mut a, &mut fs).unwrap_err(), Errno::NOEXEC);
    assert_eq!(fs.open, 0);
    assert_eq!(a.stats().mapped, 0);
}

#[test]
fn dynamic_pie_and_its_interpreter() {
    let r = Reservation::new(None, 256 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let path = fixture("hello");
    let (img, interp) = load_and_check(&mut a, &mut fs, &mut s, &path, false);
    assert!(interp.is_some());
    let argv: &[&[u8]] = &[b"hello"];
    stack_and_check(&mut a, &mut fs, &img, &params(bytes(&path), argv, &[]), argv);
}

#[test]
fn dynamic_nopie_and_its_interpreter() {
    let r = Reservation::new(Some(NOPIE_BASE), 256 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let (img, interp) = load_and_check(&mut a, &mut fs, &mut s, &fixture("hello_nopie"), true);
    assert!(interp.is_some());
    assert!(img.interp_base >= img.brk, "the interpreter placed after the fixed image: {img:x?}");
}

#[test]
fn bash() {
    let Some(bash) = std::env::var_os("EXOBOX_TEST_BASH") else {
        eprintln!("EXOBOX_TEST_BASH unset: skipped");
        return;
    };
    let r = Reservation::new(None, 256 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let path = PathBuf::from(bash);
    let (img, interp) = load_and_check(&mut a, &mut fs, &mut s, &path, false);
    assert!(interp.is_some());
    let argv: &[&[u8]] = &[b"bash", b"-c", b"echo hi"];
    let envp: &[&[u8]] = &[b"HOME=/", b"TERM=dumb", b"LANG=C"];
    stack_and_check(&mut a, &mut fs, &img, &params(bytes(&path), argv, envp), argv);
}

#[test]
fn script_one_level() {
    let r = Reservation::new(None, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let interp = fixture("static_start");
    let mut line = b"#!  ".to_vec();
    line.extend_from_slice(bytes(&interp));
    line.extend_from_slice(b" \t-x  y \t\nrest of the script\n");
    fs.add(b"/guest/script", line);
    let prog = Program::open(&mut fs, &mut s, b"/guest/script").unwrap();
    let img = prog.map(&mut a, &mut fs).unwrap();
    assert_eq!(fs.open, 0);
    check_image(&a, &std::fs::read(&interp).unwrap(), img.bias);
    let argv: &[&[u8]] = &[b"script", b"a1", b"a2"];
    let want: &[&[u8]] = &[bytes(&interp), b"-x  y", b"/guest/script", b"a1", b"a2"];
    let (_, p) = stack_and_check(&mut a, &mut fs, &img, &params(b"/guest/script", argv, &[]), want);
    assert_eq!(cstr(aux(&p, AT_EXECFN), 0, usize::MAX), b"/guest/script");
}

#[test]
fn script_without_argument_and_empty_argv() {
    let r = Reservation::new(None, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let interp = fixture("static_start");
    let mut line = b"#!".to_vec();
    line.extend_from_slice(bytes(&interp));
    fs.add(b"s", line);
    let img = Program::open(&mut fs, &mut s, b"s").unwrap().map(&mut a, &mut fs).unwrap();
    // No newline, short file: fine. argv empty: Linux gives argv[0] = "", which the script drops.
    let want: &[&[u8]] = &[bytes(&interp), b"s"];
    stack_and_check(&mut a, &mut fs, &img, &params(b"s", &[], &[]), want);
}

#[test]
fn empty_argv_gets_an_empty_argv0() {
    let r = Reservation::new(None, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let path = fixture("static_start");
    let img = Program::open(&mut fs, &mut s, bytes(&path)).unwrap().map(&mut a, &mut fs).unwrap();
    stack_and_check(&mut a, &mut fs, &img, &params(bytes(&path), &[], &[]), &[b""]);
}

#[test]
fn script_lines() {
    let ok = |l: &[u8]| {
        let sc = parse_script(l).unwrap();
        (l[sc.interp.0..sc.interp.1].to_vec(), sc.arg.map(|(a, b)| l[a..b].to_vec()))
    };
    assert_eq!(ok(b"#!/bin/sh\n"), (b"/bin/sh".to_vec(), None));
    assert_eq!(ok(b"#! /bin/sh -e\n"), (b"/bin/sh".to_vec(), Some(b"-e".to_vec())));
    assert_eq!(ok(b"#!/usr/bin/env python3 -u  \r\n"), (b"/usr/bin/env".to_vec(), Some(b"python3 -u  \r".to_vec())));
    assert_eq!(ok(b"#!/bin/sh   \n"), (b"/bin/sh".to_vec(), None));
    assert_eq!(ok(b"#!/bin/sh"), (b"/bin/sh".to_vec(), None));
    assert_eq!(parse_script(b"#!\n").unwrap_err(), Errno::NOEXEC);
    assert_eq!(parse_script(b"#!   \t\n/bin/sh").unwrap_err(), Errno::NOEXEC);
    // A full buffer without a newline: the name cut at the buffer's end is refused; a name that
    // ended inside it is fine (its argument is what fits).
    let mut long = b"#!/".to_vec();
    long.resize(BINPRM_BUF, b'a');
    assert_eq!(parse_script(&long).unwrap_err(), Errno::NOEXEC);
    let mut ended = b"#!/bin/sh ".to_vec();
    ended.resize(BINPRM_BUF, b'x');
    assert_eq!(ok(&ended).0, b"/bin/sh");
}

#[test]
fn script_of_a_script_is_enoexec() {
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    fs.add(b"inner", b"#!/bin/sh\n".to_vec());
    fs.add(b"outer", b"#!inner\n".to_vec());
    assert_eq!(Program::open(&mut fs, &mut s, b"outer").unwrap_err(), Errno::NOEXEC);
    assert_eq!(fs.open, 0);
}

/// Run a loaded static program for real: fork, point stdout at a pipe, jump. Returns its exit
/// status and output. No sandbox: this checks only that the entry, the stack and the image are
/// right.
fn run(start: Start) -> (i32, String) {
    let mut fds = [0; 2];
    assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
    let regs = start.registers();
    // SAFETY: the child only dup2s and jumps (no allocation, no locks: the test harness has
    // threads); the program it runs makes raw syscalls alone and exits.
    let pid = unsafe { libc::fork() };
    assert!(pid >= 0);
    if pid == 0 {
        unsafe {
            libc::dup2(fds[1], 1);
            crate::context::restore(&regs);
        }
    }
    unsafe { libc::close(fds[1]) };
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut status = 0;
    loop {
        let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
        assert!(r >= 0);
        if r == pid {
            break;
        }
        if Instant::now() > deadline {
            unsafe { libc::kill(pid, libc::SIGKILL) };
            panic!("the program didn't exit in 5 s");
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    let mut out = vec![0u8; 4096];
    let n = unsafe { libc::read(fds[0], out.as_mut_ptr() as *mut _, out.len()) };
    unsafe { libc::close(fds[0]) };
    out.truncate(n.max(0) as usize);
    assert!(libc::WIFEXITED(status), "killed by signal {}", libc::WTERMSIG(status));
    (libc::WEXITSTATUS(status), String::from_utf8_lossy(&out).into_owned())
}

fn load_run(at: Option<usize>, path: &[u8], extra: Option<(&[u8], Vec<u8>)>, argv: &[&[u8]], envp: &[&[u8]]) -> (i32, String) {
    let r = Reservation::new(at, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    if let Some((p, d)) = extra {
        fs.add(p, d);
    }
    let img = Program::open(&mut fs, &mut s, path).unwrap().map(&mut a, &mut fs).unwrap();
    let len = MIB;
    let lo = a.mmap(&mut fs, 0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, None).unwrap();
    let start = unsafe { img.build_stack(lo, lo + len, &params(path, argv, envp)) }.unwrap();
    run(start)
}

#[test]
fn run_static_pie() {
    let path = fixture("static_start");
    let (status, out) = load_run(None, bytes(&path), None, &[b"static_start", b"one", b"two words"], &[b"A=1", b"B=2"]);
    assert_eq!(out, "static_start argc=3 [static_start] [one] [two words] envc=2\n");
    assert_eq!(status, 42, "exit codes are in static_start.c");
}

#[test]
fn run_static_nopie() {
    let path = fixture("static_start_nopie");
    let (status, out) = load_run(Some(NOPIE_BASE), bytes(&path), None, &[b"x"], &[]);
    assert_eq!(out, "static_start argc=1 [x] envc=0\n");
    assert_eq!(status, 42);
}

#[test]
fn run_script() {
    let interp = fixture("static_start");
    let mut line = b"#!".to_vec();
    line.extend_from_slice(bytes(&interp));
    line.extend_from_slice(b" -v\n");
    let (status, out) = load_run(None, b"/s.sh", Some((b"/s.sh", line)), &[b"s.sh", b"arg"], &[]);
    assert_eq!(out, format!("static_start argc=4 [{}] [-v] [/s.sh] [arg] envc=0\n", interp.display()));
    assert_eq!(status, 42);
}

// Errors: each from a broken copy of a fixture, through `open` (nothing mapped, nothing left open).

fn open_err(data: Vec<u8>) -> Errno {
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    fs.add(b"/bad", data);
    let e = Program::open(&mut fs, &mut s, b"/bad").unwrap_err();
    assert_eq!(fs.open, 0, "files left open");
    e
}

fn static_bytes() -> Vec<u8> {
    std::fs::read(fixture("static_start")).unwrap()
}

/// The file offset of program header `i`'s field at `field` (the ELF64 layout).
fn ph_field(i: usize, field: usize) -> usize {
    64 + i * PHENT + field
}

fn put64(d: &mut [u8], at: usize, v: u64) {
    d[at..at + 8].copy_from_slice(&v.to_le_bytes());
}

fn first_load(d: &[u8]) -> usize {
    let f = ElfFile64::<LE>::parse(d).unwrap();
    f.elf_program_headers().iter().position(|p| p.p_type(LE) == elf::PT_LOAD).unwrap()
}

#[test]
fn truncated_elf() {
    let d = static_bytes();
    assert_eq!(open_err(d[..40].to_vec()), Errno::NOEXEC, "header cut");
    assert_eq!(open_err(d[..100].to_vec()), Errno::NOEXEC, "program headers cut");
    assert_eq!(open_err(vec![]), Errno::NOEXEC, "empty");
    // The segments' bytes cut: PT_LOADs now reach past the end.
    let last = loads(&d).iter().map(|l| l.0 + l.2).max().unwrap();
    assert_eq!(open_err(d[..last - 1].to_vec()), Errno::NOEXEC, "segments cut");
}

#[test]
fn load_outside_the_file() {
    let mut d = static_bytes();
    let i = first_load(&d);
    put64(&mut d, ph_field(i, 8), 1 << 40); // p_offset
    put64(&mut d, ph_field(i, 16), 1 << 40); // p_vaddr, still congruent
    assert_eq!(open_err(d), Errno::NOEXEC);
    let mut d = static_bytes();
    let i = first_load(&d);
    put64(&mut d, ph_field(i, 32), u64::MAX - 8); // p_filesz
    assert_eq!(open_err(d), Errno::NOEXEC);
}

#[test]
fn bad_segments() {
    // p_filesz > p_memsz.
    let mut d = static_bytes();
    let i = first_load(&d);
    put64(&mut d, ph_field(i, 40), 1);
    assert_eq!(open_err(d), Errno::NOEXEC, "filesz > memsz");
    // vaddr and offset disagree within a page.
    let mut d = static_bytes();
    put64(&mut d, ph_field(i, 16), 0x10);
    assert_eq!(open_err(d), Errno::NOEXEC, "vaddr % page != offset % page");
    // Overlapping (the second PT_LOAD moved onto the first).
    let mut d = static_bytes();
    let off = u64::from_le_bytes(d[ph_field(i + 1, 8)..][..8].try_into().unwrap());
    put64(&mut d, ph_field(i + 1, 16), off & 0xfff);
    assert_eq!(open_err(d), Errno::NOEXEC, "overlap");
    // A non-power-of-two alignment.
    let mut d = static_bytes();
    put64(&mut d, ph_field(i, 48), 0x3000);
    assert_eq!(open_err(d), Errno::NOEXEC, "p_align");
    // The entry outside the image.
    let mut d = static_bytes();
    put64(&mut d, 24, 1 << 30);
    assert_eq!(open_err(d), Errno::NOEXEC, "entry");
}

#[test]
fn too_many_program_headers() {
    let mut d = static_bytes();
    assert!(d.len() > 64 + (MAX_PHNUM + 1) * PHENT, "the file is big enough: the count is what fails");
    d[56..58].copy_from_slice(&(MAX_PHNUM as u16 + 1).to_le_bytes());
    assert_eq!(open_err(d), Errno::NOEXEC);
    let mut d = static_bytes();
    d[56..58].copy_from_slice(&0u16.to_le_bytes());
    assert_eq!(open_err(d), Errno::NOEXEC, "none");
    let mut d = static_bytes();
    d[54..56].copy_from_slice(&32u16.to_le_bytes()); // e_phentsize
    assert_eq!(open_err(d), Errno::NOEXEC, "phentsize");
}

#[test]
fn not_x86_64_elf64() {
    let mut d = static_bytes();
    d[4] = 1; // ELFCLASS32
    assert_eq!(open_err(d), Errno::NOEXEC, "32-bit");
    let mut d = static_bytes();
    d[5] = 2; // big-endian
    assert_eq!(open_err(d), Errno::NOEXEC, "big-endian");
    let mut d = static_bytes();
    d[18..20].copy_from_slice(&183u16.to_le_bytes()); // EM_AARCH64
    assert_eq!(open_err(d), Errno::NOEXEC, "aarch64");
    let mut d = static_bytes();
    d[16..18].copy_from_slice(&1u16.to_le_bytes()); // ET_REL
    assert_eq!(open_err(d), Errno::NOEXEC, "relocatable");
    assert_eq!(open_err(b"\x7fELF".to_vec()), Errno::NOEXEC);
    assert_eq!(open_err(b"plain text".to_vec()), Errno::NOEXEC);
}

#[test]
fn missing_program_and_interpreter() {
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    assert_eq!(Program::open(&mut fs, &mut s, b"/nonexistent/prog").unwrap_err(), Errno::NOENT);
    // hello with its PT_INTERP pointing nowhere (same length, NUL-padded).
    let mut d = std::fs::read(fixture("hello")).unwrap();
    let f = ElfFile64::<LE>::parse(&d[..]).unwrap();
    let ph = f.elf_program_headers().iter().find(|p| p.p_type(LE) == elf::PT_INTERP).unwrap();
    let (off, len) = (ph.p_offset(LE) as usize, ph.p_filesz(LE) as usize);
    let missing = b"/nonexistent/ld.so";
    d[off..off + len].fill(0);
    d[off..off + missing.len()].copy_from_slice(missing);
    assert_eq!(open_err(d.clone()), Errno::NOENT);
    // An interpreter path without its NUL.
    d[off..off + len].fill(b'a');
    assert_eq!(open_err(d), Errno::NOEXEC);
}

#[test]
fn oversized_argv_is_e2big() {
    let r = Reservation::new(None, 64 * MIB);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let path = fixture("static_start");
    let prog = Program::open(&mut fs, &mut s, bytes(&path)).unwrap();
    let len = 8 * MIB;
    // One string past MAX_ARG_STRLEN.
    let big = vec![b'x'; MAX_ARG_STRLEN];
    let argv: &[&[u8]] = &[b"p", &big];
    assert_eq!(prog.stack_bytes(&params(b"p", argv, &[]), len).unwrap_err(), Errno::TOOBIG);
    // Many strings, each fine, past a quarter of the stack.
    let s100k = vec![b'y'; 100 * 1024];
    let many: Vec<&[u8]> = (0..21).map(|_| &s100k[..]).collect();
    assert_eq!(prog.stack_bytes(&params(b"p", &many, &[]), len).unwrap_err(), Errno::TOOBIG);
    assert_eq!(prog.stack_bytes(&params(b"p", &[b"p"], &many), len).unwrap_err(), Errno::TOOBIG, "envp counts too");
    assert!(prog.stack_bytes(&params(b"p", &many[..19], &[]), len).unwrap() < len / 4 + 4096);
    // build_stack refuses the same and writes nothing.
    let img = prog.map(&mut a, &mut fs).unwrap();
    let lo = a.mmap(&mut fs, 0, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, None).unwrap();
    assert_eq!(unsafe { img.build_stack(lo, lo + len, &params(b"p", &many, &[])) }.unwrap_err(), Errno::TOOBIG);
    let mem = unsafe { std::slice::from_raw_parts(lo as *const u8, len) };
    assert!(mem.iter().all(|&b| b == 0), "nothing written");
    // A tiny stack: even a small argv doesn't fit a quarter of it.
    assert_eq!(unsafe { img.build_stack(lo, lo + 256, &params(b"p", &[b"p"], &[])) }.unwrap_err(), Errno::TOOBIG);
}

#[test]
fn arena_too_small_is_enomem_and_unmaps() {
    // hello's ld.so doesn't fit after hello: the program's mapping is undone.
    let r = Reservation::new(None, 24 * 1024);
    let mut t = table();
    let mut a = arena(&r, &mut t);
    let (mut fs, mut s) = (Fs::default(), Scratch::new());
    let prog = Program::open(&mut fs, &mut s, bytes(&fixture("hello"))).unwrap();
    assert_eq!(prog.map(&mut a, &mut fs).unwrap_err(), Errno::NOMEM);
    assert_eq!(fs.open, 0);
    assert_eq!(a.stats().mapped, 0);
}
