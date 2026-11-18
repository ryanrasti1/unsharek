//! exec inside the sandbox: load a program from the guest's filesystem into the arena and build
//! its initial stack, as Linux's `execve` (`fs/binfmt_elf.c`, `fs/binfmt_script.c`) would.
//!
//! The runtime locks down first, so nothing the program brings runs before the filter is on; then
//! it starts the program through this module. The program and its interpreter (ld.so) are read
//! from the **guest** filesystem through [`Files`] and *copied* into the arena (it is
//! read/write/execute, there is no W^X to respect). ld.so then maps the libraries itself through
//! trapped `mmap` calls the arena serves. The same path serves the guest's own `execve` in fork
//! mode.
//!
//! # Use
//! 1. [`Program::open`]: open the file, follow one `#!` line, parse and validate the ELF headers
//!    of the program and its `PT_INTERP`. Nothing in memory changes; on error the old image is
//!    intact (what `execve` must guarantee before its point of no return). [`Program::stack_bytes`]
//!    checks argv/envp against the stack the same way (`E2BIG`).
//! 2. The caller drops the old image (for a guest `execve`: after copying argv and envp out of it,
//!    since they live in the memory about to be freed).
//! 3. [`Program::map`]: map the PT_LOADs into the arena (program first: a fixed `ET_EXEC` claims its
//!    addresses before anything is placed), close the files.
//! 4. The caller maps a stack in the arena; [`Image::build_stack`] writes argc, argv, envp, the
//!    auxiliary vector and the strings into it and returns the [`Start`]: jump to `entry` with
//!    `rsp`, every other register zero and FS unset.
//!
//! # Supported
//! - Static and static-PIE programs (no `PT_INTERP`), dynamic PIEs (`ET_DYN` with `PT_INTERP`),
//!   non-PIE `ET_EXEC` programs at their link-time addresses if those lie inside the arena
//!   (`ENOEXEC` otherwise: the arena's placement should cover 0x400000, the x86-64 linkers'
//!   default base, for these to load), and an `ET_EXEC` interpreter on the same terms.
//! - `#!` scripts, one level, parsed as Linux does: the interpreter and one optional argument (the
//!   rest of the line, trimmed), then the script's path, then the original `argv[1..]`. An
//!   interpreter that is itself a script is `ENOEXEC` (Linux follows up to four levels).
//! - x86-64 little-endian ELF64 only (`ENOEXEC` for anything else, 32-bit included).
//!
//! # Differences from Linux
//! - At most [`MAX_PHNUM`] program headers (Linux allows 64 KiB of them, ~1170): the headers are
//!   read into fixed caller-provided storage ([`Scratch`]). Real programs have about a dozen.
//! - PT_LOADs must be sorted by address and must not overlap, and the entry point must lie inside
//!   the image: Linux maps such files anyway and lets them crash.
//! - The PIE base is wherever the arena puts the image (aligned to its largest `p_align`, as Linux
//!   does since 5.10); there is no ASLR beyond the arena's own placement, and no `ELF_ET_DYN_BASE`.
//! - Holes between PT_LOADs stay reserved `PROT_NONE` (as ld.so leaves them for libraries; Linux
//!   unmaps them for the program), so nothing the program maps later lands between its segments.
//! - `brk` starts at the end of the program's data; the arena never grows it (see `arena`).
//! - `PT_GNU_STACK` is ignored (the arena is executable anyway); no `AT_SECURE` programs (setuid
//!   doesn't exist in the guest's view: the IDs are passed in and unchanged).
//!
//! Errors are positive errnos ([`Errno`], as in `arena`): `ENOEXEC` for anything malformed or
//! unsupported, `ENOENT`/`EACCES`/… from [`Files::open`], `ENOMEM` when the arena has no room,
//! `E2BIG` for oversized argv/envp, `EEXIST` when an `ET_EXEC`'s fixed range is already mapped.

use core::cmp::max;

use object::LittleEndian as LE;
use object::elf::{self, FileHeader64, ProgramHeader64};
use object::read::elf::{FileHeader as _, ProgramHeader as _};

use crate::arena::{
    Arena, Backing, Errno, FileMap, MAP_ANONYMOUS, MAP_FIXED, MAP_FIXED_NOREPLACE, MAP_PRIVATE, PAGE, PROT_EXEC, PROT_NONE,
    PROT_READ, PROT_WRITE, Result,
};
use crate::context::Registers;

/// The most program headers a loaded ELF may have (see the module docs).
pub const MAX_PHNUM: usize = 128;
/// How much of a file is read to find a `#!` line: Linux's `BINPRM_BUF_SIZE`.
pub const BINPRM_BUF: usize = 256;
/// The longest `PT_INTERP` path, its NUL included: Linux's `PATH_MAX`.
pub const PATH_MAX: usize = 4096;
/// The longest single argument or environment string, its NUL included: Linux's
/// `MAX_ARG_STRLEN` (32 pages).
pub const MAX_ARG_STRLEN: usize = 32 * PAGE;

/// The auxiliary vector's key for the gate's address: exobox's own, outside Linux's range
/// (`native/fixtures/c/exobox_test.h` reads it with `getauxval`).
pub const AT_EXOBOX_GATE: u64 = 0x4558;

// Auxiliary vector keys (linux/auxvec.h, asm/auxvec.h).
pub const AT_NULL: u64 = 0;
pub const AT_PHDR: u64 = 3;
pub const AT_PHENT: u64 = 4;
pub const AT_PHNUM: u64 = 5;
pub const AT_PAGESZ: u64 = 6;
pub const AT_BASE: u64 = 7;
pub const AT_FLAGS: u64 = 8;
pub const AT_ENTRY: u64 = 9;
pub const AT_UID: u64 = 11;
pub const AT_EUID: u64 = 12;
pub const AT_GID: u64 = 13;
pub const AT_EGID: u64 = 14;
pub const AT_PLATFORM: u64 = 15;
pub const AT_HWCAP: u64 = 16;
pub const AT_CLKTCK: u64 = 17;
pub const AT_SECURE: u64 = 23;
pub const AT_RANDOM: u64 = 25;
pub const AT_HWCAP2: u64 = 26;
pub const AT_EXECFN: u64 = 31;
pub const AT_SYSINFO_EHDR: u64 = 33;
pub const AT_MINSIGSTKSZ: u64 = 51;

/// `AT_PLATFORM`'s string on x86-64.
const PLATFORM: &[u8] = b"x86_64";
/// `AT_CLKTCK`: Linux's `USER_HZ`, whatever the kernel's HZ. glibc's `sysconf(_SC_CLK_TCK)` reads it.
const CLKTCK: u64 = 100;
/// The highest address a loaded segment may reach: x86-64's 47-bit user address space (`TASK_SIZE`).
const TASK_SIZE: u64 = 0x7fff_ffff_f000;
const EHDR: usize = core::mem::size_of::<FileHeader64<LE>>();
const PHENT: usize = core::mem::size_of::<ProgramHeader64<LE>>();
/// Entries in the auxiliary vector at most, AT_NULL included.
const MAX_AUXV: usize = 24;

/// The guest's files, as the loader reads them. The caller implements it over the guest kernel;
/// handles are the same `u64`s its [`Backing`] reads mappings from.
pub trait Files {
    /// Open `path` (no NUL) for execution: a regular file the guest may execute, as `execve`'s
    /// own checks require (`EACCES` otherwise, `ENOENT`, `ENOTDIR`, … as the guest's kernel
    /// says). Relative paths are resolved against the guest's working directory.
    fn open(&mut self, path: &[u8]) -> Result<u64>;
    /// The file's size in bytes.
    fn size(&mut self, file: u64) -> Result<u64>;
    /// Read up to `buf.len()` bytes at `offset`; `Ok(0)` at the end of the file.
    fn pread(&mut self, file: u64, offset: u64, buf: &mut [u8]) -> Result<usize>;
    /// Done with a handle from [`Files::open`]. (Not `close`: the same object implements
    /// [`Backing`], whose `close` is for the arena's retained handles.)
    fn close_file(&mut self, file: u64);
}

/// One ELF file's headers, read into fixed storage. 8-aligned: `object` reads the headers in place.
#[repr(C, align(8))]
struct Headers {
    ehdr: [u8; EHDR],
    phdrs: [u8; MAX_PHNUM * PHENT],
}

/// The loader's working storage: the headers of the program and its interpreter, the `#!` line,
/// the interpreter's path (~19 KiB). Caller-provided because the crate allocates nothing; a static
/// or a long-lived stack frame. [`Program`] and [`Image`] borrow it (the strings they put on the
/// stack live here).
#[repr(C, align(8))]
pub struct Scratch {
    prog: Headers,
    interp: Headers,
    script: [u8; BINPRM_BUF],
    interp_path: [u8; PATH_MAX],
}

impl Scratch {
    pub const fn new() -> Self {
        const H: Headers = Headers { ehdr: [0; EHDR], phdrs: [0; MAX_PHNUM * PHENT] };
        Scratch { prog: H, interp: H, script: [0; BINPRM_BUF], interp_path: [0; PATH_MAX] }
    }
}

impl core::fmt::Debug for Scratch {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Scratch")
    }
}

impl Default for Scratch {
    fn default() -> Self {
        Self::new()
    }
}

/// A validated ELF: what mapping it needs, all in its own (link-time) addresses.
#[derive(Clone, Copy, Debug)]
struct Elf {
    file: u64,
    /// `ET_EXEC`: loaded at its own addresses, not moved.
    fixed: bool,
    phnum: usize,
    /// The image's page-aligned span: the lowest PT_LOAD's page to the highest's end, rounded up.
    lo: u64,
    hi: u64,
    /// The base's alignment: the largest PT_LOAD `p_align`, at least a page.
    align: u64,
    /// The page of the file the lowest PT_LOAD's page maps (where its span starts in the file).
    off0: u64,
    entry: u64,
    /// Where the program headers are in memory (`PT_PHDR`, else the PT_LOAD that holds them), if
    /// anywhere.
    phdr: Option<u64>,
}

/// The `#!` line's pieces, as ranges of [`Scratch::script`].
#[derive(Clone, Copy, Debug)]
struct Script {
    interp: (usize, usize),
    arg: Option<(usize, usize)>,
}

/// An opened, validated program: nothing mapped yet. Holds its files open: finish with
/// [`Program::map`] or [`Program::close`].
#[derive(Debug)]
pub struct Program<'s> {
    s: &'s Scratch,
    main: Elf,
    interp: Option<Elf>,
    script: Option<Script>,
}

/// A program mapped into the arena; build its stack with [`Image::build_stack`].
#[derive(Debug)]
pub struct Image<'s> {
    s: &'s Scratch,
    script: Option<Script>,
    /// The program's load bias: where its address 0 is (0 for `ET_EXEC`).
    pub bias: usize,
    /// The program's entry point (`AT_ENTRY`).
    pub entry: usize,
    /// Its program headers in memory (`AT_PHDR`, 0 if not mapped) and their count (`AT_PHNUM`).
    pub phdr: usize,
    pub phnum: usize,
    /// The interpreter's load bias (`AT_BASE`), 0 without one.
    pub interp_base: usize,
    /// Where execution starts: the interpreter's entry if there is one, else the program's.
    pub start: usize,
    /// The program's break (the end of its data, page-aligned), set in the arena too.
    pub brk: usize,
}

/// The values of the auxiliary vector and the stack that come from the caller.
#[derive(Clone, Copy, Debug)]
pub struct StackParams<'a> {
    /// The path as given to `execve` (`AT_EXECFN`; a script's path for a script), no NUL.
    pub execfn: &'a [u8],
    /// Arguments and environment, each without its NUL. An empty `argv` gets `""` as `argv[0]`,
    /// as Linux does since 5.18.
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    /// The guest's credentials.
    pub uid: u32,
    pub euid: u32,
    pub gid: u32,
    pub egid: u32,
    /// `AT_RANDOM`'s 16 bytes (glibc's stack protector and pointer guard).
    pub random: [u8; 16],
    /// The host's `AT_HWCAP`, `AT_HWCAP2`, `AT_SYSINFO_EHDR` (the vDSO; 0 leaves it out) and
    /// `AT_MINSIGSTKSZ`.
    pub hwcap: u64,
    pub hwcap2: u64,
    pub sysinfo_ehdr: u64,
    pub minsigstksz: u64,
    /// The gate's address (`AT_EXOBOX_GATE`).
    pub gate: u64,
}

/// Where the program starts: jump to `entry` with `rsp` (pointing at argc, 16-aligned).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    pub entry: usize,
    pub rsp: usize,
}

impl Start {
    /// The registers as Linux's x86-64 `start_thread` leaves them: all zero but rip and rsp. rdx
    /// matters: glibc's `_start` passes it to `__libc_start_main` as `rtld_fini` (0: none).
    pub fn registers(&self) -> Registers {
        Registers { rip: self.entry as u64, rsp: self.rsp as u64, ..Registers::default() }
    }
}

fn page_down(v: u64) -> u64 {
    v & !(PAGE as u64 - 1)
}

fn page_up(v: u64) -> Option<u64> {
    v.checked_add(PAGE as u64 - 1).map(page_down)
}

/// Read until `buf` is full or the file ends; the bytes read.
fn read_full<F: Files>(g: &mut F, file: u64, offset: u64, buf: &mut [u8]) -> Result<usize> {
    let mut done = 0;
    while done < buf.len() {
        match g.pread(file, offset + done as u64, &mut buf[done..])? {
            0 => break,
            n => done += n.min(buf.len() - done),
        }
    }
    Ok(done)
}

fn phdrs(h: &Headers, n: usize) -> &[ProgramHeader64<LE>] {
    // Validated in `parse`: n <= MAX_PHNUM, the storage is 8-aligned, the entries are plain data.
    object::pod::slice_from_bytes(&h.phdrs, n).map(|(s, _)| s).unwrap_or(&[])
}

/// Read and validate `file`'s ELF headers into `h`. For the program (`want_interp`), also
/// returns its `PT_INTERP` as (offset, size); an interpreter's own `PT_INTERP` is ignored, as
/// Linux does.
fn parse<F: Files>(g: &mut F, file: u64, h: &mut Headers, want_interp: bool) -> Result<(Elf, Option<(u64, u64)>)> {
    let size = g.size(file)?;
    if read_full(g, file, 0, &mut h.ehdr)? < EHDR {
        return Err(Errno::NOEXEC);
    }
    // `parse` checks the magic, ELFCLASS64 (a 32-bit file fails here), the version and that the
    // byte order is one it knows; we want little-endian x86-64.
    let eh = FileHeader64::<LE>::parse(&h.ehdr[..]).map_err(|_| Errno::NOEXEC)?;
    if !eh.is_little_endian() || eh.e_machine(LE) != elf::EM_X86_64 {
        return Err(Errno::NOEXEC);
    }
    let fixed = match eh.e_type(LE) {
        elf::ET_EXEC => true,
        elf::ET_DYN => false,
        _ => return Err(Errno::NOEXEC),
    };
    let phnum = eh.e_phnum(LE) as usize;
    if eh.e_phentsize(LE) as usize != PHENT || phnum == 0 || phnum > MAX_PHNUM {
        return Err(Errno::NOEXEC);
    }
    let phoff = eh.e_phoff(LE);
    let phsize = (phnum * PHENT) as u64;
    if phoff.checked_add(phsize).is_none_or(|end| end > size) {
        return Err(Errno::NOEXEC);
    }
    let entry = eh.e_entry(LE);
    if read_full(g, file, phoff, &mut h.phdrs[..phnum * PHENT])? < phnum * PHENT {
        return Err(Errno::NOEXEC);
    }

    let (mut lo, mut hi, mut align, mut off0) = (u64::MAX, 0u64, PAGE as u64, 0u64);
    let (mut prev_end, mut loads) = (0u64, 0usize);
    let (mut phdr, mut pt_phdr, mut interp) = (None, None, None);
    for ph in phdrs(h, phnum) {
        match ph.p_type(LE) {
            elf::PT_LOAD => {
                let (off, va, filesz, memsz, a) =
                    (ph.p_offset(LE), ph.p_vaddr(LE), ph.p_filesz(LE), ph.p_memsz(LE), ph.p_align(LE));
                let end = va.checked_add(memsz).ok_or(Errno::NOEXEC)?;
                let valid = filesz <= memsz
                    && off.checked_add(filesz).is_some_and(|e| e <= size)
                    // mmap needs the file offset and the address to agree within a page.
                    && va % PAGE as u64 == off % PAGE as u64
                    && (a <= 1 || a.is_power_of_two())
                    && end <= TASK_SIZE
                    // Sorted and disjoint (they may share a page: the later one's file bytes win,
                    // as with Linux's MAP_FIXED mappings in order).
                    && (loads == 0 || va >= prev_end);
                if !valid {
                    return Err(Errno::NOEXEC);
                }
                loads += 1;
                prev_end = end;
                if memsz > 0 {
                    if page_down(va) < lo {
                        off0 = page_down(off);
                    }
                    lo = lo.min(page_down(va));
                    hi = hi.max(page_up(end).ok_or(Errno::NOEXEC)?);
                }
                align = max(align, a);
                if phdr.is_none() && off <= phoff && phoff + phsize <= off + filesz {
                    phdr = Some(va + (phoff - off));
                }
            }
            elf::PT_PHDR => pt_phdr = Some(ph.p_vaddr(LE)),
            // The first one counts, as in Linux.
            elf::PT_INTERP if want_interp && interp.is_none() => {
                let (off, len) = (ph.p_offset(LE), ph.p_filesz(LE));
                if len < 2 || len > PATH_MAX as u64 || off.checked_add(len).is_none_or(|e| e > size) {
                    return Err(Errno::NOEXEC);
                }
                interp = Some((off, len));
            }
            _ => {}
        }
    }
    if loads == 0 || lo >= hi || !(lo..hi).contains(&entry) {
        return Err(Errno::NOEXEC);
    }
    let elf = Elf { file, fixed, phnum, lo, hi, align, off0, entry, phdr: pt_phdr.or(phdr) };
    Ok((elf, interp))
}

/// Parse a `#!` line (`buf` holds the file's first `n` bytes and starts with `#!`), as
/// `fs/binfmt_script.c` does: the interpreter ends at the first space, tab or newline; the
/// optional argument is the rest of the line with leading and trailing blanks removed.
fn parse_script(buf: &[u8]) -> Result<Script> {
    let blank = |c: u8| c == b' ' || c == b'\t';
    let line_end = buf.iter().position(|&c| c == b'\n');
    let end = line_end.unwrap_or(buf.len());
    let mut i = 2;
    while i < end && blank(buf[i]) {
        i += 1;
    }
    let name_lo = i;
    while i < end && !blank(buf[i]) && buf[i] != 0 {
        i += 1;
    }
    let name = (name_lo, i);
    // No newline in a full buffer: the name must have ended inside it, or it was cut (Linux 5.0+).
    if name.0 == name.1 || (line_end.is_none() && buf.len() == BINPRM_BUF && i == end) {
        return Err(Errno::NOEXEC);
    }
    while i < end && blank(buf[i]) {
        i += 1;
    }
    let mut arg_end = end;
    while arg_end > i && (blank(buf[arg_end - 1]) || buf[arg_end - 1] == 0) {
        arg_end -= 1;
    }
    // A NUL ends the argument (it is a C string to Linux).
    if let Some(z) = buf[i..arg_end].iter().position(|&c| c == 0) {
        arg_end = i + z;
    }
    Ok(Script { interp: name, arg: (arg_end > i).then_some((i, arg_end)) })
}

impl<'s> Program<'s> {
    /// Open `path` (no NUL) and validate it and its interpreter (see the module docs). No memory
    /// changes; every file it opened is closed again on error.
    pub fn open<F: Files>(g: &mut F, s: &'s mut Scratch, path: &[u8]) -> Result<Program<'s>> {
        let file = g.open(path)?;
        let n = match read_full(g, file, 0, &mut s.script) {
            Ok(n) => n,
            Err(e) => {
                g.close_file(file);
                return Err(e);
            }
        };
        let (file, script) = if n >= 2 && s.script[..2] == *b"#!" {
            g.close_file(file);
            let sc = parse_script(&s.script[..n])?;
            let f = g.open(&s.script[sc.interp.0..sc.interp.1])?;
            (f, Some(sc))
        } else {
            (file, None)
        };
        let (main, interp_at) = match parse(g, file, &mut s.prog, true) {
            Ok(r) => r,
            Err(e) => {
                g.close_file(file);
                return Err(e);
            }
        };
        let interp = match interp_at {
            None => None,
            Some((off, len)) => match Self::open_interp(g, s, off, len, file) {
                Ok(i) => Some(i),
                Err(e) => {
                    g.close_file(file);
                    return Err(e);
                }
            },
        };
        Ok(Program { s, main, interp, script })
    }

    fn open_interp<F: Files>(g: &mut F, s: &mut Scratch, off: u64, len: u64, from: u64) -> Result<Elf> {
        let len = len as usize;
        if read_full(g, from, off, &mut s.interp_path[..len])? < len {
            return Err(Errno::NOEXEC);
        }
        // A C string: it must end in a NUL, and ends at its first one.
        if s.interp_path[len - 1] != 0 {
            return Err(Errno::NOEXEC);
        }
        let end = s.interp_path.iter().position(|&c| c == 0).unwrap_or(len);
        if end == 0 {
            return Err(Errno::NOEXEC);
        }
        let file = g.open(&s.interp_path[..end])?;
        match parse(g, file, &mut s.interp, false) {
            Ok((elf, _)) => Ok(elf),
            Err(e) => {
                g.close_file(file);
                Err(e)
            }
        }
    }

    /// Give up without mapping: close the files.
    pub fn close<F: Files>(self, g: &mut F) {
        g.close_file(self.main.file);
        if let Some(i) = self.interp {
            g.close_file(i.file);
        }
    }

    /// The stack bytes `p` needs (see [`Image::build_stack`]), or `E2BIG` if it would not fit a
    /// stack of `stack_len` bytes. For checking before the old image is dropped.
    pub fn stack_bytes(&self, p: &StackParams, stack_len: usize) -> Result<usize> {
        layout(self.s, self.script, p, stack_len).map(|l| l.total)
    }

    /// Map the program and its interpreter into `arena` and close the files. On error, what this
    /// call mapped is unmapped again.
    pub fn map<G: Files + Backing>(self, arena: &mut Arena, g: &mut G) -> Result<Image<'s>> {
        let r = self.map_all(arena, g);
        self.close(g);
        r
    }

    fn map_all<G: Files + Backing>(&self, arena: &mut Arena, g: &mut G) -> Result<Image<'s>> {
        let bias = map_elf(arena, g, &self.main, &self.s.prog)?;
        let interp_bias = match &self.interp {
            None => None,
            Some(i) => match map_elf(arena, g, i, &self.s.interp) {
                Ok(b) => Some(b),
                Err(e) => {
                    let _ = arena.munmap(g, bias + self.main.lo as usize, (self.main.hi - self.main.lo) as usize);
                    return Err(e);
                }
            },
        };
        let brk = bias + self.main.hi as usize;
        arena.set_brk(brk);
        let entry = bias + self.main.entry as usize;
        Ok(Image {
            s: self.s,
            script: self.script,
            bias,
            entry,
            phdr: self.main.phdr.map_or(0, |p| bias + p as usize),
            phnum: self.main.phnum,
            interp_base: interp_bias.unwrap_or(0),
            start: match (&self.interp, interp_bias) {
                (Some(i), Some(b)) => b + i.entry as usize,
                _ => entry,
            },
            brk,
        })
    }
}

fn prot_of(flags: elf::ProgramFlags) -> u32 {
    let mut p = PROT_NONE;
    if flags.contains(elf::PF_R) {
        p |= PROT_READ;
    }
    if flags.contains(elf::PF_W) {
        p |= PROT_WRITE;
    }
    if flags.contains(elf::PF_X) {
        p |= PROT_EXEC;
    }
    p
}

/// Map one validated ELF; returns its load bias. First the whole span is reserved `PROT_NONE`
/// (at its own addresses for `ET_EXEC`, where the arena places it otherwise), then each PT_LOAD
/// replaces its part: the file's pages, the rest of the last file page zeroed, zero pages after.
fn map_elf<G: Files + Backing>(arena: &mut Arena, g: &mut G, e: &Elf, h: &Headers) -> Result<usize> {
    let span = (e.hi - e.lo) as usize;
    let anon = MAP_PRIVATE | MAP_ANONYMOUS;
    let start = if e.fixed {
        let lo = e.lo as usize;
        if !arena.contains(lo, span) {
            return Err(Errno::NOEXEC);
        }
        arena.mmap(g, lo, span, PROT_NONE, anon | MAP_FIXED_NOREPLACE, None)?
    } else if let Some(at) = (e.align <= PAGE as u64)
        .then(|| arena.mmap_in_place(g, span, PROT_NONE, FileMap { file: e.file, offset: e.off0 }))
        .flatten()
    {
        // From the file, where its bytes already are in the image zone, as ld.so reserves a
        // library: the segments whose offset and address agree (GNU ld's read-only ones) are
        // then mapped in place, not copied.
        at
    } else {
        // Over-reserve by the alignment, then give back the ends.
        let align = usize::try_from(e.align).map_err(|_| Errno::NOMEM)?;
        let len = span.checked_add(align - PAGE).ok_or(Errno::NOMEM)?;
        let r = arena.mmap(g, 0, len, PROT_NONE, anon, None)?;
        let start = (r + align - 1) & !(align - 1);
        // Trimming splits the table's extent: it can fail (ENOMEM) on a full table.
        let trimmed = (if start > r { arena.munmap(g, r, start - r) } else { Ok(0) }).and_then(|_| {
            if r + len > start + span { arena.munmap(g, start + span, r + len - (start + span)) } else { Ok(0) }
        });
        if let Err(e) = trimmed {
            let _ = arena.munmap(g, r, len);
            return Err(e);
        }
        start
    };
    let bias = start - e.lo as usize;
    if let Err(err) = map_loads(arena, g, e, h, bias) {
        let _ = arena.munmap(g, start, span);
        return Err(err);
    }
    Ok(bias)
}

fn map_loads<G: Files + Backing>(arena: &mut Arena, g: &mut G, e: &Elf, h: &Headers, bias: usize) -> Result<()> {
    for ph in phdrs(h, e.phnum) {
        if ph.p_type(LE) != elf::PT_LOAD || ph.p_memsz(LE) == 0 {
            continue;
        }
        let prot = prot_of(ph.p_flags(LE));
        let va = bias + ph.p_vaddr(LE) as usize;
        let seg = va & !(PAGE - 1);
        let file_end = va + ph.p_filesz(LE) as usize;
        let mem_end = va + ph.p_memsz(LE) as usize;
        let file_pages = (file_end + PAGE - 1) & !(PAGE - 1);
        let mem_pages = (mem_end + PAGE - 1) & !(PAGE - 1);
        let mut anon_from = seg;
        if file_end > va {
            let offset = ph.p_offset(LE) - (va - seg) as u64;
            arena.mmap(g, seg, file_end - seg, prot, MAP_PRIVATE | MAP_FIXED, Some(FileMap { file: e.file, offset }))?;
            // The file's page holds whatever follows the segment in the file; .bss starts zero.
            // Only when there is a .bss, as Linux's padzero: otherwise the page keeps the file's bytes.
            if mem_end > file_end {
                let n = file_pages.min(mem_pages) - file_end;
                // SAFETY: inside the mapping just made, in the arena's memory (read/write/execute
                // whatever `prot` records).
                unsafe { core::ptr::write_bytes(file_end as *mut u8, 0, n) };
            }
            anon_from = file_pages;
        }
        if mem_pages > anon_from {
            arena.mmap(g, anon_from, mem_pages - anon_from, prot, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, None)?;
        }
    }
    Ok(())
}

/// The arguments the program sees: a script's prefix (interpreter, its argument, the script's
/// path), then `argv` (from `argv[1]` for a script).
#[derive(Clone, Copy)]
struct Args<'a> {
    prefix: [&'a [u8]; 3],
    nprefix: usize,
    rest: &'a [&'a [u8]],
}

const EMPTY_ARG: &[&[u8]] = &[b""];

impl<'a> Args<'a> {
    fn new(s: &'a Scratch, script: Option<Script>, p: &StackParams<'a>) -> Self {
        let argv = if p.argv.is_empty() { EMPTY_ARG } else { p.argv };
        match script {
            None => Args { prefix: [b""; 3], nprefix: 0, rest: argv },
            Some(sc) => {
                let name = &s.script[sc.interp.0..sc.interp.1];
                let (prefix, nprefix) = match sc.arg {
                    Some((lo, hi)) => ([name, &s.script[lo..hi], p.execfn], 3),
                    None => ([name, p.execfn, b""], 2),
                };
                Args { prefix, nprefix, rest: &argv[1..] }
            }
        }
    }
    fn count(&self) -> usize {
        self.nprefix + self.rest.len()
    }
    fn iter(&self) -> impl Iterator<Item = &'a [u8]> + '_ {
        self.prefix[..self.nprefix].iter().chain(self.rest.iter()).copied()
    }
}

/// The stack's size, computed before anything is written.
struct Layout {
    /// Bytes of argument and environment strings, NULs included.
    strings: usize,
    /// Everything: the end marker, execfn, strings, platform, random bytes, vectors, alignment.
    total: usize,
}

fn auxv_len(p: &StackParams) -> usize {
    // Every entry in `build_stack`'s list, AT_NULL included; AT_SYSINFO_EHDR only when there is
    // a vDSO.
    21 + usize::from(p.sysinfo_ehdr != 0)
}

fn layout(s: &Scratch, script: Option<Script>, p: &StackParams, stack_len: usize) -> Result<Layout> {
    let args = Args::new(s, script, p);
    let mut strings = 0usize;
    for a in args.iter().chain(p.envp.iter().copied()) {
        if a.len() + 1 > MAX_ARG_STRLEN {
            return Err(Errno::TOOBIG);
        }
        strings += a.len() + 1;
    }
    if p.execfn.len() + 1 > MAX_ARG_STRLEN {
        return Err(Errno::TOOBIG);
    }
    let vectors = (1 + args.count() + 1 + p.envp.len() + 1 + 2 * auxv_len(p)) * 8;
    // Linux's limit: strings and their pointers within a quarter of the stack (a quarter of
    // RLIMIT_STACK), so the program keeps the rest.
    if strings + (args.count() + p.envp.len()) * 8 > stack_len / 4 {
        return Err(Errno::TOOBIG);
    }
    // Upper bound of the layout `build_stack` makes: each alignment step costs < 16 bytes.
    let total = 8 + p.execfn.len() + 1 + strings + PLATFORM.len() + 1 + 16 + vectors + 3 * 16;
    if total > stack_len {
        return Err(Errno::TOOBIG);
    }
    Ok(Layout { strings, total })
}

/// Copy `bytes` and a NUL to `at`.
///
/// # Safety
/// `[at, at + bytes.len() + 1)` is writable.
unsafe fn put_str(at: usize, bytes: &[u8]) {
    // SAFETY: the caller's contract.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), at as *mut u8, bytes.len());
        *((at + bytes.len()) as *mut u8) = 0;
    }
}

impl Image<'_> {
    /// Write the initial stack into `[lo, top)` (memory the caller mapped, e.g. in the arena) the
    /// way Linux's `create_elf_tables` does, from the top down: an 8-byte zero end marker, the
    /// `AT_EXECFN` path, the argument strings then the environment strings (`argv[0]` lowest), the
    /// platform string and the random bytes, then (16-aligned, at the returned rsp) argc, argv,
    /// NULL, envp, NULL and the auxiliary vector, ending in AT_NULL. `E2BIG` (nothing written) if
    /// the strings exceed a quarter of the stack or one exceeds [`MAX_ARG_STRLEN`].
    ///
    /// # Safety
    /// `[lo, top)` is writable memory that stays mapped while the program runs.
    pub unsafe fn build_stack(&self, lo: usize, top: usize, p: &StackParams) -> Result<Start> {
        let top = top & !15;
        if top <= lo {
            return Err(Errno::TOOBIG);
        }
        let l = layout(self.s, self.script, p, top - lo)?;
        let args = Args::new(self.s, self.script, p);

        let mut at = top - 8;
        // SAFETY (every write below): `layout` checked the whole layout fits in [lo, top).
        unsafe { (at as *mut u64).write(0) };
        at -= p.execfn.len() + 1;
        let execfn = at;
        unsafe { put_str(execfn, p.execfn) };
        at -= l.strings;
        let (mut s_at, argc, envc) = (at, args.count(), p.envp.len());
        let sp_items = 1 + argc + 1 + envc + 1;
        at -= PLATFORM.len() + 1;
        let platform = at;
        unsafe { put_str(platform, PLATFORM) };
        at -= 16;
        let random = at;
        unsafe { core::ptr::copy_nonoverlapping(p.random.as_ptr(), random as *mut u8, 16) };

        let mut aux = [(0u64, 0u64); MAX_AUXV];
        let mut n = 0;
        let mut push = |k: u64, v: u64| {
            aux[n] = (k, v);
            n += 1;
        };
        // Linux's order (create_elf_tables): the arch entries first.
        if p.sysinfo_ehdr != 0 {
            push(AT_SYSINFO_EHDR, p.sysinfo_ehdr);
        }
        push(AT_MINSIGSTKSZ, p.minsigstksz);
        push(AT_HWCAP, p.hwcap);
        push(AT_PAGESZ, PAGE as u64);
        push(AT_CLKTCK, CLKTCK);
        push(AT_PHDR, self.phdr as u64);
        push(AT_PHENT, PHENT as u64);
        push(AT_PHNUM, self.phnum as u64);
        push(AT_BASE, self.interp_base as u64);
        push(AT_FLAGS, 0);
        push(AT_ENTRY, self.entry as u64);
        push(AT_UID, p.uid as u64);
        push(AT_EUID, p.euid as u64);
        push(AT_GID, p.gid as u64);
        push(AT_EGID, p.egid as u64);
        push(AT_SECURE, 0);
        push(AT_RANDOM, random as u64);
        push(AT_HWCAP2, p.hwcap2);
        push(AT_EXECFN, execfn as u64);
        push(AT_PLATFORM, platform as u64);
        push(AT_EXOBOX_GATE, p.gate);
        push(AT_NULL, 0);
        debug_assert_eq!(n, auxv_len(p));

        // argc at a 16-aligned address: round the whole vector block's start down (STACK_ROUND).
        let items = sp_items + 2 * n;
        let sp = (at - items * 8) & !15;
        debug_assert!(sp >= lo && top - sp <= l.total);

        let mut w = sp as *mut u64;
        let mut word = |v: u64| unsafe {
            w.write(v);
            w = w.add(1);
        };
        word(argc as u64);
        for a in args.iter() {
            word(s_at as u64);
            unsafe { put_str(s_at, a) };
            s_at += a.len() + 1;
        }
        word(0);
        for e in p.envp {
            word(s_at as u64);
            unsafe { put_str(s_at, e) };
            s_at += e.len() + 1;
        }
        word(0);
        for &(k, v) in &aux[..n] {
            word(k);
            word(v);
        }
        Ok(Start { entry: self.start, rsp: sp })
    }
}

#[cfg(test)]
mod tests;
