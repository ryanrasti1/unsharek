//! The arena against a model (proptest), and the regressions capnix's arena hit. Each test runs
//! on a real `MAP_NORESERVE` reservation, and release mode's [`Backing::release`] really
//! `madvise`s, so the host's `mincore` can say which pages a sequence of calls touched.

use super::*;
use proptest::collection::vec;
use proptest::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

const MB: usize = 1 << 20;
const ANON: u32 = MAP_PRIVATE | MAP_ANONYMOUS;
const RW: u32 = PROT_READ | PROT_WRITE;

/// A reservation like the runtime's (read/write, private, anonymous, no reserve).
struct Reservation {
    base: usize,
    len: usize,
}

impl Reservation {
    fn new(len: usize) -> Self {
        // SAFETY: a fresh anonymous mapping.
        let p = unsafe {
            libc::mmap(
                ptr::null_mut(),
                len,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        assert_ne!(p, libc::MAP_FAILED);
        Reservation { base: p as usize, len }
    }

    /// Pages of `[addr, addr + len)` the host has resident.
    fn resident(&self, addr: usize, len: usize) -> usize {
        let mut v = vec![0u8; len / PAGE];
        // SAFETY: inside the reservation.
        assert_eq!(unsafe { libc::mincore(addr as *mut _, len, v.as_mut_ptr()) }, 0);
        v.iter().filter(|&&r| r & 1 != 0).count()
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        // SAFETY: ours.
        unsafe { libc::munmap(self.base as *mut _, self.len) };
    }
}

fn mem(addr: usize, len: usize) -> &'static mut [u8] {
    // SAFETY: tests only pass ranges inside a live reservation.
    unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, len) }
}

/// Files in memory, and a record of what the arena asked of the host.
#[derive(Default)]
struct Fake {
    base: usize,
    end: usize,
    files: HashMap<u64, Vec<u8>>,
    /// Retained handles, to the file they stand for.
    alias: HashMap<u64, u64>,
    next: u64,
    releases: Vec<(usize, usize)>,
    closed: Vec<u64>,
    writes: Vec<(u64, u64, usize)>,
    /// Bytes copied by `read`.
    read: usize,
    /// Files in the image zone: where their bytes are, and how many.
    in_zone: HashMap<u64, (usize, u64)>,
}

impl Fake {
    fn new(r: &Reservation) -> Self {
        Fake { base: r.base, end: r.base + r.len, next: 1000, ..Default::default() }
    }
    fn file(&self, h: u64) -> u64 {
        *self.alias.get(&h).unwrap_or(&h)
    }
    fn released(&self) -> usize {
        self.releases.iter().map(|r| r.1).sum()
    }
}

impl Backing for Fake {
    fn read(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> Result<usize> {
        let data = self.files.get(&self.file(file)).ok_or(Errno::BADF)?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(0);
        }
        let n = min(len, data.len() - off);
        mem(addr, n).copy_from_slice(&data[off..off + n]);
        self.read += n;
        Ok(n)
    }
    fn write(&mut self, file: u64, offset: u64, addr: usize, len: usize) -> Result<usize> {
        assert!(self.alias.contains_key(&file), "written through a retained handle");
        assert!(!self.closed.contains(&file), "written after close");
        let id = self.file(file);
        let data = self.files.get_mut(&id).unwrap();
        let off = offset as usize;
        if data.len() < off + len {
            data.resize(off + len, 0);
        }
        data[off..off + len].copy_from_slice(mem(addr, len));
        self.writes.push((id, offset, len));
        Ok(len)
    }
    fn retain(&mut self, file: u64) -> Result<u64> {
        self.next += 1;
        let id = self.file(file);
        self.alias.insert(self.next, id);
        Ok(self.next)
    }
    fn close(&mut self, file: u64) {
        assert!(self.alias.contains_key(&file), "closing a handle never retained");
        assert!(!self.closed.contains(&file), "closed twice");
        self.closed.push(file);
    }
    fn release(&mut self, addr: usize, len: usize) -> Result<()> {
        assert!(len > 0 && len <= MADV_CHUNK, "release of {len:#x}");
        assert!(addr >= self.base && addr + len <= self.end, "release outside the arena");
        assert_eq!(addr % PAGE, 0);
        // SAFETY: inside the reservation.
        assert_eq!(unsafe { libc::madvise(addr as *mut _, len, libc::MADV_DONTNEED) }, 0);
        self.releases.push((addr, len));
        Ok(())
    }
    fn locate(&mut self, file: u64, offset: u64) -> Option<(usize, u64)> {
        let &(at, len) = self.in_zone.get(&file)?;
        (offset <= len).then(|| (at + offset as usize, len - offset))
    }
}

fn table(cap: usize) -> Vec<Extent> {
    vec![Extent::EMPTY; cap]
}

fn arena<'t>(r: &Reservation, mode: Mode, t: &'t mut [Extent]) -> Arena<'t> {
    // SAFETY: the reservation is read/write, zero, and the arena's alone.
    unsafe { Arena::new(r.base, r.len, mode, t) }.unwrap()
}

fn prot_at(a: &Arena, addr: usize) -> Option<u32> {
    a.mappings().find(|m| m.start <= addr && addr < m.end).map(|m| m.prot)
}

/// (Compared as slices, one memcmp: a byte loop is slow in the unoptimised test build.)
fn is_zero(addr: usize, len: usize) -> bool {
    mem(addr, len) == vec![0u8; len]
}

// ----- The model -----

/// The proptest arena's size, in pages (16 MiB: small enough to fill and fragment).
const PP: usize = 4096;

#[derive(Clone, Copy, Debug, PartialEq)]
struct Pg {
    prot: u32,
    /// Written at the page's first and last byte (0: the page is all zero).
    data: u8,
}

#[derive(Clone, Debug)]
enum Op {
    Map { pages: usize, prot: u32, hint: Option<usize>, fixed: Option<usize>, noreplace: bool },
    Unmap { at: usize, pages: usize },
    Remap { at: usize, old: usize, new: usize, maymove: bool, fixed: Option<usize> },
    Protect { at: usize, pages: usize, prot: u32 },
    Write { at: usize, data: u8 },
    DontNeed { at: usize, pages: usize },
}

fn pages() -> impl Strategy<Value = usize> {
    // Mostly small; some 2 MiB and larger, which are placed 2 MiB-aligned.
    prop_oneof![8 => 1usize..=16, 3 => 17usize..=128, 1 => Just(512usize), 1 => 513usize..=1100]
}

fn prot() -> impl Strategy<Value = u32> {
    prop_oneof![Just(PROT_NONE), Just(PROT_READ), Just(RW)]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (pages(), prot(), proptest::option::of(0..PP), proptest::option::weighted(0.2, 0..PP), any::<bool>())
            .prop_map(|(pages, prot, hint, fixed, noreplace)| Op::Map { pages, prot, hint, fixed, noreplace }),
        2 => (any::<usize>(), 1usize..64).prop_map(|(at, pages)| Op::Unmap { at, pages }),
        2 => (any::<usize>(), 1usize..64, pages(), any::<bool>(), proptest::option::weighted(0.2, 0..PP))
            .prop_map(|(at, old, new, maymove, fixed)| Op::Remap { at, old, new, maymove, fixed }),
        2 => (any::<usize>(), 1usize..64, prot()).prop_map(|(at, pages, prot)| Op::Protect { at, pages, prot }),
        3 => (any::<usize>(), 1u8..=255).prop_map(|(at, data)| Op::Write { at, data }),
        1 => (any::<usize>(), 1usize..64).prop_map(|(at, pages)| Op::DontNeed { at, pages }),
    ]
}

/// Append pages `[s, e)` with `prot` to a list of runs, merging with the last when it continues.
fn push_run(runs: &mut Vec<(usize, usize, u32)>, s: usize, e: usize, prot: u32) {
    match runs.last_mut() {
        Some(last) if last.1 == s && last.2 == prot => last.1 = e,
        _ => runs.push((s, e, prot)),
    }
}

/// The first run of `n` free pages in the model.
fn free_run(model: &BTreeMap<usize, Pg>, n: usize) -> Option<usize> {
    let mut run = 0;
    for p in 0..PP {
        run = if model.contains_key(&p) { 0 } else { run + 1 };
        if run == n {
            return Some(p + 1 - n);
        }
    }
    None
}

fn check_page(base: usize, p: usize, pg: Pg) -> std::result::Result<(), TestCaseError> {
    let m = mem(base + p * PAGE, PAGE);
    prop_assert_eq!((m[0], m[PAGE - 1]), (pg.data, pg.data), "page {}", p);
    prop_assert!(is_zero(base + p * PAGE + 1, PAGE - 2), "page {} has stray bytes", p);
    Ok(())
}

fn run(mode: Mode, ops: Vec<Op>) -> std::result::Result<(), TestCaseError> {
    let r = Reservation::new(PP * PAGE);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, mode, &mut t);
    let mut b = Fake::new(&r);
    let mut model: BTreeMap<usize, Pg> = BTreeMap::new();
    let mut touched = BTreeSet::new();
    let base = r.base;
    let addr = |p: usize| base + p * PAGE;
    let page = |x: usize| (x - base) / PAGE;
    // An operation's target: a mapped page when there is one, so that most calls do something.
    let pick = |model: &BTreeMap<usize, Pg>, at: usize| {
        if model.is_empty() { at % PP } else { *model.keys().nth(at % model.len()).unwrap() }
    };

    for op in ops {
        match op {
            Op::Map { pages, prot, hint, fixed, noreplace } => {
                let fl = match fixed {
                    Some(_) if noreplace => MAP_FIXED_NOREPLACE,
                    Some(_) => MAP_FIXED,
                    None => 0,
                };
                let res = a.mmap(&mut b, fixed.or(hint).map_or(0, addr), pages * PAGE, prot, ANON | fl, None);
                let p = match fixed {
                    Some(f) if f + pages > PP => {
                        prop_assert_eq!(res, Err(Errno::NOMEM));
                        continue;
                    }
                    Some(f) if noreplace && (f..f + pages).any(|q| model.contains_key(&q)) => {
                        prop_assert_eq!(res, Err(Errno::EXIST));
                        continue;
                    }
                    Some(f) => {
                        prop_assert_eq!(res, Ok(addr(f)));
                        f
                    }
                    None => match res {
                        Err(e) => {
                            prop_assert_eq!(e, Errno::NOMEM);
                            prop_assert!(free_run(&model, pages).is_none(), "ENOMEM with room");
                            continue;
                        }
                        Ok(x) => {
                            prop_assert!(x >= base && x % PAGE == 0);
                            let p = page(x);
                            prop_assert!(p + pages <= PP);
                            prop_assert!((p..p + pages).all(|q| !model.contains_key(&q)), "overlap");
                            if let Some(h) = hint
                                && h + pages <= PP
                                && (h..h + pages).all(|q| !model.contains_key(&q))
                            {
                                prop_assert_eq!(p, h, "free hint not honoured");
                            }
                            p
                        }
                    },
                };
                for q in p..p + pages {
                    model.insert(q, Pg { prot, data: 0 });
                }
                prop_assert!(is_zero(addr(p), pages * PAGE), "new mapping not zero");
            }
            Op::Unmap { at, pages } => {
                let p = pick(&model, at);
                let n = min(pages, PP - p);
                prop_assert_eq!(a.munmap(&mut b, addr(p), n * PAGE), Ok(0));
                for q in p..p + n {
                    model.remove(&q);
                }
            }
            Op::Protect { at, pages, prot } => {
                let p = pick(&model, at);
                let n = min(pages, PP - p);
                let res = a.mprotect(addr(p), n * PAGE, prot);
                if (p..p + n).all(|q| model.contains_key(&q)) {
                    prop_assert_eq!(res, Ok(0));
                    for q in p..p + n {
                        model.get_mut(&q).unwrap().prot = prot;
                    }
                } else {
                    prop_assert_eq!(res, Err(Errno::NOMEM));
                }
            }
            Op::Write { at, data } => {
                let p = pick(&model, at);
                // Only what a correct program may do: write where it's writable.
                let Some(pg) = model.get_mut(&p).filter(|pg| pg.prot & PROT_WRITE != 0) else { continue };
                let m = mem(addr(p), PAGE);
                m[0] = data;
                m[PAGE - 1] = data;
                pg.data = data;
                touched.insert(p);
            }
            Op::DontNeed { at, pages } => {
                let p = pick(&model, at);
                let n = min(pages, PP - p);
                let res = a.madvise(&mut b, addr(p), n * PAGE, MADV_DONTNEED);
                let all = (p..p + n).all(|q| model.contains_key(&q));
                prop_assert_eq!(res, if all { Ok(0) } else { Err(Errno::NOMEM) });
                for q in p..p + n {
                    if let Some(pg) = model.get_mut(&q) {
                        pg.data = 0;
                        check_page(base, q, *pg)?;
                    }
                }
            }
            Op::Remap { at, old, new, maymove, fixed } => {
                if model.is_empty() {
                    continue;
                }
                let p = pick(&model, at);
                let mut olen = 1;
                while olen < old && p + olen < PP && model.contains_key(&(p + olen)) {
                    olen += 1;
                }
                let fl = match fixed {
                    Some(_) => MREMAP_MAYMOVE | MREMAP_FIXED,
                    None if maymove => MREMAP_MAYMOVE,
                    None => 0,
                };
                let res = a.mremap(&mut b, addr(p), olen * PAGE, new * PAGE, fl, fixed.map_or(0, addr));
                let dst = if let Some(f) = fixed {
                    if f + new > PP {
                        prop_assert_eq!(res, Err(Errno::NOMEM));
                        continue;
                    }
                    if f < p + olen && p < f + new {
                        prop_assert_eq!(res, Err(Errno::INVAL));
                        continue;
                    }
                    f
                } else if new <= olen || (p + new <= PP && (p + olen..p + new).all(|q| !model.contains_key(&q))) {
                    p
                } else if !maymove {
                    prop_assert_eq!(res, Err(Errno::NOMEM));
                    continue;
                } else {
                    match res {
                        Err(e) => {
                            prop_assert_eq!(e, Errno::NOMEM);
                            prop_assert!(free_run(&model, new).is_none(), "mremap ENOMEM with room");
                            continue;
                        }
                        Ok(x) => {
                            let d = page(x);
                            prop_assert!(d + new <= PP && (d..d + new).all(|q| !model.contains_key(&q)), "moved onto a mapping");
                            d
                        }
                    }
                };
                prop_assert_eq!(res, Ok(addr(dst)));
                let moved: Vec<Pg> = (p..p + olen).map(|q| model[&q]).collect();
                let last = moved[olen - 1].prot;
                for q in p..p + olen {
                    model.remove(&q);
                }
                for q in dst..dst + new {
                    model.remove(&q);
                }
                for i in 0..new {
                    let pg = moved.get(i).copied().unwrap_or(Pg { prot: last, data: 0 });
                    model.insert(dst + i, pg);
                    check_page(base, dst + i, pg)?;
                }
            }
        }
        a.check();
        // The arena's mappings and the model's pages, as runs of one protection.
        let mut got = vec![];
        for m in a.mappings() {
            prop_assert!(m.start >= base && m.end <= base + PP * PAGE);
            push_run(&mut got, page(m.start), page(m.end), m.prot);
        }
        let mut want = vec![];
        for (&q, pg) in &model {
            push_run(&mut want, q, q + 1, pg.prot);
        }
        prop_assert_eq!(got, want);
        prop_assert_eq!(a.stats().mapped, model.len() * PAGE);
    }
    for (&q, &pg) in &model {
        check_page(base, q, pg)?;
    }
    // Freed space is reusable, and zero: unmap it all and map the whole arena again.
    prop_assert_eq!(a.munmap(&mut b, base, PP * PAGE), Ok(0));
    if mode == Mode::Release {
        prop_assert_eq!(a.stats().extents, 1);
    }
    prop_assert_eq!(a.mmap(&mut b, 0, PP * PAGE, RW, ANON, None), Ok(base));
    for &q in &touched {
        prop_assert!(is_zero(addr(q), PAGE), "reused page {} not zero", q);
    }
    if mode == Mode::HighWater {
        prop_assert!(b.releases.is_empty(), "high-water mode released");
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn model_release(ops in vec(op(), 1..64)) {
        run(Mode::Release, ops)?;
    }

    #[test]
    fn model_high_water(ops in vec(op(), 1..64)) {
        run(Mode::HighWater, ops)?;
    }
}

// ----- Regressions -----

/// glibc's malloc reserves 128 MiB `PROT_NONE` per thread arena (`new_heap`), trims it to an
/// aligned 64 MiB with `munmap`, makes the front writable as it grows and gives the tail back
/// with `mmap(MAP_FIXED, PROT_NONE)`. capnix cleared freed pages in place without knowing which
/// were ever written: ~66 MB per sandbox. Only the pages ever writable may cost anything.
#[test]
fn glibc_prot_none_heap_costs_nothing_untouched() {
    for mode in [Mode::Release, Mode::HighWater] {
        let r = Reservation::new(1 << 30);
        let mut t = table(CAPACITY);
        let mut a = arena(&r, mode, &mut t);
        let mut b = Fake::new(&r);
        let heap_max = 64 * MB;
        let p = a.mmap(&mut b, 0, 2 * heap_max, PROT_NONE, ANON | MAP_NORESERVE, None).unwrap();
        // Trim to a 64 MiB-aligned block, as new_heap does.
        let h = (p + heap_max - 1) & !(heap_max - 1);
        if h > p {
            a.munmap(&mut b, p, h - p).unwrap();
        }
        if p + 2 * heap_max > h + heap_max {
            a.munmap(&mut b, h + heap_max, p + 2 * heap_max - (h + heap_max)).unwrap();
        }
        // grow_heap, writes, shrink_heap, delete_heap.
        a.mprotect(h, 132 << 10, RW).unwrap();
        mem(h, 1)[0] = 1;
        a.mprotect(h, MB, RW).unwrap();
        mem(h + MB - PAGE, 1)[0] = 2;
        assert_eq!(a.mmap(&mut b, h + (256 << 10), MB - (256 << 10), PROT_NONE, ANON | MAP_FIXED, None), Ok(h + (256 << 10)));
        // The written page reads zero again: given back (not resident), or cleared in place. (Not
        // read in release mode: reading faults in the host's zero page, spoiling the counts below.)
        match mode {
            Mode::Release => assert_eq!(r.resident(h + MB - PAGE, PAGE), 0),
            Mode::HighWater => assert!(is_zero(h + MB - PAGE, PAGE)),
        }
        a.munmap(&mut b, h, heap_max).unwrap();
        a.check();

        // Releases only ever covered the megabyte that was writable.
        assert!(b.releases.iter().all(|&(x, n)| x >= h && x + n <= h + MB), "{mode:?}: {:x?}", b.releases);
        assert!(b.released() <= MB);
        // Cleared in place: only the one written page that was handed out again (the shrink).
        assert_eq!(a.stats().zeroed, if mode == Mode::HighWater { PAGE as u64 } else { 0 });
        // The host holds nothing outside it (release mode: nothing at all).
        assert_eq!(r.resident(p, h - p), 0);
        assert_eq!(r.resident(h + MB, p + 2 * heap_max - (h + MB)), 0);
        if mode == Mode::Release {
            assert_eq!(r.resident(h, MB), 0);
        }

        // The next thread's heap reuses it: still nothing outside the written megabyte.
        let q = a.mmap(&mut b, 0, 2 * heap_max, PROT_NONE, ANON | MAP_NORESERVE, None).unwrap();
        assert_eq!(q, p);
        assert!(is_zero(h, MB));
        assert_eq!(r.resident(p, 2 * heap_max) - r.resident(h, MB), 0);
    }
}

/// MAP_FIXED over the program's own mapping replaces it (zero, new protection); the rest stays.
#[test]
fn map_fixed_replaces_existing_mapping() {
    for mode in [Mode::Release, Mode::HighWater] {
        let r = Reservation::new(64 * MB);
        let mut t = table(CAPACITY);
        let mut a = arena(&r, mode, &mut t);
        let mut b = Fake::new(&r);
        b.files.insert(7, vec![b'f'; 2 * PAGE]);
        let p = a.mmap(&mut b, 0, 16 * PAGE, RW, ANON, None).unwrap();
        mem(p, 16 * PAGE).fill(0xaa);

        assert_eq!(a.mmap(&mut b, p + 4 * PAGE, 4 * PAGE, RW, ANON | MAP_FIXED, None), Ok(p + 4 * PAGE));
        assert!(is_zero(p + 4 * PAGE, 4 * PAGE));
        assert!(mem(p, 4 * PAGE).iter().chain(mem(p + 8 * PAGE, 8 * PAGE).iter()).all(|&x| x == 0xaa));

        assert_eq!(a.mmap(&mut b, p + 8 * PAGE, 2 * PAGE, PROT_READ, ANON | MAP_FIXED, None), Ok(p + 8 * PAGE));
        assert_eq!(prot_at(&a, p + 8 * PAGE), Some(PROT_READ));
        assert!(is_zero(p + 8 * PAGE, 2 * PAGE));

        let f = Some(FileMap { file: 7, offset: 0 });
        assert_eq!(a.mmap(&mut b, p + 10 * PAGE, 2 * PAGE, PROT_READ, MAP_PRIVATE | MAP_FIXED, f), Ok(p + 10 * PAGE));
        assert!(mem(p + 10 * PAGE, 2 * PAGE).iter().all(|&x| x == b'f'));
        assert_eq!(mem(p + 12 * PAGE, 1)[0], 0xaa);

        assert_eq!(a.mmap(&mut b, p, PAGE, RW, ANON | MAP_FIXED_NOREPLACE, None), Err(Errno::EXIST));
        assert_eq!(mem(p, 1)[0], 0xaa);
        assert_eq!(a.mmap(&mut b, p + 16 * PAGE, PAGE, RW, ANON | MAP_FIXED_NOREPLACE, None), Ok(p + 16 * PAGE));
        // Outside the arena: the dispatcher's business, not ours.
        assert_eq!(a.mmap(&mut b, r.base + r.len, PAGE, RW, ANON | MAP_FIXED, None), Err(Errno::NOMEM));
        assert_eq!(a.stats().mapped, 17 * PAGE);
        a.check();
    }
}

/// mremap grows in place when it can, else moves with MREMAP_MAYMOVE, keeping the content.
#[test]
fn mremap_grow_and_move_preserve_content() {
    for mode in [Mode::Release, Mode::HighWater] {
        let r = Reservation::new(64 * MB);
        let mut t = table(CAPACITY);
        let mut a = arena(&r, mode, &mut t);
        let mut b = Fake::new(&r);
        let pattern = |i: usize| (i % 251) as u8 + 1;
        let p = a.mmap(&mut b, 0, 4 * PAGE, RW, ANON, None).unwrap();
        for (i, x) in mem(p, 4 * PAGE).iter_mut().enumerate() {
            *x = pattern(i);
        }
        let intact = |at: usize, n: usize| mem(at, n).iter().enumerate().all(|(i, &x)| x == pattern(i));

        assert_eq!(a.mremap(&mut b, p, 4 * PAGE, 8 * PAGE, 0, 0), Ok(p));
        assert!(intact(p, 4 * PAGE) && is_zero(p + 4 * PAGE, 4 * PAGE));
        mem(p + 4 * PAGE, 4 * PAGE).fill(0x55);

        // Blocked after: no move without MAYMOVE; with it, a move.
        a.mmap(&mut b, p + 8 * PAGE, PAGE, RW, ANON | MAP_FIXED, None).unwrap();
        assert_eq!(a.mremap(&mut b, p, 8 * PAGE, 16 * PAGE, 0, 0), Err(Errno::NOMEM));
        let q = a.mremap(&mut b, p, 8 * PAGE, 16 * PAGE, MREMAP_MAYMOVE, 0).unwrap();
        assert_ne!(q, p);
        assert!(intact(q, 4 * PAGE) && mem(q + 4 * PAGE, 4 * PAGE).iter().all(|&x| x == 0x55));
        assert!(is_zero(q + 8 * PAGE, 8 * PAGE));
        assert_eq!(prot_at(&a, p), None, "the old range is unmapped");
        assert_eq!(prot_at(&a, q + 15 * PAGE), Some(RW));

        // MREMAP_FIXED, shrinking as it moves, over whatever was there.
        let s = r.base + 32 * MB;
        a.mmap(&mut b, s, 2 * PAGE, PROT_READ, ANON | MAP_FIXED, None).unwrap();
        assert_eq!(a.mremap(&mut b, q, 16 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, s), Ok(s));
        assert!(intact(s, 4 * PAGE));
        assert_eq!(prot_at(&a, s + PAGE), Some(RW));
        assert_eq!(prot_at(&a, q), None);
        assert_eq!(a.mremap(&mut b, s, 4 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, s + PAGE), Err(Errno::INVAL));
        assert_eq!(a.mremap(&mut b, s, 4 * PAGE, 4 * PAGE, MREMAP_FIXED, s + MB), Err(Errno::INVAL));
        assert_eq!(a.mremap(&mut b, s, 4 * PAGE, 4 * PAGE, MREMAP_MAYMOVE | MREMAP_DONTUNMAP, 0), Err(Errno::INVAL));

        // Shrink in place.
        assert_eq!(a.mremap(&mut b, s, 4 * PAGE, PAGE, 0, 0), Ok(s));
        assert!(intact(s, PAGE));
        assert_eq!(prot_at(&a, s + PAGE), None);
        // Not mapped.
        assert_eq!(a.mremap(&mut b, s + PAGE, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0), Err(Errno::FAULT));
        a.check();
        if mode == Mode::HighWater {
            assert!(b.releases.is_empty());
        }
    }
}

/// A writable MAP_SHARED file mapping is a copy written back at msync, munmap and exit; its
/// handle is closed once nothing maps it. A private one is never written back.
#[test]
fn shared_mapping_written_back() {
    let r = Reservation::new(64 * MB);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, Mode::Release, &mut t);
    let mut b = Fake::new(&r);
    b.files.insert(7, vec![b'x'; 3 * PAGE]);
    let f = Some(FileMap { file: 7, offset: 0 });

    let p = a.mmap(&mut b, 0, 3 * PAGE, RW, MAP_SHARED, f).unwrap();
    assert!(mem(p, 3 * PAGE).iter().all(|&x| x == b'x'));
    let h = a.mappings().next().unwrap().shared.unwrap().file;
    assert_ne!(h, 7, "the arena keeps its own handle");

    mem(p, 1)[0] = b'A';
    assert_eq!(a.msync(&mut b, p, PAGE, MS_SYNC), Ok(0));
    assert_eq!(b.files[&7][0], b'A');

    mem(p + 2 * PAGE, 1)[0] = b'B';
    assert_eq!(a.munmap(&mut b, p + 2 * PAGE, PAGE), Ok(0));
    assert_eq!(b.files[&7][2 * PAGE], b'B');
    assert!(b.closed.is_empty(), "still mapped");

    // A move keeps it: written back from the new place, to the same offsets.
    let q = a.mremap(&mut b, p, 2 * PAGE, 2 * PAGE, MREMAP_MAYMOVE | MREMAP_FIXED, r.base + 8 * MB).unwrap();
    mem(q + PAGE, 1)[0] = b'C';
    assert_eq!(a.writeback_all(&mut b), Ok(0));
    assert_eq!(&b.files[&7][..PAGE + 1], [&b"A"[..], &[b'x'; PAGE - 1], b"C"].concat());
    assert!(b.closed.is_empty());

    assert_eq!(a.munmap(&mut b, q, 2 * PAGE), Ok(0));
    assert_eq!(b.closed, [h]);

    // At an offset; replaced by MAP_FIXED (written back first).
    let p = a.mmap(&mut b, 0, PAGE, RW, MAP_SHARED, Some(FileMap { file: 7, offset: PAGE as u64 })).unwrap();
    mem(p, 1)[0] = b'D';
    a.mmap(&mut b, p, PAGE, RW, ANON | MAP_FIXED, None).unwrap();
    assert_eq!(b.files[&7][PAGE], b'D');
    assert_eq!(b.closed.len(), 2);

    // Private, or read-only shared: never written back.
    let writes = b.writes.len();
    let p = a.mmap(&mut b, 0, PAGE, RW, MAP_PRIVATE, f).unwrap();
    let s = a.mmap(&mut b, 0, PAGE, PROT_READ, MAP_SHARED, f).unwrap();
    mem(p, 1)[0] = b'P';
    assert_eq!(a.msync(&mut b, p, PAGE, MS_ASYNC), Ok(0));
    assert_eq!(a.msync(&mut b, s, PAGE, MS_SYNC), Ok(0));
    assert_eq!(a.writeback_all(&mut b), Ok(0));
    assert_eq!(b.writes.len(), writes);
    assert_eq!(b.files[&7][0], b'A');

    assert_eq!(a.msync(&mut b, p, PAGE, MS_SYNC | MS_ASYNC), Err(Errno::INVAL));
    assert_eq!(a.msync(&mut b, r.base + 32 * MB, PAGE, MS_SYNC), Err(Errno::NOMEM));
    assert_eq!(a.mmap(&mut b, 0, PAGE, PROT_READ, MAP_PRIVATE, None), Err(Errno::BADF));
    a.check();
}

/// Threaded mode has no madvise: nothing is ever released, and reused pages (glibc's thread
/// stacks: freed when a thread exits, mapped again for the next) read zero, cleared in place
/// only where they were written.
#[test]
fn high_water_reuses_thread_stacks_zeroed() {
    let r = Reservation::new(256 * MB);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, Mode::HighWater, &mut t);
    let mut b = Fake::new(&r);
    let stack = 8 * MB;
    let mut first = None;
    for round in 0..4u8 {
        // allocate_stack: map, put a guard at the bottom, use the top.
        let s = a.mmap(&mut b, 0, stack, RW, ANON | 0x20000 /* MAP_STACK */, None).unwrap();
        assert_eq!(*first.get_or_insert(s), s, "the freed stack is reused");
        a.mprotect(s, PAGE, PROT_NONE).unwrap();
        // (Checking the written top only: reading the rest would fault in the host's zero page.)
        assert!(is_zero(s + stack - 4 * PAGE, 4 * PAGE), "round {round}: reused stack not zero");
        mem(s + stack - 3 * PAGE, 3 * PAGE).fill(round + 1);
        // glibc gives back the unused part of an exited thread's stack with MADV_DONTNEED.
        a.madvise(&mut b, s + PAGE, stack - 4 * PAGE, MADV_DONTNEED).unwrap();
        a.munmap(&mut b, s, stack).unwrap();
        a.check();
    }
    assert!(b.releases.is_empty());
    // Each reuse cleared the three written pages, no more.
    assert_eq!(a.stats().zeroed, 3 * 3 * PAGE as u64);
    // madvise(DONTNEED) clears in place too.
    let p = a.mmap(&mut b, 0, 4 * PAGE, RW, ANON, None).unwrap();
    mem(p, 4 * PAGE).fill(9);
    a.madvise(&mut b, p, 4 * PAGE, MADV_DONTNEED).unwrap();
    assert!(is_zero(p, 4 * PAGE));
    // MADV_FREE may keep the bytes, so it does.
    mem(p, 1)[0] = 9;
    a.madvise(&mut b, p, PAGE, MADV_FREE).unwrap();
    assert_eq!(mem(p, 1)[0], 9);
    assert!(b.releases.is_empty());
}

/// Release mode gives pages back in calls of at most 1 MiB, inside the arena (all the filter
/// allows), and the host then holds none of them.
#[test]
fn release_chunks_inside_arena() {
    let r = Reservation::new(64 * MB);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, Mode::Release, &mut t);
    let mut b = Fake::new(&r);
    let len = 5 * MB + MB / 2;
    let p = a.mmap(&mut b, 0, len, RW, ANON, None).unwrap();
    mem(p, len).fill(1);
    assert_eq!(r.resident(p, len), len / PAGE);

    a.madvise(&mut b, p + PAGE, 3 * MB, MADV_DONTNEED).unwrap();
    assert!(is_zero(p + PAGE, 3 * MB));
    assert_eq!(mem(p, 1)[0], 1);
    assert_eq!(b.released(), 3 * MB);

    a.munmap(&mut b, p, len).unwrap();
    assert_eq!(b.released(), 3 * MB + len);
    assert_eq!(a.stats().released, (3 * MB + len) as u64);
    assert!(b.releases.iter().all(|&(_, n)| n <= MADV_CHUNK)); // (Fake::release checks bounds too)
    assert_eq!(r.resident(p, len), 0);
    assert_eq!(a.stats().zeroed, 0);
    // Reused at once, zero, and nothing more to release.
    let q = a.mmap(&mut b, 0, len, RW, ANON, None).unwrap();
    assert_eq!(q, p);
    assert!(is_zero(q, len));
    assert_eq!(b.released(), 3 * MB + len);
}

/// PROT_EXEC is an ordinary protection: mapped and mprotect'd like any other.
#[test]
fn prot_exec_is_ordinary() {
    let rwx = PROT_READ | PROT_WRITE | PROT_EXEC;
    let r = Reservation::new(16 * MB);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, Mode::Release, &mut t);
    let mut b = Fake::new(&r);
    let p = a.mmap(&mut b, 0, PAGE, rwx, ANON, None).unwrap();
    assert_eq!(prot_at(&a, p), Some(rwx));
    let q = a.mmap(&mut b, 0, PAGE, RW, ANON, None).unwrap();
    assert_eq!(a.mprotect(q, PAGE, rwx), Ok(0));
    assert_eq!(prot_at(&a, q), Some(rwx));
}

/// When the table is full, calls that need entries fail with ENOMEM and change nothing;
/// unmapping still works, and frees entries.
#[test]
fn full_table_is_enomem_not_corruption() {
    let r = Reservation::new(16 * MB);
    let mut t = table(8);
    let mut a = arena(&r, Mode::Release, &mut t);
    let mut b = Fake::new(&r);
    let p = a.mmap(&mut b, 0, 64 * PAGE, RW, ANON, None).unwrap();
    mem(p, 64 * PAGE).fill(3);
    // Alternate protections until the table can't hold another split.
    let mut readonly = vec![];
    let mut i = 1;
    let err = loop {
        match a.mprotect(p + i * PAGE, PAGE, PROT_READ) {
            Ok(_) => readonly.push(i),
            Err(e) => break e,
        }
        i += 2;
    };
    assert_eq!(err, Errno::NOMEM);
    assert!(a.stats().extents <= 8);
    a.check();
    for j in 0..64 {
        assert_eq!(prot_at(&a, p + j * PAGE), Some(if readonly.contains(&j) { PROT_READ } else { RW }), "page {j}");
    }
    // A mapping that needs a split fails; nothing moved, nothing lost.
    let before = a.stats();
    assert_eq!(a.mmap(&mut b, p + 2 * MB, PAGE, RW, ANON | MAP_FIXED, None), Err(Errno::NOMEM));
    assert_eq!(a.munmap(&mut b, p + 8 * PAGE, PAGE), Err(Errno::NOMEM));
    assert_eq!(a.mremap(&mut b, p, PAGE, 2 * PAGE, MREMAP_MAYMOVE, 0), Err(Errno::NOMEM));
    assert_eq!(a.stats(), before);
    assert!(mem(p, 64 * PAGE).iter().all(|&x| x == 3));
    a.check();
    // Unmapping whole extents needs no room, and frees it.
    a.munmap(&mut b, p, 64 * PAGE).unwrap();
    assert_eq!(a.stats().extents, 1);
    assert_eq!(a.mmap(&mut b, 0, PAGE, RW, ANON, None), Ok(p));
    a.check();
}

/// The rest of the calls' contracts.
#[test]
fn brk_mincore_madvise_and_errors() {
    let r = Reservation::new(16 * MB);
    let mut t = table(CAPACITY);
    let mut a = arena(&r, Mode::Release, &mut t);
    let mut b = Fake::new(&r);
    b.files.insert(7, vec![b'f'; PAGE + 10]);

    // brk never grows: whatever is asked, the break stays, so glibc uses mmap.
    a.set_brk(0x5000_0000);
    assert_eq!(a.brk(0), 0x5000_0000);
    assert_eq!(a.brk(0x5100_0000), 0x5000_0000);

    let p = a.mmap(&mut b, 0, 4 * PAGE, RW, ANON, None).unwrap();
    let mut v = [0u8; 4];
    assert_eq!(a.mincore(p, 4 * PAGE, &mut v), Ok(0));
    assert_eq!(v, [1; 4]);
    assert_eq!(a.mincore(p, 5 * PAGE, &mut [0; 5]), Err(Errno::NOMEM));
    assert_eq!(a.mincore(p, 4 * PAGE, &mut [0; 3]), Err(Errno::FAULT));
    assert_eq!(a.mincore(p + 1, PAGE, &mut v), Err(Errno::INVAL));
    assert_eq!(a.mincore(r.base + r.len, PAGE, &mut v), Err(Errno::NOMEM));

    // A file's bytes survive DONTNEED (Linux would re-read the file); past EOF is zero.
    let f = a.mmap(&mut b, 0, 2 * PAGE, RW, MAP_PRIVATE, Some(FileMap { file: 7, offset: 0 })).unwrap();
    assert!(mem(f, PAGE + 10).iter().all(|&x| x == b'f') && is_zero(f + PAGE + 10, PAGE - 10));
    a.madvise(&mut b, f, 2 * PAGE, MADV_DONTNEED).unwrap();
    assert_eq!(mem(f, 1)[0], b'f');
    assert_eq!(a.madvise(&mut b, p, PAGE, MADV_WIPEONFORK), Err(Errno::INVAL));
    assert_eq!(a.madvise(&mut b, p, PAGE, MADV_REMOVE), Err(Errno::INVAL));
    assert_eq!(a.madvise(&mut b, p, PAGE, 999), Err(Errno::INVAL));
    assert_eq!(a.madvise(&mut b, p, PAGE, MADV_HUGEPAGE), Ok(0));
    assert_eq!(a.madvise(&mut b, f + PAGE, 2 * PAGE, MADV_DONTNEED), Err(Errno::NOMEM));

    assert_eq!(a.munmap(&mut b, p + 1, PAGE), Err(Errno::INVAL));
    assert_eq!(a.munmap(&mut b, p, 0), Err(Errno::INVAL));
    assert_eq!(a.munmap(&mut b, r.base + r.len, PAGE), Err(Errno::INVAL));
    assert_eq!(a.mprotect(p, 8 * PAGE, PROT_READ), Err(Errno::NOMEM));
    assert_eq!(prot_at(&a, p), Some(RW), "a failed mprotect changes nothing");
    assert_eq!(a.mmap(&mut b, 0, 0, RW, ANON, None), Err(Errno::INVAL));
    assert_eq!(a.mmap(&mut b, 0, PAGE, RW, MAP_ANONYMOUS, None), Err(Errno::INVAL));
    assert_eq!(a.mmap(&mut b, 0, 32 * MB, RW, ANON, None), Err(Errno::NOMEM));
    // A free hint is honoured.
    assert_eq!(a.mmap(&mut b, r.base + 8 * MB, PAGE, RW, ANON, None), Ok(r.base + 8 * MB));

    let s = a.stats();
    assert_eq!((s.size, s.mapped), (16 * MB, 7 * PAGE));
    assert_eq!(s.high_water, 8 * MB + PAGE);
    assert_eq!(ret(Ok(5)), 5);
    assert_eq!(ret(Err(Errno::NOMEM)), -12);
    // CAPACITY's documented cost: 40 bytes an entry, 2.5 MiB for the table.
    assert_eq!(core::mem::size_of::<Extent>(), 40);
    a.check();
}

/// High-water mode's image zone (threaded and fork mode give nothing back): a library's pages are
/// in place while never written; its data, written and freed, is no longer the image's, and the
/// next mapping of the file is a copy of the file's bytes, not the written pages. (Mapping them in
/// place again gave a forked compiler's linker a relocated libc: ld.so's "Inconsistency
/// detected".) Nothing is placed in the freed dirty part either.
#[test]
fn high_water_zone_maps_only_unwritten_pages_in_place() {
    let r = Reservation::new(16 * MB);
    let mut t = table(64);
    let mut a = arena(&r, Mode::Release, &mut t);
    let zone = r.base + 8 * MB;
    let file: Vec<u8> = (0..3 * PAGE).map(|i| (i % 251) as u8 + 1).collect();
    // SAFETY: a fresh memfd, mapped privately over the reservation's top (the runtime's zone).
    unsafe {
        let fd = libc::memfd_create(c"image".as_ptr(), 0);
        assert!(fd >= 0);
        let mut img = vec![0u8; 4 * PAGE];
        img[..file.len()].copy_from_slice(&file);
        assert_eq!(libc::write(fd, img.as_ptr().cast(), img.len()), img.len() as isize);
        let p = libc::mmap(zone as *mut _, img.len(), libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_FIXED, fd, 0);
        assert_eq!(p as usize, zone);
        libc::close(fd);
    }
    // As the runtime does: the zone set at boot, then threaded mode's switch.
    a.set_image_zone(zone).unwrap();
    a.set_mode(Mode::HighWater);
    let mut b = Fake::new(&r);
    b.files.insert(7, file.clone());
    b.in_zone.insert(7, (zone, file.len() as u64));
    let f7 = |offset| Some(FileMap { file: 7, offset });
    // ld.so: the span, the code where it is, the data (laid out at its file offset) where it is.
    assert_eq!(a.mmap(&mut b, 0, 3 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)), Ok(zone));
    assert_eq!(a.mmap(&mut b, zone + 2 * PAGE, PAGE, RW, MAP_PRIVATE | MAP_FIXED, f7(2 * PAGE as u64)), Ok(zone + 2 * PAGE));
    assert_eq!(b.read, 0, "all in place");
    mem(zone + 2 * PAGE, 1)[0] = 0x55; // a relocation
    a.munmap(&mut b, zone, 3 * PAGE).unwrap();
    a.check();
    // Again: the written page isn't the image's any more, so the span is a copy, of the file.
    let again = a.mmap(&mut b, 0, 3 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)).unwrap();
    assert!(again < zone, "mapped in place over a written page");
    assert_eq!(&mem(again, file.len())[..], &file[..]);
    // The code alone, never written, is still in place.
    assert_eq!(a.mmap(&mut b, 0, 2 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)), Ok(zone));
    // And a big mapping isn't placed in the zone's dirty page.
    let big = a.mmap(&mut b, 0, 7 * MB, RW, ANON, None).unwrap();
    assert!(big + 7 * MB <= zone);
    assert!(a.mmap(&mut b, 0, PAGE, RW, ANON, None).unwrap() < zone);
    a.check();
}

/// The image zone: a host file mapped privately into the arena's top, the way the runtime maps
/// the store's images. ld.so's sequence on a library there maps it in place (no copy); what it
/// writes is its own; anything freed there holds the image's bytes again, and other mappings
/// never land in it.
#[test]
fn image_zone_maps_files_in_place() {
    let r = Reservation::new(16 * MB);
    let mut t = table(64);
    let mut a = arena(&r, Mode::Release, &mut t);
    let zone = r.base + 8 * MB;
    // The image: a file of 2.5 pages at block 2, a nonzero byte after its slot (the next file).
    let mut img = vec![0u8; 8 * PAGE];
    let file: Vec<u8> = (0..5 * PAGE / 2).map(|i| (i % 251) as u8 + 1).collect();
    img[2 * PAGE..2 * PAGE + file.len()].copy_from_slice(&file);
    img[6 * PAGE] = 0xee;
    // SAFETY: a fresh memfd, mapped privately over the reservation's top (the runtime's zone).
    unsafe {
        let fd = libc::memfd_create(c"image".as_ptr(), 0);
        assert!(fd >= 0);
        assert_eq!(libc::write(fd, img.as_ptr().cast(), img.len()), img.len() as isize);
        let p = libc::mmap(zone as *mut _, img.len(), libc::PROT_READ | libc::PROT_WRITE, libc::MAP_PRIVATE | libc::MAP_FIXED, fd, 0);
        assert_eq!(p as usize, zone);
        libc::close(fd);
    }
    a.set_image_zone(zone).unwrap();
    assert_eq!(a.stats().size, 8 * MB, "the zone isn't the program's memory");
    let mut b = Fake::new(&r);
    b.files.insert(7, file.clone());
    let at = zone + 2 * PAGE;
    b.in_zone.insert(7, (at, file.len() as u64));
    let f7 = |offset| Some(FileMap { file: 7, offset });

    // ld.so: the span (3 pages of file, then 1 of .bss: the slot's zero block) from the file...
    assert_eq!(a.mmap(&mut b, 0, 4 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)), Ok(at));
    // ...each read-only segment where it already is...
    assert_eq!(a.mmap(&mut b, at, 2 * PAGE, PROT_READ | PROT_EXEC, MAP_PRIVATE | MAP_FIXED, f7(0)), Ok(at));
    assert_eq!(b.read, 0, "nothing copied");
    assert_eq!(&mem(at, file.len())[..], &file[..]);
    // ...the writable one copied (its offset differs from its address's), and .bss anonymous.
    assert_eq!(a.mmap(&mut b, at + 2 * PAGE, PAGE, RW, MAP_PRIVATE | MAP_FIXED, f7(PAGE as u64)), Ok(at + 2 * PAGE));
    assert_eq!(b.read, PAGE);
    assert_eq!(mem(at + 2 * PAGE, PAGE), &file[PAGE..2 * PAGE]);
    mem(at + 2 * PAGE, 1)[0] = 0x55;
    assert_eq!(a.mmap(&mut b, at + 3 * PAGE, PAGE, RW, ANON | MAP_FIXED, None), Ok(at + 3 * PAGE));
    assert!(is_zero(at + 3 * PAGE, PAGE));
    mem(at + 3 * PAGE, 1)[0] = 0x66;
    a.check();

    // A second mapping of the file while the first lives: a copy, elsewhere.
    let copy = a.mmap(&mut b, 0, 3 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)).unwrap();
    assert!(copy < zone);
    assert_eq!(&mem(copy, file.len())[..], &file[..]);
    // Nothing else is placed in the zone, however big.
    let big = a.mmap(&mut b, 0, 7 * MB, RW, ANON, None).unwrap();
    assert!(big + 7 * MB <= zone);
    // Unmapped, the zone holds the image again: mapped in place once more, unwritten.
    a.munmap(&mut b, at, 4 * PAGE).unwrap();
    assert_eq!(&mem(at, file.len())[..], &file[..]);
    assert!(is_zero(at + file.len(), 4 * PAGE - file.len()));
    assert_eq!(a.mmap(&mut b, 0, 4 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)), Ok(at));
    a.munmap(&mut b, at, 4 * PAGE).unwrap();
    // Past its slot it can't be (the next file's byte would show where zeros belong): copied.
    let long = a.mmap(&mut b, 0, 5 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)).unwrap();
    assert!(long < zone);
    assert!(is_zero(long + file.len(), 5 * PAGE - file.len()));
    // An anonymous mapping put in the zone by hand reads zero, and the image is back after it.
    assert_eq!(a.mmap(&mut b, zone, 8 * PAGE, RW, ANON | MAP_FIXED, None), Ok(zone));
    assert!(is_zero(zone, 8 * PAGE));
    a.munmap(&mut b, zone, 8 * PAGE).unwrap();
    assert_eq!(mem(zone + 6 * PAGE, 1)[0], 0xee);
    assert_eq!(a.mmap(&mut b, 0, 3 * PAGE, PROT_READ, MAP_PRIVATE, f7(0)), Ok(at));
    // Moved, an in-place mapping is a copy that keeps its bytes.
    let moved = a.mremap(&mut b, at, 3 * PAGE, 4 * PAGE, MREMAP_MAYMOVE, 0).unwrap();
    assert!(moved < zone);
    assert_eq!(&mem(moved, file.len())[..], &file[..]);
    a.check();
}
