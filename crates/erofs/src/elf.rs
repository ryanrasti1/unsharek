//! How much of the image an ELF file's in-place mapping covers.
//!
//! ld.so maps a library (or the kernel an executable) in two steps: one `mmap(NULL, span, fd,
//! off0)` reserves the whole memory image at some base A, then each PT_LOAD is mapped
//! `MAP_FIXED` at `A + (page_down(p_vaddr) - lo)` from `page_down(p_offset)`. The runtime answers
//! the first call with A = where the file's bytes (at `off0`) sit in the image mapping, so every
//! segment whose `p_vaddr - p_offset` matches the first one's (all of GNU ld's read-only ones) is
//! already in place. The writable segment and .bss are mapped over whatever follows the file's
//! bytes in the image, up to `A + (hi - lo)`; the image keeps that range unused (the file's slot).

use std::fs::File;
use std::io::Read;

use object::elf::{FileHeader32, FileHeader64, PT_LOAD};
use object::read::elf::{FileHeader, ProgramHeader};
use object::{Endianness, ReadCache, ReadRef};

/// The loader's page size. 4 KiB: x86_64, the only target; the image's block size is the same, so
/// page-aligned in the file is block-aligned in the image.
pub const PAGE: u64 = 4096;

pub fn round_up(n: u64, to: u64) -> Option<u64> {
    n.checked_next_multiple_of(to)
}

/// What a regular file is, for its placement.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// No ELF magic.
    Data,
    /// ELF magic. `mapped`: bytes from the file's start that its loaded memory image covers
    /// (page-rounded), or None when the program headers can't be read or have no PT_LOAD (an odd
    /// ELF still gets a block-aligned slot of its own size).
    Elf { mapped: Option<u64> },
}

/// Reads the magic and, for an ELF, its program headers. Only I/O errors are errors: a malformed
/// ELF is still stored, just without a computed memory image.
pub fn classify(file: &File) -> std::io::Result<Kind> {
    let mut magic = [0u8; 4];
    let mut f = file;
    match f.read_exact(&mut magic) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(Kind::Data),
        Err(e) => return Err(e),
    }
    if magic != *b"\x7fELF" {
        return Ok(Kind::Data);
    }
    // Reads through a cache from the start of the file: headers only, not the whole library.
    let cache = ReadCache::new(file);
    let class = cache
        .read_bytes_at(4, 1)
        .ok()
        .and_then(|b| b.first().copied());
    let mapped = match class {
        Some(1) => mapped_len::<FileHeader32<Endianness>>(&cache),
        Some(2) => mapped_len::<FileHeader64<Endianness>>(&cache),
        _ => None,
    };
    Ok(Kind::Elf { mapped })
}

/// `page_down(off0) + (hi - lo)`, page-rounded: off0 is the first PT_LOAD's (lowest p_vaddr)
/// offset, lo its page-aligned address, hi the highest `p_vaddr + p_memsz`. For GNU ld's output
/// off0 is 0 and this is just the memory image's size; a nonzero off0 (unusual linkers) still
/// fits, since the reservation starts at the file's offset off0, not at its start. Overflow (a
/// corrupt header) is None.
fn mapped_len<H: FileHeader<Endian = Endianness>>(data: &ReadCache<&File>) -> Option<u64> {
    let header = H::parse(data).ok()?;
    let endian = header.endian().ok()?;
    let mut first: Option<(u64, u64)> = None; // (p_vaddr, p_offset) of the lowest PT_LOAD
    let mut hi = 0u64;
    for ph in header.program_headers(endian, data).ok()? {
        if ph.p_type(endian) != PT_LOAD {
            continue;
        }
        let vaddr: u64 = ph.p_vaddr(endian).into();
        let offset: u64 = ph.p_offset(endian).into();
        let memsz: u64 = ph.p_memsz(endian).into();
        hi = hi.max(vaddr.checked_add(memsz)?);
        if first.is_none_or(|(v, _)| vaddr < v) {
            first = Some((vaddr, offset));
        }
    }
    let (vaddr, offset) = first?;
    let lo = vaddr / PAGE * PAGE;
    let off0 = offset / PAGE * PAGE;
    round_up(off0.checked_add(hi - lo)?, PAGE)
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::io::Write;

    /// A little-endian ELF64 header and program headers, nothing else: enough for the loader's
    /// view. `loads`: (p_offset, p_vaddr, p_filesz, p_memsz). The file is padded to `len`.
    pub fn elf64(e_type: u16, loads: &[(u64, u64, u64, u64)], len: usize) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2; // ELFCLASS64
        b[5] = 1; // little-endian
        b[6] = 1; // EV_CURRENT
        b[16..18].copy_from_slice(&e_type.to_le_bytes());
        b[18..20].copy_from_slice(&62u16.to_le_bytes()); // EM_X86_64
        b[20..24].copy_from_slice(&1u32.to_le_bytes());
        b[32..40].copy_from_slice(&64u64.to_le_bytes()); // e_phoff
        b[52..54].copy_from_slice(&64u16.to_le_bytes()); // e_ehsize
        b[54..56].copy_from_slice(&56u16.to_le_bytes()); // e_phentsize
        b[56..58].copy_from_slice(&(loads.len() as u16).to_le_bytes());
        for &(off, vaddr, filesz, memsz) in loads {
            let mut ph = [0u8; 56];
            ph[..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
            ph[8..16].copy_from_slice(&off.to_le_bytes());
            ph[16..24].copy_from_slice(&vaddr.to_le_bytes());
            ph[24..32].copy_from_slice(&vaddr.to_le_bytes());
            ph[32..40].copy_from_slice(&filesz.to_le_bytes());
            ph[40..48].copy_from_slice(&memsz.to_le_bytes());
            ph[48..56].copy_from_slice(&PAGE.to_le_bytes());
            b.extend_from_slice(&ph);
        }
        b.resize(len.max(b.len()), 0xcc);
        b
    }

    fn classify_bytes(bytes: &[u8]) -> Kind {
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(bytes).unwrap();
        // classify reads from the file's current position: the start, as a fresh open is.
        std::io::Seek::rewind(&mut f).unwrap();
        classify(&f).unwrap()
    }

    #[test]
    fn data_files() {
        assert_eq!(classify_bytes(b""), Kind::Data);
        assert_eq!(classify_bytes(b"\x7fEL"), Kind::Data);
        assert_eq!(classify_bytes(b"#!/bin/sh\n"), Kind::Data);
    }

    #[test]
    fn shared_library() {
        // GNU ld's shape: text at 0, data a page past its file offset, .bss beyond the file.
        let loads = [(0, 0, 0x1800, 0x1800), (0x1e00, 0x2e00, 0x300, 0x5000)];
        let mapped = 0x2e00 + 0x5000; // hi - lo
        assert_eq!(
            classify_bytes(&elf64(3, &loads, 0x2100)),
            Kind::Elf {
                mapped: Some(round_up(mapped, PAGE).unwrap())
            }
        );
    }

    #[test]
    fn non_pie_executable() {
        // ET_EXEC at 0x400000: the span is relative to the first segment, not to 0.
        let loads = [
            (0, 0x400000, 0x1000, 0x1000),
            (0x1000, 0x401000, 0x10, 0x2000),
        ];
        assert_eq!(
            classify_bytes(&elf64(2, &loads, 0x1010)),
            Kind::Elf {
                mapped: Some(0x3000)
            }
        );
    }

    #[test]
    fn first_segment_past_the_start() {
        // The reservation maps from the first segment's (page-aligned) offset.
        let loads = [(0x1100, 0x10100, 0x100, 0x100)];
        assert_eq!(
            classify_bytes(&elf64(3, &loads, 0x1200)),
            Kind::Elf {
                mapped: Some(0x2000)
            }
        );
    }

    #[test]
    fn odd_elves() {
        // No PT_LOAD, truncated headers, an unknown class, an overflowing segment.
        assert_eq!(
            classify_bytes(&elf64(1, &[], 64)),
            Kind::Elf { mapped: None }
        );
        assert_eq!(
            classify_bytes(b"\x7fELF\x02\x01"),
            Kind::Elf { mapped: None }
        );
        assert_eq!(
            classify_bytes(b"\x7fELF\x07\x01\x01\0"),
            Kind::Elf { mapped: None }
        );
        let wrap = [(0, u64::MAX - 10, 0, 100)];
        assert_eq!(
            classify_bytes(&elf64(3, &wrap, 0x200)),
            Kind::Elf { mapped: None }
        );
    }
}
