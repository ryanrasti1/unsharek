//! Images: a host image's guest side (its block device) and the layout of its ELFs.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// A host image (erofs) mapped by `unsharek::Guest::map_image`, read-only. The guest sees it as the
/// block device [`Image::device`]; [`crate::setup::mount_erofs`] mounts it.
#[derive(Clone, Copy, Debug)]
pub struct Image {
    name: &'static str,
    /// The host mapping (read-only, alive for the process's life): the disk's bytes, which the
    /// runtime also copies files from.
    data: &'static [u8],
}

impl Image {
    /// Its name: `/dev/unsharek/<name>`.
    pub fn name(&self) -> &str {
        self.name
    }

    /// The guest's block device for it (a memblk disk, the kernel series' item 12).
    pub fn device(&self) -> PathBuf {
        Path::new("/dev/unsharek").join(self.name)
    }

    /// The image's bytes (the host mapping).
    pub fn bytes(&self) -> &'static [u8] {
        self.data
    }
}

/// `data` (an image the host mapped, read-only, for the process's life) as the guest's block
/// device `/dev/unsharek/<name>`; `in_zone`: where it is mapped in the arena's image zone too.
/// Host code before lockdown (unsharek's `Guest::map_image`).
pub fn register(name: &'static str, data: &'static [u8], in_zone: Option<usize>) -> io::Result<Image> {
    let image = Image { name, data };
    crate::setup::block_device(&image, in_zone)?;
    Ok(image)
}

/// The pages of an image (offsets in it) where its ELFs' writable segments land when mapped in
/// place: for each ELF of `layout` (unsharek-erofs' `offset slot size elf|data path` lines), each
/// writable PT_LOAD's pages, placed as ld.so places them over the reservation of the file's span
/// (at the file's offset of its lowest segment, `unsharek_erofs`'s `elf.rs`), within its slot. An
/// ELF whose headers can't be read has none (nothing of it can then be written in place: it is
/// copied).
///
/// The headers are read with `pread`, not from the image's mapping: touching the mapping made its
/// pages the sandbox's (1.5 MB more PSS per idle sandbox).
pub fn writable_pages(image: &File, layout: &[u8]) -> Vec<(usize, usize)> {
    use std::os::unix::fs::FileExt;
    const PAGE: u64 = 4096;
    let mut out = Vec::new();
    for line in layout.split(|&b| b == b'\n') {
        let mut f = line.splitn(5, |&b| b == b' ');
        let num = |x: Option<&[u8]>| x.and_then(|x| std::str::from_utf8(x).ok()?.parse::<u64>().ok());
        let (Some(offset), Some(slot), Some(size)) = (num(f.next()), num(f.next()), num(f.next())) else { continue };
        if f.next() != Some(b"elf".as_slice()) {
            continue;
        }
        // The ELF header, then as much as its program headers need (a page, nearly always).
        let mut head = vec![0u8; size.min(4096) as usize];
        if image.read_at(&mut head, offset).is_err() {
            continue;
        }
        let need = head.get(0x20..0x28).zip(head.get(0x36..0x3a)).map(|(o, n)| {
            let phoff = u64::from_le_bytes(o.try_into().unwrap());
            let (ent, num) = (u16::from_le_bytes([n[0], n[1]]) as u64, u16::from_le_bytes([n[2], n[3]]) as u64);
            phoff.saturating_add(ent * num)
        });
        if let Some(need) = need
            && need > head.len() as u64
            && need <= size.min(1 << 20)
        {
            head.resize(need as usize, 0);
            if image.read_at(&mut head, offset).is_err() {
                continue;
            }
        }
        let Some(loads) = elf_loads(&head) else { continue };
        let Some(&(vaddr0, off0, _, _, _)) = loads.iter().min_by_key(|l| l.0) else { continue };
        let lo = vaddr0 / PAGE * PAGE;
        let base = offset + off0 / PAGE * PAGE;
        for &(vaddr, _, memsz, writable, _) in &loads {
            if !writable {
                continue;
            }
            let Some(end) = vaddr.checked_add(memsz).and_then(|e| e.checked_next_multiple_of(PAGE)) else { continue };
            let (s, e) = (base + (vaddr / PAGE * PAGE - lo), (base + (end - lo)).min(offset + slot));
            if s < e {
                out.push((s as usize, e as usize));
            }
        }
    }
    out
}

/// An ELF64 little-endian file's PT_LOADs: (p_vaddr, p_offset, p_memsz, writable, p_filesz).
/// None if its headers aren't whole.
fn elf_loads(elf: &[u8]) -> Option<Vec<(u64, u64, u64, bool, u64)>> {
    let u16_at = |o: usize| Some(u16::from_le_bytes(elf.get(o..o + 2)?.try_into().ok()?));
    let u32_at = |o: usize| Some(u32::from_le_bytes(elf.get(o..o + 4)?.try_into().ok()?));
    let u64_at = |o: usize| Some(u64::from_le_bytes(elf.get(o..o + 8)?.try_into().ok()?));
    if elf.get(..6)? != b"\x7fELF\x02\x01" {
        return None;
    }
    let (phoff, phentsize, phnum) = (u64_at(0x20)? as usize, u16_at(0x36)? as usize, u16_at(0x38)? as usize);
    let mut loads = Vec::new();
    for i in 0..phnum {
        let ph = phoff.checked_add(i.checked_mul(phentsize)?)?;
        const PT_LOAD: u32 = 1;
        const PF_W: u32 = 2;
        if u32_at(ph)? != PT_LOAD {
            continue;
        }
        let flags = u32_at(ph + 4)?;
        loads.push((u64_at(ph + 16)?, u64_at(ph + 8)?, u64_at(ph + 40)?, flags & PF_W != 0, u64_at(ph + 32)?));
    }
    Some(loads)
}
