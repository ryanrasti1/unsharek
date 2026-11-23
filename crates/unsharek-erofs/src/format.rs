//! erofs's on-disk structures, the subset this image uses (Linux's `fs/erofs/erofs_fs.h`). All
//! little-endian; each is written into a zeroed buffer, so reserved fields stay 0.

pub const MAGIC: u32 = 0xE0F5_E1E2;
pub const BLOCK: u64 = 4096;
pub const BLOCK_BITS: u8 = 12;
/// The superblock's place in block 0.
pub const SUPER_OFFSET: usize = 1024;
/// A nid is the inode's offset from the metadata area's start, in these units.
pub const NID_UNIT: u64 = 32;
/// `struct erofs_inode_extended`.
pub const INODE_SIZE: u64 = 64;
/// `struct erofs_dirent`.
pub const DIRENT_SIZE: usize = 12;
pub const NAME_MAX: usize = 255;

/// Data layouts (`i_format` bits 1..3).
pub const FLAT_PLAIN: u16 = 0;
pub const FLAT_INLINE: u16 = 2;

/// The kernel's FT_* directory entry types.
pub const FT_REG_FILE: u8 = 1;
pub const FT_DIR: u8 = 2;
pub const FT_SYMLINK: u8 = 7;

pub const S_IFREG: u16 = 0o100000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFLNK: u16 = 0o120000;

fn put(buf: &mut [u8], at: usize, bytes: &[u8]) {
    buf[at..at + bytes.len()].copy_from_slice(bytes);
}

pub struct Super {
    pub root_nid: u16,
    pub inos: u64,
    pub blocks: u32,
    pub meta_blkaddr: u32,
}

impl Super {
    /// `struct erofs_super_block` into block 0. No feature bits, no checksum (it's optional:
    /// EROFS_FEATURE_COMPAT_SB_CHKSUM unset), a zero uuid: the image depends only on its input.
    pub fn write(&self, block0: &mut [u8]) {
        let sb = &mut block0[SUPER_OFFSET..SUPER_OFFSET + 128];
        put(sb, 0, &MAGIC.to_le_bytes());
        sb[12] = BLOCK_BITS; // blkszbits
        put(sb, 14, &self.root_nid.to_le_bytes());
        put(sb, 16, &self.inos.to_le_bytes());
        put(sb, 24, &1u64.to_le_bytes()); // build_time: the store's mtime
        put(sb, 36, &self.blocks.to_le_bytes());
        put(sb, 40, &self.meta_blkaddr.to_le_bytes());
        put(sb, 64, b"unsharek-store"); // volume_name
    }
}

pub struct Inode {
    /// S_IF* | permission bits.
    pub mode: u16,
    pub layout: u16,
    pub size: u64,
    /// The first data block (FLAT_PLAIN), or 0 when there's none.
    pub blkaddr: u32,
    pub ino: u32,
    pub nlink: u32,
}

impl Inode {
    /// `struct erofs_inode_extended`: owner root, mtime 1 (as in the Nix store), no xattrs.
    pub fn write(&self, out: &mut [u8]) {
        let format = 1 | (self.layout << 1); // bit 0: EROFS_INODE_LAYOUT_EXTENDED
        put(out, 0, &format.to_le_bytes());
        put(out, 4, &self.mode.to_le_bytes());
        put(out, 8, &self.size.to_le_bytes());
        put(out, 16, &self.blkaddr.to_le_bytes()); // i_u.raw_blkaddr
        put(out, 20, &self.ino.to_le_bytes());
        put(out, 32, &1u64.to_le_bytes()); // i_mtime
        put(out, 44, &self.nlink.to_le_bytes());
    }
}

/// A directory's contents: entries sorted by name, bytewise ("." and ".." among them), since the
/// kernel looks names up by bisection. Each block holds whole entries: its dirents, then their
/// names, unterminated (a name's end is the next one's start; the block's last name ends at the
/// first NUL or the block's end, so a block's unused tail stays zero). The last block is cut to
/// its used bytes: the directory's size is `full blocks * BLOCK + last block's bytes`, as
/// mkfs.erofs does and the kernel's readdir expects (`maxsize = min(i_size - pos, blocksize)`).
pub fn dir_data(entries: &[(&[u8], u64, u8)]) -> Vec<u8> {
    let block = BLOCK as usize;
    let mut out = Vec::new();
    let mut i = 0;
    while i < entries.len() {
        let mut used = 0;
        let mut k = 0;
        while i + k < entries.len() && used + DIRENT_SIZE + entries[i + k].0.len() <= block {
            used += DIRENT_SIZE + entries[i + k].0.len();
            k += 1;
        }
        let start = out.len();
        out.resize(start + used, 0);
        let b = &mut out[start..];
        let mut nameoff = k * DIRENT_SIZE;
        for (j, &(name, nid, ftype)) in entries[i..i + k].iter().enumerate() {
            let de = &mut b[j * DIRENT_SIZE..(j + 1) * DIRENT_SIZE];
            put(de, 0, &nid.to_le_bytes());
            put(de, 8, &(nameoff as u16).to_le_bytes());
            de[10] = ftype;
            put(b, nameoff, name);
            nameoff += name.len();
        }
        i += k;
        if i < entries.len() {
            out.resize(start + block, 0);
        }
    }
    out
}
