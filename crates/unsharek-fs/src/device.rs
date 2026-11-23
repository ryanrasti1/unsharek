//! The virtio-fs device: virtio-mmio (version 2) registers, two split virtqueues (hiprio and one
//! request queue), and the config space `tag`. The driver's queue notify is served in the call:
//! each available chain's device-readable buffers are the request, served whole in this process
//! ([`Host::rpc`]: the passthrough, [`crate::passthrough`]); the reply is scattered into the
//! chain's device-writable buffers, then the used ring and the interrupt. No optional features (event
//! index, indirect descriptors, notification data): VERSION_1 only, which virtio-mmio v2 requires.
//!
//! The guest's addresses are the host's (LKL has no MMU: the ring's and buffers' addresses are
//! pointers in this process).
//!
//! **One request at a time, no lock.** Only the guest kernel touches the device (its readl and
//! writel are [`iomem_access`] calls), and the kernel runs on one guest CPU: in coroutine mode one
//! host thread, in threaded and fork mode whichever thread holds the CPU token. So calls never
//! overlap, and the device's state needs no lock (a lock's wait would be a futex, which the filter
//! doesn't allow). Each request is served in the notify, the CPU held: the guest waits for each
//! file operation, as for a disk without a queue.
//!
//! **Fork mode.** A guest fork is a host fork, and any process may run the kernel next: the
//! devices' state ([`Devices`]) is in the runtime's shared section (mapped shared before the
//! first fork), and so is what serves it (the passthrough's nodes, in the kernel's pool). The
//! request and reply buffers are each process's own, used only within one call.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicUsize, Ordering, fence};

/// What the device needs of its host (the runtime), which this crate doesn't know.
#[derive(Clone, Copy)]
pub struct Host {
    /// Raise the device's interrupt (`lkl_trigger_irq`).
    pub trigger_irq: fn(u32),
    /// Serve one request of the device whose server state is `state` (the passthrough's,
    /// [`crate::passthrough::serve`]): the reply's length in `reply` (0: none), or an errno.
    pub rpc: fn(state: usize, request: &[u8], reply: &mut [u8]) -> Result<usize, i32>,
}

const MAGIC: u32 = 0x7472_6976; // "virt"
const VERSION: u32 = 2;
const DEVICE_ID_FS: u32 = 26;
const VENDOR: u32 = 0x554e_534b; // "UNSK"
const F_VERSION_1: u64 = 1 << 32;
const QUEUES: usize = 2;
const QUEUE_MAX: u32 = 128;
const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
/// The size of an MMIO window: registers, then the config space.
pub const MMIO_SIZE: usize = 0x100 + CONFIG_LEN;
const CONFIG_LEN: usize = 36 + 4 + 4;
/// Where the windows are: fake addresses, never dereferenced (LKL's readl/writel are
/// `iomem_access` calls), one page apart.
const BASE: usize = 0x10_0000_0000;
/// The most devices (host directories) a sandbox has.
pub const MAX_DEVICES: usize = 16;

#[derive(Clone, Copy)]
struct Queue {
    num: u32,
    ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

const QUEUE0: Queue = Queue { num: 0, ready: 0, desc: 0, avail: 0, used: 0, last_avail: 0 };

/// A virtio-fs device: its registers and its server's state. Plain data (no heap): it lives in
/// the shared section.
#[derive(Clone, Copy)]
struct Device {
    tag: [u8; 36],
    irq: u32,
    state: usize,
    host: Option<Host>,
    status: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    int_status: u32,
    queues: [Queue; QUEUES],
}

const DEVICE0: Device = Device {
    tag: [0; 36],
    irq: 0,
    state: 0,
    host: None,
    status: 0,
    device_features_sel: 0,
    driver_features: 0,
    driver_features_sel: 0,
    queue_sel: 0,
    int_status: 0,
    queues: [QUEUE0; QUEUES],
};

/// The devices' state: in fork mode it must be shared by every process, so it is a static in the
/// runtime's shared section (`unsharek_rt::host::FS_DEVICES`: the section's statics must come
/// before the kernel's in the link, which the runtime's do), registered here with [`install`].
pub struct Devices {
    table: UnsafeCell<[Device; MAX_DEVICES]>,
    count: AtomicUsize,
}
// SAFETY: touched only by the guest kernel's calls, which never overlap (the module's comment),
// and by `add`, before the device is registered.
unsafe impl Sync for Devices {}

impl Devices {
    pub const fn new() -> Devices {
        Devices { table: UnsafeCell::new([DEVICE0; MAX_DEVICES]), count: AtomicUsize::new(0) }
    }
}

impl Default for Devices {
    fn default() -> Devices {
        Devices::new()
    }
}

/// Where the devices' state is ([`install`]): set before the first device, then only read (a
/// fork copies it, the same address in every process).
static TABLE: core::sync::atomic::AtomicPtr<Devices> = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// Use `devices` for the devices' state (the runtime's shared static). Before [`add`].
pub fn install(devices: &'static Devices) {
    TABLE.store(devices as *const Devices as *mut Devices, Ordering::Release);
}

fn devices() -> Option<&'static Devices> {
    // SAFETY: a &'static Devices, or null.
    unsafe { TABLE.load(Ordering::Acquire).as_ref() }
}

/// A request's or a reply's largest size: a FUSE write's or read's data (the server's max_write,
/// [`crate::MAX_DATA`]) and its headers.
pub const BUF: usize = crate::MAX_DATA + 4096;
struct Buf(UnsafeCell<[u8; BUF]>);
// SAFETY: as Devices's: one call at a time, in each process (these are private, not shared).
unsafe impl Sync for Buf {}
static REQUEST: Buf = Buf(UnsafeCell::new([0; BUF]));
/// A chain's writable buffers ([`Device::notify`]): as many as a reply's pages and headers.
struct Writable(UnsafeCell<[(*mut u8, usize); WRITABLE_MAX]>);
// SAFETY: as Buf's.
unsafe impl Sync for Writable {}
const WRITABLE_MAX: usize = BUF / 4096 + 8;
static WRITABLE: Writable = Writable(UnsafeCell::new([(core::ptr::null_mut(), 0); WRITABLE_MAX]));
static REPLY: Buf = Buf(UnsafeCell::new([0; BUF]));

/// A device `tag` (mounted in the guest as `mount -t virtiofs <tag>`), interrupting on `irq`,
/// served from `state` ([`Host::rpc`]'s): its MMIO window's address and size, for
/// `virtio_mmio_device_add(base, size, irq)` (the caller's: LKL's syscall). Host code, before the
/// first fork.
pub fn add(tag: &str, irq: u32, state: usize, host: Host) -> Option<(usize, usize)> {
    let d = devices()?;
    let i = d.count.load(Ordering::Relaxed);
    if i == MAX_DEVICES || tag.len() > 36 {
        return None;
    }
    let mut t = [0u8; 36];
    t[..tag.len()].copy_from_slice(tag.as_bytes());
    // SAFETY: slot i isn't registered yet: nothing else reads it.
    unsafe { (*d.table.get())[i] = Device { tag: t, irq, state, host: Some(host), ..DEVICE0 } };
    d.count.store(i + 1, Ordering::Release);
    Some((BASE + i * 0x1000, MMIO_SIZE))
}

impl Device {
    fn config(&self) -> [u8; CONFIG_LEN] {
        let mut c = [0u8; CONFIG_LEN];
        c[..36].copy_from_slice(&self.tag);
        c[36..40].copy_from_slice(&1u32.to_le_bytes()); // num_request_queues
        c
    }

    fn read(&self, off: usize, out: &mut [u8]) -> i32 {
        if off >= 0x100 {
            let c = self.config();
            let o = off - 0x100;
            if o + out.len() > c.len() {
                return -1;
            }
            out.copy_from_slice(&c[o..o + out.len()]);
            return 0;
        }
        let q = &self.queues[self.queue_sel as usize % QUEUES];
        let v: u32 = match off {
            0x000 => MAGIC,
            0x004 => VERSION,
            0x008 => DEVICE_ID_FS,
            0x00c => VENDOR,
            0x010 => (if self.device_features_sel == 1 { F_VERSION_1 >> 32 } else { F_VERSION_1 }) as u32,
            0x034 => QUEUE_MAX,
            0x044 => q.ready,
            0x060 => self.int_status,
            0x070 => self.status,
            0x0fc => 0, // config generation: the config never changes
            _ => return -1,
        };
        if out.len() != 4 {
            return -1;
        }
        out.copy_from_slice(&v.to_le_bytes());
        0
    }

    /// A register write; a queue notify serves the queue, and says so (the interrupt is due).
    fn write(&mut self, off: usize, val: &[u8]) -> Result<bool, ()> {
        if off >= 0x100 || val.len() != 4 {
            return Err(());
        }
        let v = u32::from_le_bytes(val.try_into().unwrap());
        let sel = self.queue_sel as usize % QUEUES;
        let lo = |p: &mut u64| *p = (*p & !0xffff_ffff) | v as u64;
        let hi = |p: &mut u64| *p = (*p & 0xffff_ffff) | (v as u64) << 32;
        match off {
            0x014 => self.device_features_sel = v,
            0x020 => {
                if self.driver_features_sel == 1 {
                    self.driver_features = (self.driver_features & 0xffff_ffff) | (v as u64) << 32
                } else {
                    self.driver_features = (self.driver_features & !0xffff_ffff) | v as u64
                }
            }
            0x024 => self.driver_features_sel = v,
            0x030 => self.queue_sel = v,
            0x038 => self.queues[sel].num = v,
            0x044 => self.queues[sel].ready = v,
            0x050 => return Ok(self.notify(v as usize % QUEUES)),
            0x064 => self.int_status &= !v,
            0x070 => {
                self.status = v;
                if v == 0 {
                    self.queues = [QUEUE0; QUEUES];
                }
            }
            0x080 => lo(&mut self.queues[sel].desc),
            0x084 => hi(&mut self.queues[sel].desc),
            0x090 => lo(&mut self.queues[sel].avail),
            0x094 => hi(&mut self.queues[sel].avail),
            0x0a0 => lo(&mut self.queues[sel].used),
            0x0a4 => hi(&mut self.queues[sel].used),
            _ => return Err(()),
        }
        Ok(false)
    }

    /// Serve queue `qi`: every chain the driver made available since the last notify. Whether
    /// any was (the interrupt is then due).
    fn notify(&mut self, qi: usize) -> bool {
        let q = self.queues[qi];
        let Some(host) = self.host else { return false };
        if q.ready == 0 || q.num == 0 {
            return false;
        }
        let num = q.num as usize;
        // SAFETY: this process's buffers, one call at a time (the module's comment).
        let (request, reply) = unsafe { (&mut *REQUEST.0.get(), &mut *REPLY.0.get()) };
        let mut served = false;
        // SAFETY: the driver's ring, at the addresses it wrote (this process's memory: LKL has no
        // MMU), laid out as virtio 1.x's split virtqueue: desc[num] of 16 bytes; avail = flags,
        // idx, ring[num] of u16; used = flags, idx, ring[num] of (u32 id, u32 len).
        unsafe {
            let desc = q.desc as *const u8;
            let avail = q.avail as *const u16;
            let used = q.used as *mut u8;
            let mut last = q.last_avail;
            loop {
                let avail_idx = core::ptr::read_volatile(avail.add(1));
                fence(Ordering::Acquire);
                if last == avail_idx {
                    break;
                }
                let head = core::ptr::read_volatile(avail.add(2 + last as usize % num));
                // the chain: readable buffers (the request, gathered), then writable ones
                let mut len = 0;
                // A read's reply is a header and up to max_pages (256) pages, each its own
                // descriptor: a shorter list cut the reply, a short read the guest took for EOF
                // (a 1.4 MB file read as 124 KiB: 32 descriptors, a 128 KiB readahead's 33).
                let writable = &mut *WRITABLE.0.get();
                let mut nw = 0;
                let mut i = head as usize;
                for _ in 0..num {
                    let d = desc.add(16 * (i % num));
                    let addr = (d as *const u64).read_unaligned() as *mut u8;
                    let dlen = (d.add(8) as *const u32).read_unaligned() as usize;
                    let flags = (d.add(12) as *const u16).read_unaligned();
                    let next = (d.add(14) as *const u16).read_unaligned();
                    if flags & DESC_F_WRITE != 0 {
                        if nw < writable.len() {
                            writable[nw] = (addr, dlen);
                            nw += 1;
                        }
                    } else {
                        let k = dlen.min(BUF - len);
                        core::ptr::copy_nonoverlapping(addr, request.as_mut_ptr().add(len), k);
                        len += k;
                    }
                    if flags & DESC_F_NEXT == 0 {
                        break;
                    }
                    i = next as usize;
                }
                let room = writable[..nw].iter().map(|w| w.1).sum::<usize>().min(BUF);
                let n = match (host.rpc)(self.state, &request[..len], &mut reply[..room]) {
                    Ok(n) => n,
                    // The server failed: the request fails (EIO), if it wants a reply.
                    Err(_) => error_reply(&request[..len], reply, room),
                };
                // scatter the reply into the writable buffers
                let mut off = 0;
                for &(addr, wlen) in &writable[..nw] {
                    if off == n {
                        break;
                    }
                    let k = wlen.min(n - off);
                    core::ptr::copy_nonoverlapping(reply.as_ptr().add(off), addr, k);
                    off += k;
                }
                let used_idx = core::ptr::read_volatile((used as *const u16).add(1));
                let e = used.add(4 + 8 * (used_idx as usize % num));
                (e as *mut u32).write_unaligned(head as u32);
                (e.add(4) as *mut u32).write_unaligned(n as u32);
                fence(Ordering::Release);
                core::ptr::write_volatile((used as *mut u16).add(1), used_idx.wrapping_add(1));
                last = last.wrapping_add(1);
                served = true;
            }
            self.queues[qi].last_avail = last;
        }
        if served {
            self.int_status |= 1;
        }
        served
    }
}

/// A FUSE error reply (`fuse_out_header`: len, -EIO, the request's unique) for a request whose
/// server didn't answer; nothing for one that wants no reply (no room for one).
fn error_reply(request: &[u8], reply: &mut [u8], room: usize) -> usize {
    if room < 16 || request.len() < 16 {
        return 0;
    }
    reply[..4].copy_from_slice(&16u32.to_le_bytes());
    reply[4..8].copy_from_slice(&(-5i32).to_le_bytes()); // EIO
    reply[8..16].copy_from_slice(&request[8..16]);
    16
}

/// LKL's `ioremap` host op: a device's window maps to itself (its address is a cookie).
pub extern "C" fn ioremap(addr: core::ffi::c_long, size: core::ffi::c_int) -> *mut core::ffi::c_void {
    let n = devices().map_or(0, |d| d.count.load(Ordering::Acquire));
    let a = addr as usize;
    if a >= BASE && a + size as usize <= BASE + n * 0x1000 { a as *mut _ } else { core::ptr::null_mut() }
}

/// LKL's `iomem_access` host op: a register read or write of a device's window.
///
/// # Safety
/// `val` points to `size` bytes, as LKL's readl/writel pass.
pub unsafe extern "C" fn iomem_access(
    addr: *const core::ffi::c_void,
    val: *mut core::ffi::c_void,
    size: core::ffi::c_int,
    write: core::ffi::c_int,
) -> core::ffi::c_int {
    let a = addr as usize;
    if a < BASE {
        return -1;
    }
    let (i, off) = ((a - BASE) / 0x1000, (a - BASE) % 0x1000);
    let Some(d) = devices() else { return -1 };
    if i >= d.count.load(Ordering::Acquire) {
        return -1;
    }
    // SAFETY: the caller's `size` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(val as *mut u8, size as usize) };
    // SAFETY: the kernel's calls never overlap (the module's comment); the borrow ends before the
    // interrupt, whose handler reads the device's registers (another call, nested in this one).
    let (r, irq) = {
        let dev = unsafe { &mut (*d.table.get())[i] };
        if write != 0 {
            match dev.write(off, buf) {
                Ok(due) => (0, due.then(|| (dev.host.map(|h| h.trigger_irq), dev.irq))),
                Err(()) => (-1, None),
            }
        } else {
            (dev.read(off, buf), None)
        }
    };
    if let Some((Some(trigger), irq)) = irq {
        trigger(irq);
    }
    r
}
