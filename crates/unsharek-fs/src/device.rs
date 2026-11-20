//! The virtio-fs device: virtio-mmio (version 2) registers, two split virtqueues (hiprio and one
//! request queue), and the config space `tag`. The driver's queue notify is served in the call:
//! each available chain's device-readable buffers are the request, its device-writable ones the
//! reply, then the used ring and the interrupt. No optional features (event index, indirect
//! descriptors, notifications data): VERSION_1 only, which virtio-mmio v2 requires.
//!
//! The guest's addresses are the host's (LKL has no MMU: the ring's and buffers' addresses are
//! pointers in this process).

use std::sync::Mutex;

use crate::Backend;

/// What the device needs of its host (the runtime), which this crate doesn't know.
#[derive(Clone, Copy)]
pub struct Host {
    /// Raise the device's interrupt (`lkl_trigger_irq`).
    pub trigger_irq: fn(u32),
    /// Run the backend: in a setup the thread's own syscalls trap to the guest, and a backend's
    /// are the host's (the runtime lets them through for the call).
    pub host_calls: fn(&mut dyn FnMut()),
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
/// A reply's largest size: a FUSE read's data (the driver's max_pages) and its header.
const REPLY_MAX: usize = (1 << 20) + 4096;

#[derive(Default, Clone, Copy)]
struct Queue {
    num: u32,
    ready: u32,
    desc: u64,
    avail: u64,
    used: u64,
    last_avail: u16,
}

/// A virtio-fs device and its backend.
pub struct VirtioFs {
    tag: [u8; 36],
    irq: u32,
    host: Host,
    backend: Box<dyn Backend>,
    status: u32,
    device_features_sel: u32,
    driver_features: u64,
    driver_features_sel: u32,
    queue_sel: u32,
    int_status: u32,
    queues: [Queue; QUEUES],
    request: Vec<u8>,
    reply: Vec<u8>,
    /// A notify served: the interrupt, raised once the lock is let go (its handler reads the
    /// status register).
    irq_due: bool,
}

static DEVICES: Mutex<Vec<VirtioFs>> = Mutex::new(Vec::new());

impl VirtioFs {
    /// A device for `backend`, mounted in the guest as `mount -t virtiofs <tag>`, interrupting
    /// on `irq`. [`VirtioFs::add`] registers it.
    pub fn new(tag: &str, irq: u32, host: Host, backend: Box<dyn Backend>) -> VirtioFs {
        let mut t = [0u8; 36];
        t[..tag.len().min(36)].copy_from_slice(&tag.as_bytes()[..tag.len().min(36)]);
        VirtioFs {
            tag: t,
            irq,
            host,
            backend,
            status: 0,
            device_features_sel: 0,
            driver_features: 0,
            driver_features_sel: 0,
            queue_sel: 0,
            int_status: 0,
            queues: [Queue::default(); QUEUES],
            request: Vec::new(),
            reply: vec![0; REPLY_MAX],
            irq_due: false,
        }
    }

    /// Register the device: its MMIO window's address and size, for
    /// `virtio_mmio_device_add(base, size, irq)` (the caller's: LKL's syscall).
    pub fn add(self) -> (usize, usize) {
        let mut d = DEVICES.lock().unwrap();
        let base = BASE + d.len() * 0x1000;
        d.push(self);
        (base, MMIO_SIZE)
    }

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

    fn write(&mut self, off: usize, val: &[u8]) -> i32 {
        if off >= 0x100 || val.len() != 4 {
            return -1;
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
            0x050 => self.notify(v as usize % QUEUES),
            0x064 => self.int_status &= !v,
            0x070 => {
                self.status = v;
                if v == 0 {
                    self.queues = [Queue::default(); QUEUES];
                }
            }
            0x080 => lo(&mut self.queues[sel].desc),
            0x084 => hi(&mut self.queues[sel].desc),
            0x090 => lo(&mut self.queues[sel].avail),
            0x094 => hi(&mut self.queues[sel].avail),
            0x0a0 => lo(&mut self.queues[sel].used),
            0x0a4 => hi(&mut self.queues[sel].used),
            _ => return -1,
        }
        0
    }

    /// Serve queue `qi`: every chain the driver made available since the last notify.
    fn notify(&mut self, qi: usize) {
        let q = self.queues[qi];
        if q.ready == 0 || q.num == 0 {
            return;
        }
        let num = q.num as usize;
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
                std::sync::atomic::fence(std::sync::atomic::Ordering::Acquire);
                if last == avail_idx {
                    break;
                }
                let head = core::ptr::read_volatile(avail.add(2 + last as usize % num));
                // the chain: readable buffers, then writable ones
                self.request.clear();
                let mut writable: Vec<(*mut u8, usize)> = Vec::new();
                let mut i = head as usize;
                for _ in 0..num {
                    let d = desc.add(16 * (i % num));
                    let addr = (d as *const u64).read_unaligned() as *mut u8;
                    let len = (d.add(8) as *const u32).read_unaligned() as usize;
                    let flags = (d.add(12) as *const u16).read_unaligned();
                    let next = (d.add(14) as *const u16).read_unaligned();
                    if flags & DESC_F_WRITE != 0 {
                        writable.push((addr, len));
                    } else {
                        self.request.extend_from_slice(core::slice::from_raw_parts(addr, len));
                    }
                    if flags & DESC_F_NEXT == 0 {
                        break;
                    }
                    i = next as usize;
                }
                let room: usize = writable.iter().map(|w| w.1).sum::<usize>().min(self.reply.len());
                let (req, reply, backend) = (&self.request, &mut self.reply[..room], &mut self.backend);
                let mut n = 0;
                (self.host.host_calls)(&mut || n = backend.handle(req, reply));
                // scatter the reply into the writable buffers
                let mut off = 0;
                for &(addr, len) in &writable {
                    let k = len.min(n - off);
                    core::ptr::copy_nonoverlapping(self.reply.as_ptr().add(off), addr, k);
                    off += k;
                    if off == n {
                        break;
                    }
                }
                let used_idx = core::ptr::read_volatile((used as *const u16).add(1));
                let e = used.add(4 + 8 * (used_idx as usize % num));
                (e as *mut u32).write_unaligned(head as u32);
                (e.add(4) as *mut u32).write_unaligned(n as u32);
                std::sync::atomic::fence(std::sync::atomic::Ordering::Release);
                core::ptr::write_volatile((used as *mut u16).add(1), used_idx.wrapping_add(1));
                last = last.wrapping_add(1);
            }
            self.queues[qi].last_avail = last;
        }
        self.int_status |= 1;
        self.irq_due = true;
    }
}

/// LKL's `ioremap` host op: a device's window maps to itself (its address is a cookie).
pub extern "C" fn ioremap(addr: core::ffi::c_long, size: core::ffi::c_int) -> *mut core::ffi::c_void {
    let n = DEVICES.lock().unwrap().len();
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
    // SAFETY: the caller's `size` bytes.
    let buf = unsafe { core::slice::from_raw_parts_mut(val as *mut u8, size as usize) };
    // The lock is held across the backend's call (a notify): one request at a time.
    let mut d = DEVICES.lock().unwrap();
    let Some(dev) = d.get_mut(i) else { return -1 };
    let r = if write != 0 { dev.write(off, buf) } else { dev.read(off, buf) };
    let irq = core::mem::take(&mut dev.irq_due).then_some((dev.host.trigger_irq, dev.irq));
    drop(d);
    if let Some((trigger, irq)) = irq {
        trigger(irq);
    }
    r
}
