# unsharek-fs

Host directories for the guest, through Linux's own virtio-fs driver: the guest mounts
`-t virtiofs <tag>`, and its stock `fs/fuse/virtio_fs.c` puts FUSE requests on a virtqueue. This
crate is the device's host side, a virtio-mmio (v2) device with two split virtqueues, and what
serves it: `passthrough`, a host directory answered in this process with the plain file calls
unsharek-tcb's fs plugin allows (`openat`, `fstat`, `pread64`, `getdents64`, `readlinkat`; for
read-write also `pwrite64`, `ftruncate`, `fsync`, `mkdirat`, `unlinkat`, `renameat2`,
`symlinkat`, `fchmodat`, `utimensat`), each through the runtime's gate, every path absolute.
Landlock (unsharek-tcb's `plugin::Files`) confines the paths; none of this is trusted.

One request at a time, the guest's CPU held while it is served (the kernel runs on one guest
CPU, so the device needs no lock). Fork mode: the devices' state is a static of the runtime's
shared section (`unsharek_rt::host::FS_DEVICES`), each directory's nodes in memory the caller
maps shared, and each process keeps only a cache of fds it can open again by path.
