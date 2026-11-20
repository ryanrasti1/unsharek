# unsharek-fs

Host directories for the guest, through Linux's own virtio-fs driver: the guest mounts
`-t virtiofs <tag>`, and its stock `fs/fuse/virtio_fs.c` puts FUSE requests on a virtqueue. This
crate is the device's host side, a virtio-mmio (v2) device with two split virtqueues: it takes each
request off the queue as bytes, sends it to the device's server over a unix stream socket (`wire`:
a length, then the bytes, each way), and scatters the reply back. The kernel side is config only.

The sandbox's part is `read` and `write` on that one granted fd, which its filter already allows:
nothing of the server runs in the sandbox. The server is another process, anything speaking
`wire`; `unsharek-fs-server` is the one the CLI runs. One request at a time, the guest's CPU held
for its round trip (the kernel runs on one guest CPU, so the device needs no lock); in fork mode
the devices' state is a static of the runtime's shared section (`unsharek_rt::host::FS_DEVICES`).
