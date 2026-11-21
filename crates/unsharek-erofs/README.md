# unsharek-erofs

Builds erofs images of a store path that Linux's driver mounts unmodified, laid out so the runtime
can map every ELF file in place: each file's data starts on a page, and each ELF gets a slot of
unused blocks as long as its memory image, where its writable segment and `.bss` land. ld.so's one
reservation of a library is answered with where its bytes already are in the image mapping, so code
is shared by every sandbox through the host's page cache and never copied.

Images are deterministic (owners root, mtime 1, sorted entries), so identical trees give identical
images. `synthesize` makes the same layout as a list of extents over the host's own files, nothing
copied. The crate's own tests check images with `fsck.erofs`.
