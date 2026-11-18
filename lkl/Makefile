# The kernel: LKL (arch/lkl) from $(EXOBOX_LKL_SRC), built out of tree into target/lkl with
# lkl/defconfig. The source tree is never written to (kbuild's O= needs it clean of in-tree builds),
# so one checkout serves this and any other build of it.
#
#   make -C lkl                       the kernel object and the posix host (both below)
#   make -C lkl EXOBOX_LKL_SRC=...    another checkout (default: the exobox/native worktree)
#
# Normally run by native/lkl-sys's build.rs, incrementally: a cold build is ~20 s on 24 cores, a
# no-op one ~3.5 s (kbuild walking its tree; build.rs only runs it when lkl/ or the source changed).
#
# Outputs, in $(KOUT):
#   liblkl-kernel.a   lkl.o alone (as $(KOUT)/lkl.o, with its stack note: see below): the kernel,
#                     what exobox links. exobox provides the host operations itself.
#   liblkl-posix.a    tools/lkl/lib's objects (liblkl-in.o): the stock posix host (lkl_host_ops) and
#                     its helpers (lkl_strerror, the disk/net/virtio code). Only lkl-sys's smoke test
#                     links it, to prove the plumbing on a stock kernel with a stock host.
#   tools/lkl/include headers for bindgen: the generated lkl/ (asm/syscalls.h, asm/host_ops.h, the
#                     uapi renamed lkl_*) and lkl_autoconf.h; lkl.h itself is in the source's
#                     tools/lkl/include.
# tools/lkl's own liblkl.a is both of these in one archive; split, the posix host can't be linked
# into exobox by accident (its symbols would satisfy what exobox's host must define).

.SUFFIXES:
MAKEFLAGS += -r --no-print-directory

EXOBOX_LKL_SRC ?= /home/ryan/src/lkl-exobox
# The build's root. target/ is cargo's and gitignored; build.rs passes its own (from OUT_DIR).
KOUT ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../target/lkl)
DEFCONFIG := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/defconfig)
LKL := $(KOUT)/tools/lkl
STAMP := $(KOUT)/.exobox_defconfig.sha256
SRCSTAMP := $(KOUT)/.exobox_lkl_src

# Assembler flags for every kernel object (C and asm; kbuild records them, so a change rebuilds).
# -mrelax-relocations=no: GOT references get R_X86_64_GOTPCREL, which no linker rewrites, instead of
# GOTPCRELX/REX_GOTPCRELX, which it may. GCC 16 emits `push sym@GOTPCREL(%rip)` (a function pointer
# passed on the stack) with a GOTPCRELX relocation, and ld 2.46 relaxed that `ff /6` as if it were
# an indirect call, into `addr32 call sym`: the kernel called the function instead of passing it
# (capnix tier A; four sites: udp_setsockopt, which Go's resolver reaches, and inet_ehashfn passed
# in inet_lhash2_lookup, __inet_lookup_listener, tcp_v4_rcv). Fixed here, in the object, so nothing
# that links it needs a flag (tier A linked with --no-relax). The cost: GOT loads instead of lea for
# the kernel's global addresses, which didn't show in tier A's benchmark.
# native/lkl-sys/tests/boot.rs checks lkl.o's relocations.
KFLAGS := -Wa,-mrelax-relocations=no

.PHONY: all kernel
all: $(KOUT)/liblkl-kernel.a $(KOUT)/liblkl-posix.a

# tools/lkl supports O=. kbuild only takes a named defconfig from arch/lkl/configs/ in the source,
# so lkl/defconfig is copied to $(KOUT)/.config and expanded there (KCONFIG=olddefconfig fills in
# the defaults `make <name>_defconfig` would). The stamp is the defconfig's hash: when it differs,
# the config starts over (tools/lkl's kernel.config, which it appends to .config, is made again) and
# kbuild rebuilds what the change touches. The same when the source checkout changes: the generated
# headers and the objects belong to one tree. (A build from another config once went unnoticed in
# capnix: hence the stamp, not "is there a .config".) Otherwise the sub-make is incremental: tools/lkl
# always recurses into kbuild (its lkl.o rule is FORCE), which finds nothing to do in seconds.
# Only liblkl.a is asked for (spelled as tools/lkl spells it, with its `//`), not tools/lkl's
# programs and tests.
kernel:
	@test -e $(EXOBOX_LKL_SRC)/arch/lkl/Makefile || { echo "EXOBOX_LKL_SRC=$(EXOBOX_LKL_SRC): not an LKL checkout" >&2; exit 1; }
	@mkdir -p $(LKL)/include $(LKL)/tests
	@if [ "$$(cat $(STAMP) 2>/dev/null)" != "$$(sha256sum < $(DEFCONFIG))" ] || \
	    [ "$$(cat $(SRCSTAMP) 2>/dev/null)" != "$(abspath $(EXOBOX_LKL_SRC))" ]; then \
		rm -f $(STAMP) $(LKL)/kernel.config $(LKL)/Makefile.conf; \
		cp $(DEFCONFIG) $(KOUT)/.config; \
		echo "$(abspath $(EXOBOX_LKL_SRC))" > $(SRCSTAMP); \
	fi
	+$(MAKE) -C $(EXOBOX_LKL_SRC)/tools/lkl O=$(KOUT) KCONFIG=olddefconfig \
		KCFLAGS="$(KFLAGS)" KAFLAGS="$(KFLAGS)" \
		$(if $(filter --jobserver% -j%,$(MAKEFLAGS)),,-j$(shell nproc)) $(KOUT)//tools/lkl/liblkl.a
	@sha256sum < $(DEFCONFIG) > $(STAMP)

# The archives are remade only when tools/lkl's objects are newer, so a no-op build leaves their
# mtimes (and cargo's link step) alone.
#
# lkl.o gets back a .note.GNU-stack (empty: the stack needn't be executable). Every kernel object
# has one, but the vmlinux link script's DISCARDS drops it, and an object without it tells ld the
# binary needs an executable stack: ld warns and makes the whole program's stack executable unless
# the link says -z noexecstack (rustc's does; a plain gcc link doesn't).
$(KOUT)/liblkl-kernel.a: kernel
	@if [ ! -e $@ ] || [ $(LKL)/lib/lkl.o -nt $@ ]; then \
		objcopy --add-section .note.GNU-stack=/dev/null --set-section-flags .note.GNU-stack=noload,readonly \
			$(LKL)/lib/lkl.o $(KOUT)/lkl.o && \
		rm -f $@ && ar rcs $@ $(KOUT)/lkl.o && echo "  AR      $@"; fi
$(KOUT)/liblkl-posix.a: kernel
	@if [ ! -e $@ ] || [ $(LKL)/lib/liblkl-in.o -nt $@ ]; then rm -f $@ && ar rcs $@ $(LKL)/lib/liblkl-in.o && echo "  AR      $@"; fi
