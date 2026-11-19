# The kernel: LKL (arch/lkl), built out of tree into target/lkl with lkl/defconfig. The build never
# writes to the source tree (kbuild's O= needs it clean of in-tree builds), so one checkout serves
# this and any other build of it.
#
#   make -C lkl                       the kernel object and the posix host (both below), from the
#                                     submodule lkl/linux (the kernel's commit is the submodule's:
#                                     what `nix build` links too)
#   make -C lkl EXOBOX_LKL_SRC=...    another checkout instead (another worktree's kernel)
#   make -C lkl EXOBOX_LKL_CONFIG=/abs/frag.config
#                                     config lines merged over lkl/defconfig (later lines win, as
#                                     kconfig reads a .config: CONFIG_SYSVIPC=y, or
#                                     `# CONFIG_X is not set`), for more drivers or filesystems
#   make -C lkl install PREFIX=dir    the kernel's build as lkl-sys's EXOBOX_LKL_PREBUILT takes it
#                                     (flake.nix's lib.exoboxKernel): see `install` below
#
# Normally run by native/lkl-sys's build.rs, incrementally: a cold build is ~20 s on 24 cores, a
# no-op one ~3.5 s (kbuild walking its tree; build.rs only runs it when lkl/, the fragment or the
# kernel's tree changed).
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

# The build's root. target/ is cargo's and gitignored; build.rs passes its own (from OUT_DIR).
KOUT ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/../target/lkl)

# The source: the submodule lkl/linux, as it is on disk. Kernel work happens there (a branch of
# the kernel's repository, checked out in the submodule), and a kernel change lands in exobox as
# the submodule's new commit, with exobox's side of it, in one commit. EXOBOX_LKL_SRC names
# another checkout (a worktree's, whose own submodule isn't checked out).
EXOBOX_LKL_SRC ?= $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/linux)
DEFCONFIG := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/defconfig)
LKL := $(KOUT)/tools/lkl
STAMP := $(KOUT)/.exobox_defconfig.sha256
# A config fragment, appended to lkl/defconfig. Absolute: this Makefile runs from lkl/ (make -C), so
# a relative path would silently mean another file than the caller's (build.rs resolves its own).
EXOBOX_LKL_CONFIG ?=
ifneq ($(EXOBOX_LKL_CONFIG),)
ifneq ($(EXOBOX_LKL_CONFIG),$(abspath $(EXOBOX_LKL_CONFIG)))
$(error EXOBOX_LKL_CONFIG=$(EXOBOX_LKL_CONFIG): must be an absolute path)
endif
endif
# The config the kernel starts from: the defconfig, then the fragment. The echo ends the file with a
# newline whatever the fragment ends with (tools/lkl appends its kernel.config to .config).
CONFIG_TEXT = { cat $(DEFCONFIG) $(EXOBOX_LKL_CONFIG) && echo; }
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
# so lkl/defconfig (and EXOBOX_LKL_CONFIG after it) is copied to $(KOUT)/.config and expanded there
# (KCONFIG=olddefconfig fills in the defaults `make <name>_defconfig` would; for a symbol set twice,
# kconfig takes the later line). The stamp is the hash of that text, so a change to the defconfig or
# the fragment's content (not only its name) is seen: when it differs,
# the config starts over (tools/lkl's kernel.config, which it appends to .config, is made again) and
# kbuild rebuilds what the change touches. The same when the source checkout changes: the generated
# headers and the objects belong to one tree. (A build from another config once went unnoticed in
# capnix: hence the stamp, not "is there a .config".) Otherwise the sub-make is incremental: tools/lkl
# always recurses into kbuild (its lkl.o rule is FORCE), which finds nothing to do in seconds.
# Only liblkl.a is asked for (spelled as tools/lkl spells it, with its `//`), not tools/lkl's
# programs and tests.
kernel:
	@test -e $(EXOBOX_LKL_SRC)/arch/lkl/Makefile || { echo "$(EXOBOX_LKL_SRC): not an LKL checkout (the submodule: git submodule update --init lkl/linux; or EXOBOX_LKL_SRC=<a checkout>)" >&2; exit 1; }
	@test -z "$(EXOBOX_LKL_CONFIG)" || test -f "$(EXOBOX_LKL_CONFIG)" || { echo "EXOBOX_LKL_CONFIG=$(EXOBOX_LKL_CONFIG): no such file" >&2; exit 1; }
	@mkdir -p $(LKL)/include $(LKL)/tests
	@if [ "$$(cat $(STAMP) 2>/dev/null)" != "$$($(CONFIG_TEXT) | sha256sum)" ] || \
	    [ "$$(cat $(SRCSTAMP) 2>/dev/null)" != "$(abspath $(EXOBOX_LKL_SRC))" ]; then \
		rm -f $(STAMP) $(LKL)/kernel.config $(LKL)/Makefile.conf; \
		$(CONFIG_TEXT) > $(KOUT)/.config; \
		echo "$(abspath $(EXOBOX_LKL_SRC))" > $(SRCSTAMP); \
	fi
	+$(MAKE) -C $(EXOBOX_LKL_SRC)/tools/lkl O=$(KOUT) KCONFIG=olddefconfig \
		KCFLAGS="$(KFLAGS)" KAFLAGS="$(KFLAGS)" \
		$(if $(filter --jobserver% -j%,$(MAKEFLAGS)),,-j$(shell nproc)) $(KOUT)//tools/lkl/liblkl.a
	@# Written only when it changes: build.rs watches it (and the other stamps), so a build with
	@# other settings into this shared $(KOUT) makes every other lkl-sys build script run again.
	@new=$$($(CONFIG_TEXT) | sha256sum); [ "$$(cat $(STAMP) 2>/dev/null)" = "$$new" ] || echo "$$new" > $(STAMP)

# The archives are remade only when tools/lkl's objects are newer, so a no-op build leaves their
# mtimes (and cargo's link step) alone.
#
# lkl.o gets back a .note.GNU-stack (empty: the stack needn't be executable). Every kernel object
# has one, but the vmlinux link script's DISCARDS drops it, and an object without it tells ld the
# binary needs an executable stack: ld warns and makes the whole program's stack executable unless
# the link says -z noexecstack (rustc's does; a plain gcc link doesn't).
#
# The kernel's writable data (.data, .bss, .data.rel, .data.rel.local: what it writes after boot)
# becomes one section, exobox_shared, which ends on a page boundary (the 4 KiB pad after it, its
# alignment the section's): fork mode maps the binary's exobox_shared shared between its processes
# before the first fork, so that the processes run one kernel (exobox_rt::share). The runtime's
# own shared state (its scheduler, the CPU token, the host ops' pools) is put in the same section
# by its statics' #[link_section]; in the binary, the Rust objects come before this one, so the
# section starts (its alignment) and ends (the pad) on a page and holds nothing else. Boot-only
# data (.init.data, __param, .data..ro_after_init) stays where it was: a fork copies it as it is.
SHARED := .data .bss .data.rel .data.rel.local
$(KOUT)/liblkl-kernel.a: kernel
	@if [ ! -e $@ ] || [ $(LKL)/lib/lkl.o -nt $@ ]; then \
		printf '\t.section exobox_shared,"aw",@progbits\n\t.balign 4096\n\t.zero 4096\n\t.section .note.GNU-stack,"",@progbits\n' \
			| as -o $(KOUT)/shared_end.o - && \
		objcopy --add-section .note.GNU-stack=/dev/null --set-section-flags .note.GNU-stack=noload,readonly \
			$(foreach s,$(SHARED),--rename-section $(s)=exobox_shared,alloc,load,contents,data) \
			$(LKL)/lib/lkl.o $(KOUT)/lkl-renamed.o && \
		ld -r -o $(KOUT)/lkl.o $(KOUT)/lkl-renamed.o $(KOUT)/shared_end.o && \
		rm -f $@ && ar rcs $@ $(KOUT)/lkl.o && echo "  AR      $@"; fi
$(KOUT)/liblkl-posix.a: kernel
	@if [ ! -e $@ ] || [ $(LKL)/lib/liblkl-in.o -nt $@ ]; then rm -f $@ && ar rcs $@ $(LKL)/lib/liblkl-in.o && echo "  AR      $@"; fi

# What a build of exobox needs from the kernel's, in one directory (lkl-sys's EXOBOX_LKL_PREBUILT,
# flake.nix's lib.exoboxKernel): the two archives and lkl.o (lkl-sys's relocation test reads it),
# include/ with lkl.h's tree from the source and the generated headers from the build merged (the
# two -I's of a dev build in one), and the expanded .config, to see what the kernel was built with.
PREFIX ?=
.PHONY: install
install: all
	@test -n "$(PREFIX)" || { echo "install: PREFIX= is required" >&2; exit 1; }
	mkdir -p $(PREFIX)/include
	cp $(KOUT)/liblkl-kernel.a $(KOUT)/liblkl-posix.a $(KOUT)/lkl.o $(KOUT)/.config $(PREFIX)/
	@# -L: copies of the files, not links into the source (flake.nix's is a tree of symlinks).
	cp -rL $(EXOBOX_LKL_SRC)/tools/lkl/include/. $(LKL)/include/. $(PREFIX)/include/
