# exobox's Nix library, without flakes: `import ./nix/lib.nix { inherit pkgs; }` gives
# `exoboxKernel` and `mkExobox`, the same functions the flake's `lib` has (flake.nix imports this).
# The kernel's default source is the submodule lkl/linux: a checkout of exobox used this way needs
# it checked out (`git submodule update --init lkl/linux`, or a recursive clone).
{ pkgs }:
let
  inherit (pkgs) lib;
  fs = lib.fileset;
  system = pkgs.stdenv.hostPlatform.system;

  # The kernel, built once by lkl/Makefile as its own derivation, in the layout lkl-sys's
  # build.rs takes as EXOBOX_LKL_PREBUILT (lkl/Makefile's `install`): liblkl-kernel.a, lkl.o,
  # liblkl-posix.a (lkl-sys's boot test, run in mkExobox's checkPhase), include/, and the
  # expanded .config. `config` is a fragment of kernel config lines over lkl/defconfig (later
  # lines win: "CONFIG_SYSVIPC=y\n", or "# CONFIG_X is not set\n").
  exoboxKernel = { src ? ../lkl/linux, config ? "" }:
    pkgs.stdenv.mkDerivation {
      pname = "exobox-kernel";
      version = src.shortRev or "0";
      inherit src;
      # Only the Makefile and the defconfig: an edit elsewhere in the repository doesn't rebuild
      # the kernel.
      lkl = fs.toSource {
        root = ../lkl;
        fileset = fs.unions [ ../lkl/Makefile ../lkl/defconfig ];
      };
      # A file, as in a dev build's EXOBOX_LKL_CONFIG (empty: the defconfig alone).
      fragment = pkgs.writeText "exobox-kernel-fragment.config" config;
      # The devshell's kernel tools (flake.nix's devShells), and the same compiler and
      # hardening flags as a dev build.
      nativeBuildInputs = with pkgs; [ flex bison bc python3 perl ];
      # Not $(whoami)@$(hostname) and the build's time: the same inputs make the same object.
      KBUILD_BUILD_USER = "nix";
      KBUILD_BUILD_HOST = "exobox";
      KBUILD_BUILD_TIMESTAMP = "1970-01-01";
      dontConfigure = true;
      # The build is out of tree, as in development, so the source is read, never written: it
      # is a tree of symlinks to the store's files, not a copy (1.7 GB, which once filled the
      # disk). Only the scripts are real files, for their shebangs: kbuild runs some directly,
      # and the sandbox has no /usr/bin/env.
      unpackPhase = ''
        runHook preUnpack
        cp -rs $src source
        chmod -R u+w source
        sourceRoot=source
        runHook postUnpack
      '';
      postPatch = ''
        grep -RlZ '^#!' scripts arch/lkl/scripts tools/lkl |
          while IFS= read -r -d "" f; do cp --remove-destination "$(readlink "$f")" "$f"; done
        chmod -R u+w scripts arch/lkl/scripts tools/lkl
        patchShebangs scripts arch/lkl/scripts tools/lkl
      '';
      # lkl/Makefile passes the outer make's jobserver on to kbuild.
      buildPhase = ''
        runHook preBuild
        make -C $lkl -j$NIX_BUILD_CORES EXOBOX_LKL_SRC=$PWD KOUT=$NIX_BUILD_TOP/kout \
          EXOBOX_LKL_CONFIG=$fragment
        runHook postBuild
      '';
      installPhase = ''
        runHook preInstall
        make -C $lkl install EXOBOX_LKL_SRC=$PWD KOUT=$NIX_BUILD_TOP/kout \
          EXOBOX_LKL_CONFIG=$fragment PREFIX=$out
        runHook postInstall
      '';
      # Objects to link, not programs: the fixup's strip and patchelf have nothing to do (and
      # stripping lkl.o would drop what the relocation test reads).
      dontStrip = true;
      dontPatchELF = true;
    };

  # exobox (the CLI) and exobox-erofs (the image builder), linking `kernel` (an exoboxKernel):
  # lkl-sys's build.rs runs no make (EXOBOX_LKL_PREBUILT).
  mkExobox = { kernel ? exoboxKernel { } }:
    pkgs.rustPlatform.buildRustPackage {
      pname = "exobox";
      version = "0.0.0";
      # What cargo reads: a change to the docs (READMEs, native/DEPS.md) or the flake doesn't
      # rebuild. In a git tree, only tracked files (not target/ or .cache/).
      src = fs.toSource {
        root = ../.;
        fileset = fs.unions [
          ../Cargo.toml
          ../Cargo.lock
          (fs.difference ../native (fs.fileFilter (f: f.hasExt "md") ../native))
          # A workspace member: cargo loads every member's manifest, built or not (the
          # package failed to build without it).
          (fs.difference ../examples (fs.fileFilter (f: f.hasExt "md") ../examples))
          ../.config
        ];
      };
      cargoLock.lockFile = ../Cargo.lock;
      cargoBuildFlags = [ "-p" "exobox" "-p" "exobox-erofs" ];
      # bindgen's libclang (as in the devshell)
      nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];
      env.EXOBOX_LKL_PREBUILT = "${kernel}";

      # The hermetic tests only, with nextest (lkl-sys's boot test needs a process per test, as
      # in ./test): lkl-sys's (the given kernel boots, answers syscalls and halts; lkl.o has no
      # relaxable relocations; the shim), and exobox's (the security filter's among them)
      # and exobox-erofs's unit tests. Not the
      # suite, the store test, erofs's image tests or exobox-rt's: they need the devshell's
      # programs (EXOBOX_TEST_*, fsck.erofs), the host's nix-store, or a kernel checkout.
      useNextest = true;
      # No spaces in an argument: the hook splits the flags on whitespace.
      cargoTestFlags = [
        "-p" "lkl-sys" "-p" "exobox" "-p" "exobox-erofs"
        "-E" "package(lkl-sys)|kind(lib)"
      ];

      passthru = { inherit kernel; };
      meta = {
        description = "Unmodified Linux programs on an in-process Linux kernel (LKL), behind a strict seccomp filter";
        license = lib.licenses.gpl2Only;
        mainProgram = "exobox";
        platforms = [ system ];
      };
    };
in
{
  inherit exoboxKernel mkExobox;
}
