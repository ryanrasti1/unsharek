{
  description = "exobox: Linux (LKL) as a library, hosting unmodified programs behind a strict seccomp filter";

  # capnix's revision, so the two share store paths.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5d2b81a7a3be3e2f832879028e4d60abbf58e9a0";
  # The kernel's source is the submodule lkl/linux (lkl/README.md: stock LKL plus exobox's series):
  # the flake sees it only with submodules on. A kernel change is the submodule's new commit plus
  # exobox's side of it, in one commit.
  inputs.self.submodules = true;

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;
      fs = lib.fileset;

      # The kernel, built once by lkl/Makefile as its own derivation, in the layout lkl-sys's
      # build.rs takes as EXOBOX_LKL_PREBUILT (lkl/Makefile's `install`): liblkl-kernel.a, lkl.o,
      # liblkl-posix.a (lkl-sys's boot test, run in mkExobox's checkPhase), include/, and the
      # expanded .config. `config` is a fragment of kernel config lines over lkl/defconfig (later
      # lines win: "CONFIG_SYSVIPC=y\n", or "# CONFIG_X is not set\n").
      exoboxKernel = { src ? ./lkl/linux, config ? "" }:
        pkgs.stdenv.mkDerivation {
          pname = "exobox-kernel";
          version = src.shortRev or "0";
          inherit src;
          # Only the Makefile and the defconfig: an edit elsewhere in the repository doesn't rebuild
          # the kernel.
          lkl = fs.toSource {
            root = ./lkl;
            fileset = fs.unions [ ./lkl/Makefile ./lkl/defconfig ];
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
      mkExobox = { kernel ? self.packages.${system}.kernel }:
        pkgs.rustPlatform.buildRustPackage {
          pname = "exobox";
          version = "0.0.0";
          # What cargo reads: a change to the docs (READMEs, native/DEPS.md) or the flake doesn't
          # rebuild. In a git tree, only tracked files (not target/ or .cache/).
          src = fs.toSource {
            root = ./.;
            fileset = fs.unions [
              ./Cargo.toml
              ./Cargo.lock
              (fs.difference ./native (fs.fileFilter (f: f.hasExt "md") ./native))
              ./.config
            ];
          };
          cargoLock.lockFile = ./Cargo.lock;
          cargoBuildFlags = [ "-p" "exobox" "-p" "exobox-erofs" ];
          # bindgen's libclang (as in the devshell)
          nativeBuildInputs = [ pkgs.rustPlatform.bindgenHook ];
          env.EXOBOX_LKL_PREBUILT = "${kernel}";

          # The hermetic tests only, with nextest (lkl-sys's boot test needs a process per test, as
          # in ./test): lkl-sys's (the given kernel boots, answers syscalls and halts; lkl.o has no
          # relaxable relocations; the shim), and exobox's and exobox-erofs's unit tests. Not the
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
      lib = { inherit exoboxKernel mkExobox; };

      packages.${system} = rec {
        kernel = exoboxKernel { };
        default = mkExobox { };
        # The same store path (meta isn't part of the derivation): both binaries are built
        # together. Only `nix run .#exobox-erofs` differs.
        exobox-erofs = default // { meta = default.meta // { mainProgram = "exobox-erofs"; }; };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          cargo
          rustc
          clippy
          rustfmt
          cargo-nextest
          gcc
          gnumake
          # the kernel's build (lkl/)
          flex
          bison
          bc
          python3
          strace
          # the test oracle for native/erofs (fsck.erofs checks and extracts its images; dump.erofs
          # inspects them), and guest store images for programs outside the Nix store (the test
          # fixtures)
          erofs-utils
          # bindgen's libclang for native/lkl-sys: sets LIBCLANG_PATH, and BINDGEN_EXTRA_CLANG_ARGS
          # to the C compiler's include paths (a bare libclang finds neither glibc's headers nor
          # its own stddef.h). Its setup hook runs when the shell is entered, so devshell.sh's
          # cached environment has both.
          rustPlatform.bindgenHook
        ];

        # Programs from nixpkgs the test suite runs in the sandbox (native/tests).
        EXOBOX_TEST_BASH = "${pkgs.bash}/bin/bash";
        EXOBOX_TEST_COREUTILS = "${pkgs.coreutils}";
        EXOBOX_TEST_PYTHON = "${pkgs.python3}/bin/python3";
        # a C++ program for the pipeline case (suite: pipeline_cpp)
        EXOBOX_TEST_PATCHELF = "${pkgs.patchelf}/bin/patchelf";
        # ./test --perf (native/exobox/tests/perf.rs): parallel work and a C build
        EXOBOX_TEST_XZ = "${pkgs.xz}/bin/xz";
        EXOBOX_TEST_MAKE = "${pkgs.gnumake}/bin/make";
        EXOBOX_TEST_GCC = "${pkgs.gcc}/bin/gcc";
        # Marks this shell, so ./test runs inside it directly.
        EXOBOX_DEVSHELL = "1";
      };
    };
}
