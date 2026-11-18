{
  description = "exobox: Linux (LKL) as a library, hosting unmodified programs behind a strict seccomp filter";

  # capnix's revision, so the two share store paths.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5d2b81a7a3be3e2f832879028e4d60abbf58e9a0";
  # The kernel's source (lkl/README.md): stock LKL plus exobox's series, built by lkl/Makefile.
  # TODO: enable once exobox/native is pushed, for the final `nix build` (and add `linux` to the
  # outputs' arguments). Dev builds don't use it: they build from EXOBOX_LKL_SRC, a local checkout
  # (default /home/ryan/src/lkl-exobox), incrementally.
  # inputs.linux = {
  #   url = "github:ryanrasti/linux/exobox/native";
  #   flake = false;
  # };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
    in
    {
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
