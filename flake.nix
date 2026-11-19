{
  description = "exobox: Linux (LKL) as a library, hosting unmodified programs behind a strict seccomp filter";

  # capnix's revision, so the two share store paths.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5d2b81a7a3be3e2f832879028e4d60abbf58e9a0";
  # The kernel's source is the submodule lkl/linux (lkl/README.md: stock LKL plus exobox's series):
  # the flake sees it only with submodules on. A kernel change is the submodule's new commit plus
  # exobox's side of it, in one commit.
  inputs.self.submodules = true;

  # seccomp-fn (its own repository to be): the filter's compiler, Kani and the proof's check.
  inputs.seccomp-fn = { url = "path:./seccomp-fn"; inputs.nixpkgs.follows = "nixpkgs"; };

  outputs = { self, nixpkgs, seccomp-fn }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;

      # exoboxKernel and mkExobox: nix/lib.nix, also importable without flakes (default.nix).
      exobox = import ./nix/lib.nix { inherit pkgs; seccompFn = seccomp-fn.lib; };
      inherit (exobox) exoboxKernel mkExobox;
      # Programs the suite and the smoke check run: nix/test-programs.nix.
      tp = import ./nix/test-programs.nix { inherit pkgs; };
      # Kani, the model checker the filter's proof runs on (seccomp-fn/nix/kani.nix).
      kani = seccomp-fn.packages.${system}.kani;
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

      # The release step's check: the package's exobox runs hello, Python, bash, Go and busybox in
      # all three modes inside Nix's build sandbox (nix/smoke.nix). `nix build .#checks.x86_64-linux.smoke`.
      checks.${system} = {
        smoke = import ./nix/smoke.nix { inherit pkgs tp; exobox = self.packages.${system}.default; };
        # The filter's proof (`./test --prove`), which the package requires: nix/lib.nix's
        # `kaniCheck`.
        kani = self.packages.${system}.default.kani;
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
          # ./test --prove: cargo kani
          kani
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
        # Rust's tools, rustup-less (suite: cargo_version, cargo_build)
        EXOBOX_TEST_CARGO = "${pkgs.cargo}/bin/cargo";
        EXOBOX_TEST_RUSTC = "${pkgs.rustc}/bin/rustc";
        # Static programs, each from a different toolchain (nix/test-programs.nix): Go's runtime
        # (goprobe, built here; go-httpbin from nixpkgs), musl's (busybox), and glibc's static
        # archives, for a -static-pie fixture (native/fixtures' build.rs).
        EXOBOX_TEST_GOPROBE = "${tp.goprobe}/bin/goprobe";
        EXOBOX_TEST_HTTPBIN = "${tp.httpbin}/bin/go-httpbin";
        EXOBOX_TEST_BUSYBOX = "${tp.busybox}/bin/busybox";
        EXOBOX_GLIBC_STATIC = "${pkgs.glibc.static}/lib";
        # Marks this shell, so ./test runs inside it directly.
        EXOBOX_DEVSHELL = "1";
      };
    };
}
