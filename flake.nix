{
  description = "unsharek: Linux (LKL) as a library, hosting unmodified programs behind a strict seccomp filter";

  # The revision is flake.lock's.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  # The kernel's source is the submodule crates/lkl-sys/linux (crates/lkl-sys/README.md: stock LKL plus unsharek's series):
  # the flake sees it only with submodules on. A kernel change is the submodule's new commit plus
  # unsharek's side of it, in one commit.
  inputs.self.submodules = true;

  # seccomp-fn (its own repository to be): the filter's compiler, Kani and the proof's check.
  inputs.seccomp-fn = { url = "path:./seccomp-fn"; inputs.nixpkgs.follows = "nixpkgs"; };

  outputs = { self, nixpkgs, seccomp-fn }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      inherit (pkgs) lib;

      # unsharekKernel and mkUnsharek: nix/lib.nix, also importable without flakes (default.nix).
      unsharek = import ./nix/lib.nix { inherit pkgs; seccompFn = seccomp-fn.lib; };
      inherit (unsharek) unsharekKernel mkUnsharek;
      # Programs the suite and the smoke check run: nix/test-programs.nix.
      tp = import ./nix/test-programs.nix { inherit pkgs; };
      # Kani, the model checker the filter's proof runs on (seccomp-fn/flake.nix).
      kani = seccomp-fn.packages.${system}.kani;
    in
    {
      lib = { inherit unsharekKernel mkUnsharek; };

      packages.${system} = rec {
        kernel = unsharekKernel { };
        default = mkUnsharek { };
        # The same store path (meta isn't part of the derivation): both binaries are built
        # together. Only `nix run .#unsharek-erofs` differs.
        unsharek-erofs = default // { meta = default.meta // { mainProgram = "unsharek-erofs"; }; };
      };

      # The release step's check: the package's unsharek runs hello, Python, bash, Go and busybox in
      # all three modes inside Nix's build sandbox (nix/smoke.nix). `nix build .#checks.x86_64-linux.smoke`.
      checks.${system} = {
        smoke = import ./nix/smoke.nix { inherit pkgs tp; unsharek = self.packages.${system}.default; };
        # The filter's proof (`cargo xtask prove`), which the package requires: nix/lib.nix's
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
          # the kernel's build (crates/lkl-sys/)
          flex
          bison
          bc
          python3
          strace
          # the test oracle for crates/unsharek-erofs (fsck.erofs checks and extracts its images; dump.erofs
          # inspects them), and guest store images for programs outside the Nix store (the test
          # fixtures)
          erofs-utils
          # bindgen's libclang for crates/lkl-sys: sets LIBCLANG_PATH, and BINDGEN_EXTRA_CLANG_ARGS
          # to the C compiler's include paths (a bare libclang finds neither glibc's headers nor
          # its own stddef.h). Its setup hook runs when the shell is entered (direnv, or
          # nix develop), so the environment has both.
          rustPlatform.bindgenHook
          # cargo xtask prove: cargo kani
          kani
        ];

        # Programs from nixpkgs the test suite runs in the sandbox (crates/tests).
        UNSHAREK_TEST_BASH = "${pkgs.bash}/bin/bash";
        UNSHAREK_TEST_COREUTILS = "${pkgs.coreutils}";
        UNSHAREK_TEST_PYTHON = "${pkgs.python3}/bin/python3";
        # a C++ program for the pipeline case (suite: pipeline_cpp)
        UNSHAREK_TEST_PATCHELF = "${pkgs.patchelf}/bin/patchelf";
        # cargo xtask perf (crates/unsharek/tests/perf.rs): parallel work and a C build
        UNSHAREK_TEST_XZ = "${pkgs.xz}/bin/xz";
        UNSHAREK_TEST_MAKE = "${pkgs.gnumake}/bin/make";
        UNSHAREK_TEST_GCC = "${pkgs.gcc}/bin/gcc";
        # Rust's tools, rustup-less (suite: cargo_version, cargo_build)
        UNSHAREK_TEST_CARGO = "${pkgs.cargo}/bin/cargo";
        UNSHAREK_TEST_RUSTC = "${pkgs.rustc}/bin/rustc";
        # Static programs, each from a different toolchain (nix/test-programs.nix): Go's runtime
        # (goprobe, built here; go-httpbin from nixpkgs), musl's (busybox), and glibc's static
        # archives, for a -static-pie fixture (crates/unsharek-fixtures' build.rs).
        UNSHAREK_TEST_GOPROBE = "${tp.goprobe}/bin/goprobe";
        UNSHAREK_TEST_HTTPBIN = "${tp.httpbin}/bin/go-httpbin";
        UNSHAREK_TEST_BUSYBOX = "${tp.busybox}/bin/busybox";
        UNSHAREK_GLIBC_STATIC = "${pkgs.glibc.static}/lib";
      };
    };
}
