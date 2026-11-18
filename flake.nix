{
  description = "exobox: Linux (LKL) as a library, hosting unmodified programs behind a strict seccomp filter";

  # capnix's revision, so the two share store paths.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5d2b81a7a3be3e2f832879028e4d60abbf58e9a0";

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
          # guest store images for programs outside the Nix store (the test fixtures)
          erofs-utils
        ];

        # Programs from nixpkgs the test suite runs in the sandbox (native/tests).
        EXOBOX_TEST_BASH = "${pkgs.bash}/bin/bash";
        EXOBOX_TEST_COREUTILS = "${pkgs.coreutils}";
        EXOBOX_TEST_PYTHON = "${pkgs.python3}/bin/python3";
        # Marks this shell, so ./test runs inside it directly.
        EXOBOX_DEVSHELL = "1";
      };
    };
}
