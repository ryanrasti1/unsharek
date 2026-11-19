{
  description = "seccomp-fn: a seccomp filter as a plain Rust function, compiled to classic BPF and proven equal to it by Kani";

  # exobox's pin (the repository this came from), so the two share store paths.
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5d2b81a7a3be3e2f832879028e4d60abbf58e9a0";

  outputs = { self, nixpkgs }:
    let
      # Kani's release bundle is x86_64 Linux's (nix/kani.nix).
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};
      sf = import ./nix/lib.nix { inherit pkgs; };
    in
    {
      # `kaniCheck { name, src, cargoLock, runs }`: a consumer's proofs as a derivation; `kani`;
      # `proof`, the examples' (checks.kani) (nix/lib.nix).
      lib = { inherit (sf) kaniCheck kani proof; };

      packages.${system} = {
        inherit (sf) kani;
        default = sf.kani;
      };

      checks.${system} = {
        # The examples' proofs.
        kani = sf.proof;
        # The tests: the macro's sampled ones, and run_bpf against the build machine's kernel.
        tests = pkgs.rustPlatform.buildRustPackage {
          pname = "seccomp-fn-tests";
          version = "0.0.0";
          src = sf.proof.src;
          cargoLock.lockFile = ./Cargo.lock;
          installPhase = "touch $out";
        };
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = [ pkgs.cargo pkgs.rustc pkgs.clippy pkgs.rustfmt sf.kani ];
      };
    };
}
