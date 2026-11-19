# seccomp-fn's Nix library, without flakes: `import ./nix/lib.nix { inherit pkgs; }` gives
# `kani` (nix/kani.nix), `kaniCheck` and `proof` (the examples' proofs). flake.nix imports this.
{ pkgs }:
let
  kani = import ./kani.nix { inherit pkgs; };

  # A derivation that runs `cargo kani` on a crate's `#[seccomp]` harnesses (each function equal
  # to its program, for every input and every param) and fails if any proof fails. `src` is a
  # Cargo workspace, `cargoLock` its lock file (its dependencies are vendored from it: no
  # network); each of `runs` is one `cargo kani` invocation's arguments, from `src`'s root.
  # Its output holds each run's log and a summary of the harnesses checked.
  kaniCheck = { name, src, cargoLock, runs }:
    pkgs.stdenv.mkDerivation {
      inherit name src;
      cargoDeps = pkgs.rustPlatform.importCargoLock { lockFile = cargoLock; };
      nativeBuildInputs = [ pkgs.rustPlatform.cargoSetupHook kani ];
      dontConfigure = true;
      # Kani's driver and its cargo want a writable HOME.
      buildPhase = ''
        runHook preBuild
        export HOME=$TMPDIR
        set -o pipefail
        i=0
        ${pkgs.lib.concatMapStrings (args: ''
          i=$((i + 1))
          echo "cargo kani ${pkgs.lib.escapeShellArgs args}" | tee kani-$i.log
          cargo kani ${pkgs.lib.escapeShellArgs args} 2>&1 | tee -a kani-$i.log
        '') runs}
        runHook postBuild
      '';
      installPhase = ''
        mkdir -p $out
        cp kani-*.log $out/
        grep -h -e '^cargo kani' -e '^Checking harness' -e '^VERIFICATION' -e '^Verification Time' \
          -e '^Complete' kani-*.log > $out/summary
      '';
    };
in
{
  inherit kani kaniCheck;
  # seccomp-fn's own examples, proven.
  proof = kaniCheck {
    name = "seccomp-fn-proof";
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions [ ../Cargo.toml ../Cargo.lock ../seccomp-fn ../seccomp-fn-macros ];
    };
    cargoLock = ../Cargo.lock;
    runs = [ [ "-p" "seccomp-fn" ] ];
  };
}
