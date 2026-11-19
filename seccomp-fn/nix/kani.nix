# Kani, the Rust model checker (github.com/model-checking/kani), for `./test --prove` and the
# `kani` check: not in nixpkgs. Its prebuilt release bundle (kani-compiler, kani-driver, CBMC,
# kissat, Kani's std) plus the nightly toolchain it was built against, which `cargo kani setup`
# would fetch with rustup: here the same components from static.rust-lang.org, pinned by hash,
# laid out where kani-compiler's RUNPATH looks ($ORIGIN/../toolchain). autoPatchelfHook fixes
# the interpreters and library paths for Nix.
{ pkgs }:
let
  version = "0.68.0";
  # The bundle's rust-toolchain-version: nightly-2026-08-21.
  date = "2026-08-21";
  bundle = pkgs.fetchurl {
    url = "https://github.com/model-checking/kani/releases/download/kani-${version}/kani-${version}-x86_64-unknown-linux-gnu.tar.gz";
    sha256 = "1ls3g2pfk3a4gpk4xv4agm4j5515qiwhikx2cjzhppiysy2b9qij";
  };
  component = name: sha256: pkgs.fetchurl {
    url = "https://static.rust-lang.org/dist/${date}/${name}-nightly${if name == "rust-src" then "" else "-x86_64-unknown-linux-gnu"}.tar.xz";
    inherit sha256;
  };
  components = [
    (component "rustc" "1d4lap2393wyzswc0ncksh956mcndimjh3ay91d2ndjilmgq2cg5")
    (component "cargo" "0mwwadyajyfv31n0n8xd6ill1inbl2v17cvzf83shzmdf36nsc2i")
    (component "rust-std" "18x35ssy6z2gw3w3vx8kjsml9kdiv8ghcghp0hypr5kg1ibi5kaj")
    (component "rustc-dev" "1nqvyxka8r1qm43fxr72r0b57qfbnpp6i9bfgm0c9hvx8jviynhp")
    (component "rust-src" "1kgq89wzd4mdi9wfd32bhxz58l8hjibvzp50kbphdgsh7ib4jbdp")
  ];
in
pkgs.stdenv.mkDerivation {
  pname = "kani";
  inherit version;
  src = bundle;
  nativeBuildInputs = [ pkgs.autoPatchelfHook pkgs.makeWrapper ];
  buildInputs = [ pkgs.stdenv.cc.cc.lib pkgs.zlib ];
  dontConfigure = true;
  dontBuild = true;
  dontStrip = true;
  installPhase = ''
    runHook preInstall
    mkdir -p $out
    cp -r . $out/
    # Each dist tarball holds component directories (its `components` file) whose trees merge
    # into one toolchain, as rustup's install.sh would lay them out.
    mkdir -p $out/toolchain
    for t in ${toString components}; do
      d=$(mktemp -d)
      tar xJf $t -C $d
      top=$(echo $d/*)
      for c in $(cat $top/components); do cp -r $top/$c/. $out/toolchain/; done
      rm -rf $d
    done
    rm -f $out/toolchain/manifest-*
    # kani-driver is cargo-kani or kani by its name; the toolchain's cargo and rustc come first,
    # and gcc (goto-cc preprocesses Kani's C stubs with it).
    for n in cargo-kani kani; do
      makeWrapper $out/bin/kani-driver $out/bin/$n --argv0 $n \
        --prefix PATH : $out/toolchain/bin:$out/bin:${pkgs.gcc}/bin
    done
    runHook postInstall
  '';
  meta.description = "Kani ${version}, its bundle and toolchain";
}
