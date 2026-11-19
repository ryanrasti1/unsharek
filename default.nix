# exobox without flakes: `import ./. { inherit pkgs; }` (pkgs: any nixpkgs; the flake pins capnix's
# revision). Gives nix/lib.nix's functions and the default builds.
{ pkgs ? import <nixpkgs> { } }:
let
  exobox = import ./nix/lib.nix { inherit pkgs; };
in
exobox // {
  kernel = exobox.exoboxKernel { };
  exobox = exobox.mkExobox { };
}
