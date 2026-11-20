# unsharek without flakes: `import ./. { inherit pkgs; }` (pkgs: any nixpkgs; the flake pins capnix's
# revision). Gives nix/lib.nix's functions and the default builds.
{ pkgs ? import <nixpkgs> { } }:
let
  unsharek = import ./nix/lib.nix { inherit pkgs; };
in
unsharek // {
  kernel = unsharek.unsharekKernel { };
  unsharek = unsharek.mkUnsharek { };
}
