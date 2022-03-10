{ pkgs ? import (builtins.fetchGit {
    name = "nixpkgs-unstable-2021-06-16";
    url = https://github.com/nixos/nixpkgs/;
    rev = "0747387223edf1aa5beaedf48983471315d95e16";
}) {} }:

with pkgs;

let
    sparse = import ./nix/sparse.nix { inherit pkgs; };
in
    multiStdenv.mkDerivation {
        name = "iwlwifi";
        buildInputs = [
            flex
            bison
            openssl
            bc
            hostname
            kmod
            elfutils
            sparse
        ];
    }
