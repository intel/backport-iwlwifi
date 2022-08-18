{ pkgs ? import (builtins.fetchGit {
    name = "nixpkgs-unstable-2021-06-16";
    url = https://github.com/nixos/nixpkgs/;
    rev = "0747387223edf1aa5beaedf48983471315d95e16";
}) {} }:

with pkgs;

let
    sparse = import ./nix/sparse.nix { inherit pkgs; };

    ccacheWrapper = pkgs.ccacheWrapper.override ({
        cc = pkgs.multiStdenv.cc;
    });
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
            ccache
            perl
            which
        ];

        shellHook = ''
          export PATH=${ccacheWrapper}/bin:$PATH
          export LC_ALL=C
          export LANG=C
        '';
    }
