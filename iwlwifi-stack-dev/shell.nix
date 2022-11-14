{ pkgs ? import (builtins.fetchGit {
    name = "nixpkgs-unstable-2022-05-17";
    url = https://github.com/nixos/nixpkgs/;
    rev = "acc4a0bbb9485e155e0a20786f9f48d7eda0ba40";
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
            rsync
        ];

        shellHook = ''
          export PATH=${ccacheWrapper}/bin:$PATH
          export LC_ALL=C
          export LANG=C
        '';
    }
