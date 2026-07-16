{ pkgs ? import (builtins.fetchGit {
    name = "nixpkgs-release-25.05";
    url = https://github.com/nixos/nixpkgs/;
    ref = "refs/tags/25.05";
    rev = "afb2b21ba489196da32cd9f0072e0dce6588a20a";
}) {} }:

with pkgs;

let
    sparse = import ./nix/sparse.nix { inherit pkgs; };

    coccinelle = pkgs.coccinelle.overrideAttrs {
        version = "1.3.1";

        src = fetchFromGitHub {
            repo = "coccinelle";
            rev = "1.3.1";
            owner = "coccinelle";
            hash = "sha256-ZNWuloXhAXWNNoVWLOuDbC3e6KNL7nzM2346tB04qXA=";
        };
    };

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
            unifdef # for prune
            git
            python3
            python3Packages.jira
            codespell
            coccinelle
            yq # for android scripting
        ];

        shellHook = ''
          export PATH=${ccacheWrapper}/bin:$PATH
          export LC_ALL=C
          export LANG=C
        '';
    }
