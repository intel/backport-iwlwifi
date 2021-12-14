{ pkgs }:

with pkgs;

let
  GCC_BASE = "${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.uname.processor}-unknown-linux-gnu/${stdenv.cc.cc.version}";
in multiStdenv.mkDerivation rec {
  pname = "sparse";
  version = "0.6.4";

  src = fetchurl {
    url = "mirror://kernel/software/devel/sparse/dist/${pname}-${version}.tar.xz";
    sha256 = "0z1qds52144nvsdnl82r3zs3vax618v920jmffyyssmwj54qpcka";
  };

  enableParallelBuilding = true;

  nativeBuildInputs = [ pkg-config ];
  buildInputs = [ perl ];

  makeFlags = [ "PREFIX=$(out)" ];

  preConfigure = ''
    sed -i 's|"/usr/include"|"${stdenv.cc.libc.dev}/include"|' pre-process.c
    sed -i 's|qx(\$ccom -print-file-name=)|"${GCC_BASE}"|' cgcc
  '';

  buildFlags = "GCC_BASE:=${GCC_BASE}";

  patches = [
    ./sparse.patch
  ];
}
