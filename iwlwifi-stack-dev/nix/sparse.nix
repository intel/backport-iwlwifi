{ pkgs }:

with pkgs;

let
  GCC_BASE = "${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.uname.processor}-unknown-linux-gnu/${stdenv.cc.cc.version}";
in multiStdenv.mkDerivation rec {
  pname = "sparse";
  version = "git-37156835";

  src = fetchGit {
    name = "sparse-37156835";
    url = "https://git.kernel.org/pub/scm/devel/sparse/sparse.git";
    rev = "37156835e3d725b6d750f000be33ba3814bb2310";
    ref = "master";
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
