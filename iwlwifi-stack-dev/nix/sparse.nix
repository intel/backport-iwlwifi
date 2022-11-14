{ pkgs }:

with pkgs;

let
  GCC_BASE = "${stdenv.cc.cc}/lib/gcc/${stdenv.hostPlatform.uname.processor}-unknown-linux-gnu/${stdenv.cc.cc.version}";
in multiStdenv.mkDerivation rec {
  pname = "sparse";
  version = "git+ce1a6720";

  src = fetchGit {
    name = "sparse-ce1a6720";
    url = "https://git.kernel.org/pub/scm/devel/sparse/sparse.git";
    rev = "ce1a6720f69e6233ec9abd4e9aae5945e05fda41";
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
