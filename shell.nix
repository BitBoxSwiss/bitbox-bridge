with import <nixpkgs> {};

stdenv.mkDerivation {
  name = "bitbox-bridge-env";

  nativeBuildInputs = [
    rustc 
    cargo
    pkg-config
    openssl
    cacert
  ];

  buildInputs = [
    libudev-zero
  ];

  # Set Environment Variables
  RUST_BACKTRACE = 1;
}
