let
  # release 23.05, 2023-08-13
  pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/90497216e09e9fe341fc3f2544398000cad33d20.tar.gz")) {};
in pkgs.mkShell {
  buildInputs = with pkgs; [
    openssl
    pkg-config
    rust.packages.stable.cargo
    rust.packages.stable.rustc
    rust.packages.stable.rustfmt
    vscode
  ];
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
