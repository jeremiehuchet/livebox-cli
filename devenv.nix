{ pkgs, ... }:

{
  packages = [
    pkgs.openssl
    pkgs.pkg-config
  ];

  languages.rust = {
    enable = true;
    channel = "stable";
    components = [ "rustc" "cargo" "clippy" "rustfmt" "rust-analyzer" ];
  };

  pre-commit.hooks.rustfmt.enable = true;

  enterShell = ''
    ln -sf $RUST_SRC_PATH $DEVENV_STATE/rust-stdlib
  '';
}

