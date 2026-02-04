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

  git-hooks.hooks.rustfmt.enable = true;

  enterShell = ''
    ln -sf $RUST_SRC_PATH $DEVENV_STATE/rust-stdlib
  '';
}

