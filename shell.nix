let
  # release 22.11, 2023-05-19
  pkgs = import (fetchTarball("https://github.com/NixOS/nixpkgs/archive/03f2eb03bf67cda480680f82782889afa8d85b18.tar.gz")) {};
  openapi-generator-cli-6_4 = pkgs.openapi-generator-cli.overrideAttrs (finalAttrs: previousAttrs: {
    version = "6.4.0";
    src = pkgs.fetchurl {
      url = "mirror://maven/org/openapitools/${previousAttrs.pname}/${finalAttrs.version}/${previousAttrs.pname}-${finalAttrs.version}.jar";
      sha256 = "sha256-Na6tMA4MlGn72dMM9G9BU4l9yygpEgkcpOySEtzp0VE=";
    };
  });
in pkgs.mkShell {
  buildInputs = with pkgs; [
    openapi-generator-cli-6_4
    openssl
    pkg-config
    rust_1_66.packages.stable.cargo
    rust_1_66.packages.stable.rustc
    rust_1_66.packages.stable.rustfmt
    vscode
  ];
  RUST_SRC_PATH = "${pkgs.rust.packages.stable.rustPlatform.rustLibSrc}";
}
