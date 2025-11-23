{
  inputs = {
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    nix-src.url = "github:nixos/nix?ref=master";
  };

  outputs =
    {
      self,
      nixpkgs,
      nix-src,
      utils,
      crane,
    }:
    utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs { inherit system; };
        craneLib = crane.mkLib pkgs;
        nix = nix-src.packages.${system}.nix;
      in
      {
        defaultPackage = pkgs.rustPlatform.buildRustPackage {

          pname = "snarf";
          version = "0.0.1";

          src = pkgs.lib.cleanSource ./.;

          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "nar-bridge-0.1.0" = "sha256-a/WYaBl5xluFUyvOh/hPgR0bjBcL7GfS0fpFxIV49cc=";
              "wu-manber-0.1.0" = "sha256-7YIttaQLfFC/32utojh2DyOHVsZiw8ul/z0lvOhAE/4=";
            };
          };

          meta = with pkgs.lib; {
            description = "A fast line-oriented regex search tool, similar to ag and ack";
            homepage = "https://github.com/BurntSushi/ripgrep";
            license = licenses.unlicense;
            maintainers = [ ];
          };

          # RUST_SRC_PATH = pkgs.rustPlatform.rustLibSrc;
          # pkgs.rustPlatform.rustLibSrc
          buildInputs = with pkgs; [
            cargo
            runc
            rustc
            nix.dev
            rustfmt
            pre-commit
            rustPackages.clippy
            protobuf
          ];

          nativeBuildInputs = with pkgs; [
            protobuf
          ];
        };

        devShells.default = craneLib.devShell {
          LIBCLANG_PATH = "${pkgs.llvmPackages_21.libclang.lib}/lib";
          packages = [
            nix.dev
            pkgs.protobuf
            pkgs.pkg-config
          ];
        };
      }
    );
}
