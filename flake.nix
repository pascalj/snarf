{
  inputs = {
    crane.url = "github:ipetkov/crane";
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
      crane,
    }:
    let
      forAllSystems =
        function:
        nixpkgs.lib.genAttrs [
          "x86_64-linux"
          "aarch64-linux"
          "aarch64-darwin"
        ] (system: function nixpkgs.legacyPackages.${system});
    in
    {
      defaultPackage = forAllSystems (
        pkgs:
        pkgs.rustPlatform.buildRustPackage {

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
            rustfmt
            pre-commit
            rustPackages.clippy
            protobuf
          ];

          nativeBuildInputs = with pkgs; [
            protobuf
          ];
        }
      );

      devShells = forAllSystems (pkgs: {
        default = (crane.mkLib pkgs).craneLib.devShell { packages = [ pkgs.protobuf ]; };
      });
    };
}
