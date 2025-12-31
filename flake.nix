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
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {

          pname = "snarf";
          version = "0.0.1";

          src = pkgs.lib.sourceFilesBySuffices ./. [
            "Cargo.lock"
            "Cargo.toml"
            ".rs"
            ".proto"
          ];

          # Copy over the proto files from snix. See devenv:
          # https://github.com/cachix/devenv/blob/a949ae71fdbcdbdc76c0b191e1db9d3e0d8c86eb/devenv/package.nix#L43C1-L54C6
          postConfigure = ''
            pushd "$NIX_BUILD_TOP/cargo-vendor-dir"
            mkdir -p snix/{castore,store,build}/protos

            [ -d snix-castore-*/protos ] && cp snix-castore-*/protos/*.proto snix/castore/protos/ 2>/dev/null || true
            [ -d snix-store-*/protos ] && cp snix-store-*/protos/*.proto snix/store/protos/ 2>/dev/null || true
            [ -d snix-build-*/protos ] && cp snix-build-*/protos/*.proto snix/build/protos/ 2>/dev/null || true

            popd
          '';
          preBuild = ''
            export PROTO_ROOT="$NIX_BUILD_TOP/cargo-vendor-dir"
          '';

          cargoLock = {
            lockFile = ./Cargo.lock;
            outputHashes = {
              "nar-bridge-0.1.0" = "sha256-a/WYaBl5xluFUyvOh/hPgR0bjBcL7GfS0fpFxIV49cc=";
              "wu-manber-0.1.0" = "sha256-7YIttaQLfFC/32utojh2DyOHVsZiw8ul/z0lvOhAE/4=";
            };
          };

          meta = with pkgs.lib; {
            description = "A Snix-based Nix binary cache";
            homepage = "https://github.com/pascalj/snarf";
            license = licenses.gpl3;
            maintainers = [ ];
          };

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

          dontUsePytestCheck = "do not run";
        };
      });

      nixosModules = {
        snarf = import ./module.nix self;
        default = self.nixosModules.snarf;
      };

      checks = forAllSystems (pkgs: {
        # Test whether the service successfully starts
        smoke = pkgs.testers.runNixOSTest {
          name = "snarf-dummy";
          nodes.machine =
            { ... }:
            {
              imports = [
                self.nixosModules.default
              ];
            };
          testScript = ''
            machine.wait_for_unit("snarf.service")
          '';
        };
      });

      devShells = forAllSystems (pkgs: {
        default = (crane.mkLib pkgs).craneLib.devShell { packages = [ pkgs.protobuf ]; };
      });
    };
}
