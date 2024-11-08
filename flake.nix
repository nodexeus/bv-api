{
  description = "blockvisor-api";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

    flake-parts = {
      url = "github:hercules-ci/flake-parts";
      inputs.nixpkgs-lib.follows = "nixpkgs";
    };
  };

  outputs =
    inputs@{ nixpkgs, flake-parts, ... }:

    flake-parts.lib.mkFlake { inherit inputs; } {
      debug = true;
      systems = [
        "x86_64-linux"
        "aarch64-darwin"
      ];

      perSystem =
        {
          pkgs,
          system,
          ...
        }:
        {
          formatter = nixpkgs.legacyPackages.${system}.nixfmt-rfc-style;

          devShells.default =
            let
              inherit (pkgs.stdenv) isDarwin;

              packages = with pkgs; [
                openssl
                pgcli
                pgformatter
                pkg-config
                postgresql.lib
                protobuf
              ];

              darwinPackages = with pkgs; [
                darwin.apple_sdk.frameworks.SystemConfiguration
                libiconv
              ];

            in
            pkgs.mkShell {
              packages = packages ++ (if isDarwin then darwinPackages else [ ]);
            };
        };
    };
}
