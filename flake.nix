{
  description = "Webauthn minimal";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, utils, nixpkgs }:
    utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        packages.default = pkgs.buildGoModule {
          pname = "webauthn-minimal";
          version = "0.0.1";
          src = ./.;
          vendorSha256 = "sha256-TDKN+Dce7kpFjzxrGv8m6H7HDoTSnHz83CfSvZhNwT0=";
        };
      });
}

