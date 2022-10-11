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
          vendorSha256 = null;
        };
      });
}

