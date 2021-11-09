{
  description = "EKS Experiment";

  inputs.utils.url = "github:numtide/flake-utils";

  outputs = { self, utils, nixpkgs }:
    utils.lib.eachDefaultSystem (system:
      let pkgs = nixpkgs.legacyPackages.${system}; in
      {
        packages.container = pkgs.dockerTools.buildLayeredImage {
          name = self.defaultPackage.${system}.pname;
          contents = [
            self.defaultPackage.${system}
          ];
        };

        packages.streamContainer = pkgs.dockerTools.streamLayeredImage {
          name = self.defaultPackage.${system}.pname;
          contents = [
            self.defaultPackage.${system}
          ];
        };


        defaultPackage = pkgs.buildGoModule {
          pname = "webauthn-minimal";
          version = "0.0.1";
          src =  pkgs.lib.cleanSource ./.;
        };

        devShell = with pkgs; mkShell {
          nativeBuildInputs = [
            bashInteractive
            go
          ];
        };
      });
}

