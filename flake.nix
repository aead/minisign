{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/release-22.11";
    flake-utils.url = "github:numtide/flake-utils";
  };
  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs { inherit system; };
    in {
      packages = {
        default = pkgs.buildGoModule {
          pname = "minisign";
          version = if self ? shortRev && self ? revCount # available only when building a clean tree
            then "${self.lastModifiedDate}.${self.shortRev}.${builtins.toString self.revCount}"
            else self.lastModifiedDate;
          src = self;
          # this hash will need to change when go.mod is updated
          vendorHash = "sha256-CM9aw6Hyt2aaf5CwWcd4q4pVm9QSqV/HClhRkCRQtN8=";
        };
      };
    });
}
