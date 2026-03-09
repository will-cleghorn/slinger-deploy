{
  description = "Kube-Iroh (kiro) P2P Deployment Engine";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, rust-overlay, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs { inherit system overlays; };
        
        # Optimized Rust Toolchain
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" ];
          targets = [ "x86_64-unknown-linux-musl" "aarch64-unknown-linux-musl" ];
        };

        # The kiro Binary Build
        kiro-bin = pkgs.rustPlatform.buildRustPackage {
          pname = "kiro";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          nativeBuildInputs = [ pkgs.pkg-config rustToolchain ];
          buildInputs = [ pkgs.openssl ];

          # Static linking for Distroless compatibility
          target = "${system}-unknown-linux-musl";
          doCheck = false;
        };

      in {
        # 1. Development Shell
        devShells.default = pkgs.mkShell {
          buildInputs = [
            rustToolchain
            pkgs.cargo-edit
            pkgs.cargo-watch
            pkgs.pkg-config
            pkgs.openssl
          ];
          shellHook = ''
            echo "🚀 Kube-Iroh Development Environment Active"
          '';
        };

        # 2. The Package
        packages.default = kiro-bin;

        # 3. Minimal Container Image (The "Consumer" sidecar)
        packages.container = pkgs.dockerTools.buildImage {
          name = "kiro-consumer";
          tag = "latest";
          config = {
            Cmd = [ "${kiro-bin}/bin/kiro" "consume" ];
            # Essential for Iroh's DERP (HTTPS) fallback
            Env = [ "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt" ];
          };
        };
      }
    );
}
