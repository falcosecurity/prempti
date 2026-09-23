{
  description = "Prempti - Falco-based policy and visibility layer for AI coding agents";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: rec {
        prempti = pkgs.callPackage ./nix/prempti.nix { };
        falco-bin = pkgs.callPackage ./nix/falco-bin.nix { };
        default = prempti;
      });

      nixosModules = rec {
        prempti = import ./nix/nixos-module.nix self;
        default = prempti;
      };

      homeManagerModules = rec {
        prempti = import ./nix/home-manager-module.nix self;
        default = prempti;
      };

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          inputsFrom = [ self.packages.${pkgs.stdenv.hostPlatform.system}.prempti ];
          packages = with pkgs; [ cargo rustc rustfmt clippy rust-analyzer ];
          # The e2e harness (tests/src/e2e.rs::find_falco) honours $FALCO before
          # looking under build/; point it at the store copy so
          # `cargo test -p prempti-tests --release` runs the Falco-driven tests.
          FALCO = "${self.packages.${pkgs.stdenv.hostPlatform.system}.falco-bin}/bin/falco";
        };
      });

      # Evaluate the NixOS module against a minimal config so `nix flake check`
      # catches option/type errors without building a full system.
      checks = forAllSystems (pkgs:
        let
          eval = nixpkgs.lib.nixosSystem {
            system = pkgs.stdenv.hostPlatform.system;
            modules = [
              self.nixosModules.prempti
              {
                boot.loader.grub.enable = false;
                fileSystems."/" = { device = "nodev"; fsType = "tmpfs"; };
                system.stateVersion = "25.05";
                services.prempti = {
                  enable = true;
                  mode = "monitor";
                pluginSettings.deny_tags = [ "coding_agent_deny" "team_deny" ];
                settings.log_level = "info";
                  rules.example = ''
                    - rule: Deny git push
                      desc: test
                      condition: tool.name = "Bash" and tool.input_command startswith "git push"
                      output: Falco blocked git push (%tool.input_command)
                      priority: CRITICAL
                      source: coding_agent
                      tags: [coding_agent_deny]
                  '';
                };
              }
            ];
          };
        in
        {
          nixos-module = eval.config.systemd.user.units."prempti.service".unit;
          prempti = self.packages.${pkgs.stdenv.hostPlatform.system}.prempti;
        });
    };
}
