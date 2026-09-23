# home-manager module: services.prempti
#
# Same options as the NixOS module, but the unit is installed only for this
# user via home-manager's systemd.user.services.
self:
{ config, lib, pkgs, ... }:
let
  cfg = config.services.prempti;
  common = import ./common.nix { inherit lib pkgs self; };
  setup = common.mkSetupScript cfg;
in
{
  options.services.prempti = common.options;

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = pkgs.stdenv.isLinux;
        message = "services.prempti (home-manager) only supports Linux; use the upstream .pkg on macOS.";
      }
    ];

    home.packages = [ cfg.package ];

    systemd.user.services.prempti = {
      Unit = {
        Description = "Prempti - Runtime Security for AI Coding Agents with Falco";
        After = [ "network.target" ];
      };
      Service = {
        Type = "simple";
        ExecStartPre = "${setup}/bin/prempti-setup";
        ExecStart = "${cfg.package}/bin/premptictl daemon --prefix %h/.prempti";
        Restart = "on-failure";
        RestartSec = 5;
        Environment = [ "PATH=${lib.makeBinPath [ pkgs.systemd pkgs.coreutils ]}" ];
      };
      Install.WantedBy = [ "default.target" ];
    };
  };
}
