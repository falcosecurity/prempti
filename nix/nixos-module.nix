# NixOS module: services.prempti
#
# Installs Prempti as a *per-user* systemd unit (systemd.user.services), since
# the hook must edit ~/.claude/settings.json and the broker socket lives under
# the user's home. Every user on the host gets the unit; it only does anything
# once a Claude Code session on that account fires the hook.
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
    environment.systemPackages = [ cfg.package ];

    systemd.user.services.prempti = {
      description = "Prempti - Runtime Security for AI Coding Agents with Falco";
      after = [ "network.target" ];
      wantedBy = [ "default.target" ];
      # premptictl shells out to systemctl for restart cycles.
      path = [ pkgs.systemd pkgs.coreutils ];
      serviceConfig = {
        Type = "simple";
        ExecStartPre = "${setup}/bin/prempti-setup";
        # The supervisor spawns Falco, owns logs/rotation, and registers the
        # Claude Code hook on start / removes it on stop.
        ExecStart = "${cfg.package}/bin/premptictl daemon --prefix %h/.prempti";
        Restart = "on-failure";
        RestartSec = 5;
      };
    };
  };
}
