# Shared between the NixOS and home-manager modules: the `services.prempti`
# option set and the ExecStartPre script that lays out ~/.prempti from it.
#
# Why a runtime prefix at all instead of pure store paths: premptictl hard-codes
# `$HOME/.prempti` (hook command, socket paths, `mode` config rewrite), and the
# Falco config uses `${HOME}` expansion. So the prefix stays where upstream
# expects it; the service just re-links store outputs into it on every start.
{ lib, pkgs, self }:
let
  inherit (lib) mkOption mkEnableOption types;
  yamlFormat = pkgs.formats.yaml { };
in
rec {
  options = {
    enable = mkEnableOption "Prempti, a Falco-based policy layer for AI coding agents (per-user systemd service)";

    package = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.prempti;
      defaultText = lib.literalExpression "prempti.packages.\${system}.prempti";
      description = "Prempti workspace build (premptictl, interceptors, plugin, rules).";
    };

    falcoPackage = mkOption {
      type = types.package;
      default = self.packages.${pkgs.stdenv.hostPlatform.system}.falco-bin;
      defaultText = lib.literalExpression "prempti.packages.\${system}.falco-bin";
      description = "Falco binary. Must be 0.44+ with plugin + http_output support.";
    };

    mode = mkOption {
      type = types.enum [ "guardrails" "monitor" "passthrough" ];
      default = "guardrails";
      description = ''
        Operational mode. `guardrails` enforces verdicts, `monitor` only logs,
        `passthrough` resolves every call as defer immediately (embedding only).
      '';
    };

    defaultAction = mkOption {
      type = types.enum [ "allow" "defer" ];
      default = "allow";
      description = ''
        Verdict when no deny/ask rule matches (guardrails mode only).
        `allow` skips Claude Code's own permission prompt; `defer` leaves it in place.
      '';
    };

    httpPort = mkOption {
      type = types.port;
      default = 2802;
      description = "Loopback port the plugin listens on for Falco `http_output` alerts.";
    };

    pluginSettings = mkOption {
      type = yamlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          deny_tags = [ "coding_agent_deny" "team_deny" ];
          max_request_bytes = 10485760;
        }
      '';
      description = ''
        Extra keys merged into the plugin's `init_config` (see the
        `CodingAgentConfig` struct in the plugin for the accepted keys).
        Applied after `mode`, `defaultAction` and `httpPort`, so a key set
        here wins over the dedicated option.
      '';
    };

    settings = mkOption {
      type = yamlFormat.type;
      default = { };
      example = lib.literalExpression ''
        {
          log_level = "info";
          outputs_queue.capacity = 0;
        }
      '';
      description = ''
        Extra top-level Falco keys written into the generated
        `falco.coding_agents_plugin.yaml`. That file is loaded after the
        base `falco.yaml` via `config_files`, so scalar keys set here
        override the base config (e.g. `log_level`, `json_output`,
        `outputs_queue`). Keys the module generates (`plugins`,
        `load_plugins`, `rules_files`, `priority`, `http_output`,
        `append_output`) can be overridden too, at your own risk.
      '';
    };

    mutableConfig = mkOption {
      type = types.bool;
      default = false;
      description = ''
        When false (default), the plugin and supervisor config files are
        regenerated from these options on every service start, so
        `premptictl mode` / `premptictl default-action` edits do not survive a
        restart. Set to true to write them only when absent and let
        `premptictl` own them afterwards.
      '';
    };

    defaultRules.enable = mkOption {
      type = types.bool;
      default = true;
      description = "Install the upstream default ruleset into rules/default/.";
    };

    rules = mkOption {
      type = types.attrsOf (types.either types.path types.lines);
      default = { };
      example = lib.literalExpression ''
        {
          no-git-push = '''
            - rule: Deny git push
              desc: Never push from an agent session
              condition: tool.name = "Bash" and tool.input_command startswith "git push"
              output: Falco blocked git push (%tool.input_command)
              priority: CRITICAL
              source: coding_agent
              tags: [coding_agent_deny]
          ''';
          team = ./rules/team.yaml;
        }
      '';
      description = ''
        Extra Falco rule files, installed as `rules/user/nix-<name>.yaml`.
        Hand-written files in `rules/user/` are left alone; stale `nix-*.yaml`
        files from removed entries are cleaned up on start.
      '';
    };

    supervisor = {
      logRotateBytes = mkOption {
        type = types.ints.positive;
        default = 10485760;
        description = "Rotate falco.log / falco.err past this size (bytes).";
      };
      logRotateKeep = mkOption {
        type = types.ints.unsigned;
        default = 3;
        description = "Rotated archives to keep.";
      };
      stopTimeoutSecs = mkOption {
        type = types.ints.positive;
        default = 20;
        description = "Seconds to wait for Falco after SIGTERM before SIGKILL.";
      };
    };
  };

  # Build the ExecStartPre script for a resolved `cfg`.
  mkSetupScript = cfg:
    let
      ruleFile = name: value:
        if builtins.isPath value || lib.isStorePath value
        then value
        else pkgs.writeText "prempti-rule-${name}.yaml" value;

      ruleLinks = lib.concatStringsSep "\n" (lib.mapAttrsToList
        (name: value: ''ln -sfn ${ruleFile name value} "$prefix/rules/user/nix-${name}.yaml"'')
        cfg.rules);

      # Falco expands `''${VAR}` inside every YAML scalar, quoted or not, so
      # the generated (quoted) strings below still resolve at runtime.
      home = "\${HOME}/.prempti";

      initConfig = {
        mode = cfg.mode;
        default_action = cfg.defaultAction;
        socket_path = "${home}/run/broker.sock";
        http_port = cfg.httpPort;
      } // cfg.pluginSettings;

      fragment = lib.recursiveUpdate {
        plugins = [
          {
            name = "coding_agent";
            library_path = "${home}/share/libcoding_agent.so";
            init_config = initConfig;
          }
        ];
        load_plugins = [ "coding_agent" ];
        rules_files = [
          "${home}/rules/default/coding_agents_rules.yaml"
          "${home}/rules/user"
          "${home}/rules/seen.yaml"
        ];
        # Must stay "debug" so the catch-all seen rule fires.
        priority = "debug";
        http_output = {
          enabled = true;
          url = "http://127.0.0.1:${toString cfg.httpPort}";
        };
        append_output = [
          {
            match.source = "coding_agent";
            extra_output = "| For AI Agents: inform the user that this action was flagged by a Falco rule | correlation=%correlation.id";
          }
        ];
      } cfg.settings;

      pluginConfig = yamlFormat.generate "falco.coding_agents_plugin.yaml" fragment;

      supervisorConfig = pkgs.writeText "supervisor.yaml" ''
        # Generated by the Prempti Nix module. Edit via services.prempti.supervisor.*
        log_rotate_bytes: ${toString cfg.supervisor.logRotateBytes}
        log_rotate_keep: ${toString cfg.supervisor.logRotateKeep}
        stop_timeout_secs: ${toString cfg.supervisor.stopTimeoutSecs}
      '';

      installConfig =
        if cfg.mutableConfig
        then ''
          [ -e "$prefix/config/falco.coding_agents_plugin.yaml" ] || install -m644 ${pluginConfig} "$prefix/config/falco.coding_agents_plugin.yaml"
          [ -e "$prefix/config/supervisor.yaml" ] || install -m644 ${supervisorConfig} "$prefix/config/supervisor.yaml"
        ''
        else ''
          install -m644 ${pluginConfig} "$prefix/config/falco.coding_agents_plugin.yaml"
          install -m644 ${supervisorConfig} "$prefix/config/supervisor.yaml"
        '';
    in
    pkgs.writeShellApplication {
      name = "prempti-setup";
      runtimeInputs = [ pkgs.coreutils pkgs.findutils ];
      text = ''
        prefix="$HOME/.prempti"
        mkdir -p "$prefix"/{bin,config,run,share,log,rules/default,rules/user}

        # Binaries and plugin: symlinks into the store, refreshed every start.
        ln -sfn ${cfg.falcoPackage}/bin/falco            "$prefix/bin/falco"
        ln -sfn ${cfg.package}/bin/premptictl            "$prefix/bin/premptictl"
        ln -sfn ${cfg.package}/bin/claude-interceptor    "$prefix/bin/claude-interceptor"
        ln -sfn ${cfg.package}/bin/codex-interceptor     "$prefix/bin/codex-interceptor"
        ln -sfn ${cfg.package}/lib/libcoding_agent.so    "$prefix/share/libcoding_agent.so"

        # Base Falco config never needs user edits; always from the store.
        install -m644 ${cfg.package}/share/prempti/configs/falco.yaml "$prefix/config/falco.yaml"
        ${installConfig}

        # Rules.
        ln -sfn ${cfg.package}/share/prempti/rules/seen.yaml "$prefix/rules/seen.yaml"
        ${if cfg.defaultRules.enable
          then ''ln -sfn ${cfg.package}/share/prempti/rules/default/coding_agents_rules.yaml "$prefix/rules/default/coding_agents_rules.yaml"''
          else ''rm -f "$prefix/rules/default/coding_agents_rules.yaml"''}
        find "$prefix/rules/user" -maxdepth 1 -name 'nix-*.yaml' -type l -delete
        ${ruleLinks}
      '';
    };
}
