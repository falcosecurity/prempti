# Prempti Rust workspace: interceptors, ctl tool, and the Falco plugin.
#
# Output layout (mirrors what the tarball installer ships, minus Falco):
#   bin/premptictl, bin/claude-interceptor, bin/codex-interceptor
#   lib/libcoding_agent.so
#   share/prempti/configs/*.yaml      (templates, unused at runtime)
#   share/prempti/rules/default/coding_agents_rules.yaml
#   share/prempti/rules/seen.yaml
{
  lib,
  rustPlatform,
}:
let
  cargoToml = builtins.fromTOML (builtins.readFile ../Cargo.toml);
  version = cargoToml.workspace.package.version;
in
rustPlatform.buildRustPackage {
  pname = "prempti";
  inherit version;

  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml
      ../Cargo.lock
      ../hooks
      ../plugins
      ../tools
      ../tests
      ../rules
      ../configs
    ];
  };

  cargoLock.lockFile = ../Cargo.lock;

  cargoBuildFlags = [
    "-p" "claude-interceptor"
    "-p" "codex-interceptor"
    "-p" "coding-agents-plugin"
    "-p" "premptictl"
  ];

  # Unit tests for these crates need no Falco; the e2e crate does and is
  # excluded from the build above.
  cargoTestFlags = [
    "-p" "claude-interceptor"
    "-p" "codex-interceptor"
    "-p" "coding-agents-plugin"
    "-p" "premptictl"
  ];

  postInstall = ''
    # buildRustPackage installs bins to $out/bin and the cdylib to $out/lib.
    # Ship rules and config templates alongside so modules can reference them.
    mkdir -p $out/share/prempti/rules/default $out/share/prempti/configs
    cp rules/default/coding_agents_rules.yaml $out/share/prempti/rules/default/
    cp rules/seen.yaml $out/share/prempti/rules/
    cp configs/*.yaml $out/share/prempti/configs/
  '';

  meta = with lib; {
    description = "Policy and visibility layer for AI coding agents, powered by Falco";
    homepage = "https://github.com/falcosecurity/prempti";
    license = licenses.asl20;
    platforms = platforms.linux;
    mainProgram = "premptictl";
  };
}
