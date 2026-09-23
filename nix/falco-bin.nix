# Pre-built Falco binary from download.falco.org, patched for NixOS.
#
# Falco is not packaged in nixpkgs and building it from source drags in a
# large C++ toolchain. Prempti only needs the `falco` userspace binary in
# `nodriver` mode, and the upstream tarball links against nothing but glibc,
# so autoPatchelf is all that is required.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
}:
let
  version = "0.44.0";
  arch = stdenv.hostPlatform.uname.processor; # x86_64 | aarch64
  hashes = {
    x86_64 = "sha256-Fu0nRuIs6eDrxKz0+6yxYvNESl8lt8Z2y/+acNLuVXs=";
    aarch64 = "sha256-i7v40ODPZ7XYJajnbL5sIjpLEo2iUdPGnlqokZ4KrQ4=";
  };
in
stdenv.mkDerivation {
  pname = "falco-bin";
  inherit version;

  src = fetchurl {
    url = "https://download.falco.org/packages/bin/${arch}/falco-${version}-${arch}.tar.gz";
    hash = hashes.${arch} or (throw "falco-bin: unsupported architecture ${arch}");
  };

  nativeBuildInputs = [ autoPatchelfHook ];
  buildInputs = [ stdenv.cc.cc.lib ];

  dontConfigure = true;
  dontBuild = true;

  installPhase = ''
    runHook preInstall
    install -Dm755 usr/bin/falco $out/bin/falco
    runHook postInstall
  '';

  meta = with lib; {
    description = "Falco runtime security engine (pre-built userspace binary)";
    homepage = "https://falco.org";
    license = licenses.asl20;
    platforms = [ "x86_64-linux" "aarch64-linux" ];
    sourceProvenance = with sourceTypes; [ binaryNativeCode ];
    mainProgram = "falco";
  };
}
