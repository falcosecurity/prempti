# macOS Installer

Packaging and installation scripts for Prempti on macOS (Apple Silicon and Intel).

## Prerequisites

Building from source requires:

- Rust (latest stable)
- CMake >= 3.24
- Xcode Command Line Tools
- OpenSSL via Homebrew

```bash
xcode-select --install
brew install cmake openssl@3
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Packaging

Build a distributable package from the repo root:

```bash
make macos              # Native architecture of the host
make macos-aarch64      # Apple Silicon
make macos-x86_64       # Intel (native on Intel, or Rosetta cross-compile on Apple Silicon)
make macos-universal    # Universal binary (requires Rosetta + x86_64 Homebrew)
```

Or directly:

```bash
bash installers/macos/package.sh                      # Native architecture
bash installers/macos/package.sh --target aarch64      # Apple Silicon
bash installers/macos/package.sh --target x86_64       # Intel
```

Output: `build/prempti-<version>-darwin-<arch>.{tar.gz,pkg}`

The package is self-contained: Falco binary (built from source), interceptor, plugin, ctl tool, configs (`falco.yaml`, `falco.coding_agents_plugin.yaml`, `supervisor.yaml`), rules, launchd plist, and installer.

### Falco Build from Source

Falco does not ship pre-built macOS binaries. The first build compiles Falco from source (~5 min). Subsequent builds use the cached binary.

```bash
bash installers/macos/build-falco.sh                 # Native architecture
bash installers/macos/build-falco.sh --arch x86_64   # Cross-compile for Intel
bash installers/macos/build-falco.sh --force          # Rebuild from scratch
```

The build enables http_output on macOS with `MINIMAL_BUILD=ON` + `-DBUILD_HTTP_OUTPUT=ON` — no source patch needed since Falco 0.44.

#### http_output (native since Falco 0.44)

Falco 0.43 did not build `http_output` on macOS — OpenSSL/curl were gated behind `NOT APPLE` and `outputs_http.cpp` compiled only under `Linux AND NOT MINIMAL_BUILD` — so prempti carried a patch to re-enable it. Falco 0.44 reworked http_output into a first-class, OS-agnostic build option (`BUILD_HTTP_OUTPUT`, upstreamed from prempti via falcosecurity/falco#3827) that defines `HAS_HTTP_OUTPUT` and pulls in curl. The patch is gone; the build just opts in.

**Design choice**: `MINIMAL_BUILD=ON` + `-DBUILD_HTTP_OUTPUT=ON`. `BUILD_HTTP_OUTPUT` defaults ON for normal builds but OFF under `MINIMAL_BUILD`, so we enable it explicitly. This keeps gRPC, protobuf, c-ares, cpp-httplib, and the webserver out — only curl-based http output is built. The rejected alternative `MINIMAL_BUILD=OFF` would activate all non-minimal code paths (webserver, metrics) and require all their dependencies.

#### Bundled vs system dependencies

Native macOS builds use **system libraries** for OpenSSL, curl, and zlib:

- `USE_BUNDLED_OPENSSL=OFF` with `OPENSSL_ROOT_DIR` pointing to Homebrew
- `USE_BUNDLED_CURL=OFF` (macOS ships curl)
- `USE_BUNDLED_ZLIB=OFF` (macOS ships zlib)

**Why not bundle everything**: Falco's bundled OpenSSL, curl, and zlib use autotools (`./config`, `./configure`) as ExternalProject builds. These autotools scripts do not respect CMake's `CMAKE_OSX_ARCHITECTURES`, causing architecture mismatch errors on macOS (e.g., `archive member 'adler32.o' not a mach-o file`, `invalid control bits in './libcrypto.a'`). System libraries avoid this entirely.

All other bundled dependencies (TBB, nlohmann-json, jsoncpp, re2, valijson, cxxopts) are CMake-based and build correctly on macOS.

#### Cross-compilation (x86_64 on Apple Silicon)

Cross-compilation uses **Rosetta + x86_64 Homebrew** at `/usr/local`:

```bash
arch -x86_64 /usr/local/bin/cmake -B build-x86_64 -S . [flags]
arch -x86_64 /usr/local/bin/cmake --build build-x86_64 --target falco
```

Both `arch -x86_64` (Rosetta) AND `CFLAGS="-arch x86_64"` are required:

- `arch -x86_64` makes autotools scripts detect x86_64 via `uname -m` (OpenSSL's `./config` uses this to select `darwin64-x86_64-cc` vs `darwin64-arm64-cc`)
- `CFLAGS="-arch x86_64"` forces Apple's universal compiler to produce x86_64 code (without it, the compiler picks its native arm64 slice)

Rejected alternatives:

- **`CMAKE_OSX_ARCHITECTURES` alone**: CMake ExternalProject sub-builds (jsoncpp, TBB, re2) spawn separate cmake processes that ignore the parent's `CMAKE_OSX_ARCHITECTURES`. Empirically verified: `lipo -info` on built jsoncpp showed arm64 despite x86_64 target.
- **`CFLAGS="-arch x86_64"` without Rosetta**: Environment CFLAGS don't propagate to all ExternalProject sub-builds. OpenSSL's `./config` still detects arm64 via `uname -m` and selects ARM assembly, causing `"unsupported ARM architecture"` errors.
- **`MACHINE=x86_64` env var**: OpenSSL's `./config` on macOS ignores the `MACHINE` environment variable for platform detection.
- **Native cmake cross-compilation**: Even with toolchain files, ExternalProject sub-builds don't inherit toolchain settings.
- **Bundling autotools deps for cross-compilation**: zlib and curl autotools builds produce test programs that can't link cross-arch. OpenSSL selects wrong assembly. Not viable without patching each dependency.

#### Universal binary

`make macos-universal` produces a fat arm64+x86_64 package:

1. Rust components cross-compile natively (`cargo build --target x86_64-apple-darwin` works on ARM without Rosetta)
2. Falco arm64 builds natively with system libs
3. Falco x86_64 builds under Rosetta with x86_64 Homebrew
4. `lipo -create` combines each binary pair into a universal fat binary

Prerequisites: Rosetta, x86_64 Homebrew at `/usr/local` with cmake and openssl@3.

## Installation

> **Migrating from `coding-agents-kit`?** Prempti does not migrate or remove existing `coding-agents-kit` installations. Uninstall `coding-agents-kit` first to avoid duplicate services or stale Claude Code hooks.

### From .pkg (recommended)

```bash
open prempti-<version>-darwin-universal.pkg
```

The macOS Installer wizard guides you through the setup.

### From tar.gz

```bash
tar xzf prempti-<version>-darwin-<arch>.tar.gz
cd prempti-<version>-darwin-<arch>
bash install.sh
```

### Options

```bash
bash install.sh --dry-run                # Show what would be done
```

### What It Does

1. Verifies macOS and architecture match the package
2. Copies binaries (`falco`, `claude-interceptor`, `premptictl`), plugin, configs, and rules to `~/.prempti/`
3. Installs and loads a launchd user agent (`dev.falcosecurity.prempti`) that runs `premptictl daemon --prefix <prefix>`
4. The supervisor (`ctl daemon`) registers the Claude Code hook on start and removes it on stop

### Gatekeeper

Since the binaries are not code-signed, macOS Gatekeeper may block them (especially when installing from a tarball downloaded via a browser). Go to **System Settings > Privacy & Security** and allow the blocked binary, or clear the quarantine attribute from the entire install tree — both the executables in `bin/` and the plugin library in `share/` can be flagged:

```bash
xattr -dr com.apple.quarantine ~/.prempti
```

## Uninstallation

```bash
~/.prempti/bin/premptictl uninstall
~/.prempti/bin/premptictl uninstall --keep-user-rules    # Preserve custom rules
```

## Installation Directory

```
~/.prempti/
├── bin/                    # falco, claude-interceptor, premptictl
├── config/                 # falco.yaml, falco.coding_agents_plugin.yaml,
│                           # supervisor.yaml (preserved on upgrade)
├── log/                    # falco.log[.1..N], falco.err[.1..N] (rotated by supervisor)
├── run/                    # broker.sock, supervisor.sock (runtime)
├── share/                  # libcoding_agent.dylib
└── rules/
    ├── default/            # Default rules (overwritten on upgrade)
    ├── user/               # Custom rules (preserved on upgrade)
    └── seen.yaml           # Catch-all rule (required)
```

The launchd plist is installed to `~/Library/LaunchAgents/dev.falcosecurity.prempti.plist`.

## Service Management

launchd invokes `premptictl daemon --prefix <prefix>` directly — no shell wrapper. The supervisor handles hook registration on start and removal on stop, captures Falco's stdout/stderr into rotating log files, and exposes a control socket at `run/supervisor.sock` for graceful shutdown. SIGTERM from launchd reaches the supervisor, which then orchestrates the cleanup chain.

## Files

| File | Purpose |
|------|---------|
| `package.sh` | Build script: compiles Rust components and Falco, creates tar.gz and .pkg |
| `install.sh` | Installer: copies files, sets up launchd, kicks off the supervisor |
| `build-falco.sh` | Builds Falco from source with native http_output (`-DBUILD_HTTP_OUTPUT=ON`) |
| `dev.falcosecurity.prempti.plist` | launchd user agent template (invokes `ctl daemon`) |
