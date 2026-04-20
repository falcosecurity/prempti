# Version is pulled from the workspace Cargo.toml so this is the single
# source of truth: bumping [workspace.package].version propagates to every
# build step automatically.
VERSION := $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
FALCO_VERSION := 0.43.0
ARCH := $(shell uname -m)

.PHONY: all build build-interceptor build-plugin build-ctl \
	download-falco-linux falco-linux-bin-dir \
	falco-macos falco-macos-bin-dir \
	falco-windows falco-windows-x64 falco-windows-arm64 \
	test test-interceptor test-e2e \
	linux linux-x86_64 linux-aarch64 \
	macos macos-aarch64 macos-x86_64 macos-universal \
	windows windows-x64 windows-arm64 \
	clean help

all: linux

## Build all components for the native architecture (no packaging)
build: build-interceptor build-plugin build-ctl

## Build the interceptor
build-interceptor:
	cd hooks/claude-code && cargo build --release

## Build the plugin
build-plugin:
	cd plugins/coding-agent-plugin && cargo build --release

## Build the ctl tool
build-ctl:
	cd tools/coding-agents-kit-ctl && cargo build --release

## Download pre-built Falco binary for the native architecture (Linux only)
download-falco-linux:
	@mkdir -p build
	@if [ ! -f "build/falco-$(FALCO_VERSION)-$(ARCH).tar.gz" ]; then \
		echo "Downloading Falco $(FALCO_VERSION) for $(ARCH)..."; \
		curl -fSL -o "build/falco-$(FALCO_VERSION)-$(ARCH).tar.gz" \
			"https://download.falco.org/packages/bin/$(ARCH)/falco-$(FALCO_VERSION)-$(ARCH).tar.gz"; \
	fi
	@tar xzf "build/falco-$(FALCO_VERSION)-$(ARCH).tar.gz" -C build/

## Print the path to the downloaded Falco binary directory (Linux only)
falco-linux-bin-dir:
	@echo "build/falco-$(FALCO_VERSION)-$(ARCH)/usr/bin"

## Run all tests
test: test-interceptor test-e2e

## Run interceptor unit tests (Rust, cross-platform)
test-interceptor: build-interceptor
	cd tests && cargo test --test interceptor -- --nocapture

## Run end-to-end tests (Rust, cross-platform, requires Falco built)
test-e2e: build
	cd tests && cargo test --test e2e --test e2e_monitor -- --nocapture

## Build Linux packages for all architectures
linux: linux-x86_64 linux-aarch64

## Build Linux package for x86_64
linux-x86_64:
	bash installers/linux/package.sh --target x86_64

## Build Linux package for aarch64 (requires cross toolchain)
linux-aarch64:
	bash installers/linux/package.sh --target aarch64

## Build macOS package for the native architecture
macos: macos-aarch64

## Build macOS package for Apple Silicon
macos-aarch64:
	bash installers/macos/package.sh --target aarch64

## Build macOS package for Intel (must run on Intel Mac)
macos-x86_64:
	bash installers/macos/package.sh --target x86_64

## Build macOS universal binary package (requires Rosetta + x86_64 Homebrew)
macos-universal:
	bash installers/macos/package.sh --target universal

## Build Falco from source for macOS (required before packaging)
falco-macos:
	bash installers/macos/build-falco.sh

## Print the path to the built Falco binary directory (macOS only)
falco-macos-bin-dir:
	@echo "build/falco-$(FALCO_VERSION)-darwin-$(subst arm64,aarch64,$(ARCH))"

## Build Windows packages (must run on Windows)
windows: windows-x64

## Build Windows x64 MSI package
windows-x64:
	powershell -NoProfile -ExecutionPolicy Bypass -File installers/windows/package.ps1 -Arch x64

## Build Windows arm64 MSI package
windows-arm64:
	powershell -NoProfile -ExecutionPolicy Bypass -File installers/windows/package.ps1 -Arch arm64

## Build Falco from source for Windows (default: x64; requires vcpkg + MSVC)
falco-windows: falco-windows-x64

## Build Falco from source for Windows x64
falco-windows-x64:
	powershell -NoProfile -ExecutionPolicy Bypass -File installers/windows/build-falco.ps1 -Arch x64

## Build Falco from source for Windows arm64
falco-windows-arm64:
	powershell -NoProfile -ExecutionPolicy Bypass -File installers/windows/build-falco.ps1 -Arch arm64

## Remove build artifacts
clean:
	rm -rf build/
	-cd hooks/claude-code && cargo clean
	-cd plugins/coding-agent-plugin && cargo clean
	-cd tools/coding-agents-kit-ctl && cargo clean
	-cd tests && cargo clean

## Show available targets
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Build:"
	@echo "  build              Build all components for the native architecture"
	@echo "  build-interceptor  Build the interceptor"
	@echo "  build-plugin       Build the plugin"
	@echo "  build-ctl          Build the ctl tool"
	@echo ""
	@echo "Test:"
	@echo "  test               Run all tests"
	@echo "  test-interceptor   Run interceptor unit tests"
	@echo "  test-e2e           Run end-to-end tests (requires Falco in PATH)"
	@echo "  (tests are cross-platform — same targets work on all platforms)"
	@echo ""
	@echo "Falco:"
	@echo "  download-falco-linux  Download pre-built Falco binary (Linux only)"
	@echo "  falco-linux-bin-dir   Print path to downloaded Falco binary directory"
	@echo "  falco-macos           Build Falco from source (macOS only)"
	@echo "  falco-macos-bin-dir   Print path to built Falco binary directory"
	@echo "  falco-windows         Build Falco from source for Windows (default: x64)"
	@echo "  falco-windows-x64    Build Falco from source for Windows x64"
	@echo "  falco-windows-arm64  Build Falco from source for Windows arm64"
	@echo ""
	@echo "Package:"
	@echo "  linux              Build Linux packages for all architectures (default)"
	@echo "  linux-x86_64       Build Linux x86_64 package"
	@echo "  linux-aarch64      Build Linux aarch64 package (requires cross toolchain)"
	@echo "  macos              Build macOS package for native architecture"
	@echo "  macos-aarch64      Build macOS Apple Silicon package"
	@echo "  macos-x86_64       Build macOS Intel package (must run on Intel Mac)"
	@echo "  macos-universal    Build macOS universal binary (requires Rosetta + x86_64 Homebrew)"
	@echo "  windows            Build Windows x64 MSI package (default)"
	@echo "  windows-x64        Build Windows x64 MSI package"
	@echo "  windows-arm64      Build Windows arm64 MSI package"
	@echo ""
	@echo "Other:"
	@echo "  clean              Remove all build artifacts"
