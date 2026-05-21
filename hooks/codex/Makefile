PREFIX ?= $(HOME)/.prempti

.PHONY: all linux macos install clean test

all:
	cargo build --release

linux: all

macos:
	cargo build --release --target aarch64-apple-darwin
	cargo build --release --target x86_64-apple-darwin
	lipo -create -output target/release/codex-interceptor \
		target/aarch64-apple-darwin/release/codex-interceptor \
		target/x86_64-apple-darwin/release/codex-interceptor

install: all
	install -d $(PREFIX)/bin
	install -m 755 target/release/codex-interceptor $(PREFIX)/bin/

clean:
	cargo clean

test:
	cargo test --release
