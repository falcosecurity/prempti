PREFIX ?= $(HOME)/.prempti

.PHONY: all linux macos install clean test

all:
	cargo build --release

linux: all

macos:
	cargo build --release --target aarch64-apple-darwin
	cargo build --release --target x86_64-apple-darwin
	lipo -create -output target/release/claude-interceptor \
		target/aarch64-apple-darwin/release/claude-interceptor \
		target/x86_64-apple-darwin/release/claude-interceptor

install: all
	install -d $(PREFIX)/bin
	install -m 755 target/release/claude-interceptor $(PREFIX)/bin/

clean:
	cargo clean

test: all
	@cd ../.. && bash tests/test_interceptor.sh
