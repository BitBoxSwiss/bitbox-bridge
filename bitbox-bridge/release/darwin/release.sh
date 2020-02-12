#!/usr/bin/env bash
# Must be executed from the top folder

set -e

PATH="/opt/osxcross/target/bin:$PATH" \
CARGO_HOME=/tmp/cargo \
TARGET_CC=x86_64-apple-darwin14-clang \
cargo build --target x86_64-apple-darwin --release

NAME=BitBoxBridge
VERSION=$(toml-echo bitbox-bridge/Cargo.toml package.version)

(
	cd bitbox-bridge/release/darwin
	mkdir -p tmp/opt/shiftcrypto/bitbox-bridge/bin
	cp ../../../target/x86_64-apple-darwin/release/bitbox-bridge tmp/opt/shiftcrypto/bitbox-bridge/bin
	mkdir -p tmp/Library/LaunchDaemons
	cp ch.shiftcrypto.bitboxbridge.plist tmp/Library/LaunchDaemons
)

# Packaging in MacOS X
# https://vincent.bernat.ch/en/blog/2013-autoconf-osx-packaging
# https://stackoverflow.com/questions/11487596/making-os-x-installer-packages-like-a-pro-xcode-developer-id-ready-pkg
