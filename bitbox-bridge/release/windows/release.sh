#!/usr/bin/env bash
# Must be executed from the top folder

set -e

CARGO_HOME=/tmp/cargo \
TARGET_CC=clang \
cargo build --target x86_64-pc-windows-gnu --release

cp target/x86_64-pc-windows-gnu/release/bitbox-bridge.exe bitbox-bridge/release/windows/
