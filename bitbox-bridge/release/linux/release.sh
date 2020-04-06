#!/usr/bin/env bash
# Must be executed from the top folder

set -e

NAME=bitbox-bridge
VERSION=$(toml-echo bitbox-bridge/Cargo.toml package.version)
TAR=${NAME}-${VERSION}.tar.bz2

# Build executable
(cd bitbox-bridge || exit; CARGO_HOME=/tmp/cargo cargo build --release)

pushd bitbox-bridge/release/linux || exit

# Create tarball
install -D -m 0755 ../../../target/release/bitbox-bridge ./opt/bitbox-bridge/bin/bitbox-bridge
install -D -m 0644 hid-digitalbitbox.rules ./lib/udev/rules.d/50-hid-digitalbitbox.rules
install -D -m 0644 bitbox-bridge.service ./usr/lib/systemd/system/bitbox-bridge.service
tar --owner=0 --group=0 --numeric-owner --mtime='1970-01-01' --sort=name \
	-caf "${TAR}"  ./opt ./lib ./usr

DEPS_deb=libhidapi-libusb0
DEPS_rpm=hidapi

# Create packages
for type in deb rpm; do
	DEPS=DEPS_${type}
	fpm \
		--force \
		--input-type tar \
		--output-type ${type} \
		--architecture x86_64 \
		--name "${NAME}" \
		--version "${VERSION}" \
		--depends systemd \
		--depends "${!DEPS}" \
		--url 'http://shiftcrypto.ch' \
		--maintainer 'Shiftcrypto <support@shiftcrypto.ch>' \
		--before-install pre-install.sh \
		--after-install post-install.sh \
		--before-remove pre-remove.sh \
		"${TAR}"
done
popd || exit
