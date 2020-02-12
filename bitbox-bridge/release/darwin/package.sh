#!/bin/sh

# Script for packaging on Mac OSX. Run after you have run "release.sh" in the docker container.
# Must be executed from the top folder

set -e

NAME=BitBoxBridge
VERSION=$(toml-echo bitbox-bridge/Cargo.toml package.version)

(
	cd bitbox-bridge/release/darwin
	pkgbuild --root tmp --scripts scripts --identifier ch.shiftcrypto.bitboxbridge --version "${VERSION}" --ownership recommended bridge.pkg
	productbuild --distribution distribution.xml --resources resources --package-path . --version "${VERSION}" "${NAME}-${VERSION}.pkg"
)
