#!/usr/bin/env bash
# Must be executed from the top folder

# This script will run the release script for every architecture

set -e

for dir in linux windows darwin; do
	bitbox-bridge/release/${dir}/release.sh
done
