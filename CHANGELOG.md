# Changelog

## 1.6.1
- Fix accept/deny prompt on Windows

## 1.6.0

- Prompt to accept/deny a host which is not explicitly allowed

## 1.5.1
- Fix bug where on macOS 13.3, the bridge would register one BitBox02 twice
- Fix a bug on Windows 11 causing timeouts of BitBox02 workflows
- Release built using the `shiftcrypto/bitbox-bridge:1` Docker image

## 1.5.0

- Whitelist adalite.io

## 1.4.0

- Whitelist Chrome and Firefox extensions

## 1.3.1

- Fix a bug where the bridge crashes if a connected USB devices contains unicode in the HID device info

## 1.3.0
- Whitelist bity.com
- Enable builds for Apple's M1 aarch64 platform
- Produce amd64+aarch64 Apple's universal binary

## 1.2.0
- Whitelist pocketbitcoin.com
