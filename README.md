# BitBoxBridge

This is the BitBoxBridge, it connects web wallets like MyEtherWallet to your BitBox02.

## Installers

There are installers for Windows/OSX and linux under [releases](https://github.com/digitalbitbox/bitbox-bridge/releases).

## Compile

### Dependencies

Go to [rustup](https://rustup.rs/) and get at least version 1.38 of the stable rust compiler.

You need `libusb-1.0-0-dev` to compile the examples (`apt install libusb-1.0-0-dev`). Cargo will
compile libhidapi and link to it statically.

There are also docker build containers for every supported target in [bitbox-bridge/release](bitbox-bridge/release).

### Compile

Only build:

```
cargo build --release
```

## Run

Build and run:

```
cargo run --release
```

# BitBoxBridge API

Return current API version:

```
GET /api/info
```

Return map of available usb devices. (might have to poll multiple times)

```
GET /api/v1/devices
```

Open websocket.

`<path>` can be found in the value returned by `/devices`. WebSocket opening will fail with an
error in case the device is busy.

```
/api/v1/socket/<path>
```

# Troubleshooting

The bridge should be available on `http://localhost:8178`. Try the `/` endpoint and see if the
bridge is running. Try `/api/v1/devices` to see if your device is listed.

The website is online at [http://dev.shiftcrypto.ch/bridge](http://dev.shiftcrypto.ch/bridge)
