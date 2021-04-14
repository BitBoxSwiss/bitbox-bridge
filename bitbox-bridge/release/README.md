# How to release all the platforms

* Bump the version number, build the project to update the lockfile, commit and
  merge to master. The version number is in `bitbox-bridge/Cargo.toml`.
* Replace the `ProductCode` in `wix\Product.wxs` for the windows installer.
  Create a new id with `uuidgen` (available both on windows and linux).

Run `make release`. If needed, run `make dockerinit` to create the docker image.

## Linux:
Packages (deb/rpm/tar.gz2) will be created without further work.

## Windows:
* Copy the whole project to a windows machine
* Run `package.cmd`

## OSX
* Install "toml-echo", `cargo install --version 0.3.0 toml-echo`.
* Copy the whole project to an OSX machine
* Run `bitbox-bridge/release/darwin/package.sh`

You can of course also mount the same directory on windows/osx to avoid copying.

```
make dockerinit
make release
```

You can also build for only one architecture with `make release-linux` and so on.
