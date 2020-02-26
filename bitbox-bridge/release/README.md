# How to release all the platforms

Bump the version number, build the project to update the lockfile, commit and merge to master. The
version number is in `bitbox-bridge/Cargo.toml`.

Run `make release`. If needed, run `make dockerinit` to create the docker image.

Linux packages (deb/rpm/tar.gz2) will be created immediately. For Windows and OSX:

* Copy the whole project to a windows machine and go into the windows subdirectory and run
`package.cmd`.
* Copy the whole project to an OSX machine and run `bitbox-bridge/release/darwin/package.sh`.

You can of course also mount the same directory on windows/osx to avoid copying.

```
make dockerinit
make release
```

You can also build for only one architecture with `make release-linux` and so on.
