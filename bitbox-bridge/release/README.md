# How to release all the platforms

Bump the version number, commit and merge to master. The version number is in
`bitbox-bridge/Cargo.toml`.

Go in each subdirectory and run `make release`. If needed, run `make dockerinit` to create the
docker images.

Copy the whole project to a windows machine and go into the windows subdirectory and run
`package.cmd`.

Copy the whole project to an OSX machine and run `bitbox-bridge/release/darwin/package.sh`.

You can of course also mount the same directory on windows/osx to avoid copying.


```
make -C windows release
make -C linux release
make -C darwin release
```
