# A poor mans command runner
CONTAINER=shiftcrypto/bitbox-bridge:2
USER=$(shell id -u):$(shell id -g)
MOUNT=$(shell pwd)/../..:/bitbox-bridge

dockerinit:
	docker build --pull --force-rm --no-cache -t ${CONTAINER} .

dockershell:
	docker run --user ${USER} --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bash

# this will run all release scripts in a single container to speed up compilation
release:
	docker run --user ${USER} --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bitbox-bridge/release/release.sh

release-linux:
	docker run --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bitbox-bridge/release/linux/release.sh

release-windows:
	docker run  --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bitbox-bridge/release/windows/release.sh

release-darwin:
	docker run --user ${USER} --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bitbox-bridge/release/darwin/release.sh

clean:
	rm -rf linux/lib linux/opt linux/usr darwin/tmp

distclean: clean
	rm -rf linux/*.deb linux/*.rpm linux/*.tar.bz2 darwin/*.pkg windows/*.exe
