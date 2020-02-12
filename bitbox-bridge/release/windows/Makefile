# A poor mans command runner

CONTAINER=shiftcrypto/bitbox-bridge-windows
MOUNT=$(shell pwd)/../../..:/bitbox-bridge
USER=$(shell id -u):$(shell id -g)


dockerinit:
	docker build --pull --force-rm --no-cache -t ${CONTAINER} .

dockershell:
	docker run --user ${USER} --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bash

release:
	docker run --user ${USER} --interactive --tty -v ${MOUNT} -w /bitbox-bridge ${CONTAINER} bitbox-bridge/release/windows/release.sh
