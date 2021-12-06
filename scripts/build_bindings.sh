#!/bin/sh

docker build --tag bindings-builder -f docker/bindings/Dockerfile bindings/

docker run \
    -it \
    --rm \
    --mount type=bind,src="$(pwd)/bindings",target=/root/outside \
    bindings-builder \
    cp -r build/py-eosio/lib /root/outside/py_eosio

chown guille -R bindings/
