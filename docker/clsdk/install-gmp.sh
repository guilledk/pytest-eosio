#!/bin/bash

cores="$(nproc --all)"

# 1 - wget gmp sources, untar & enter directory

wget https://gmplib.org/download/gmp/gmp-6.2.1.tar.xz

tar xf gmp-6.2.1.tar.xz

pushd gmp-6.2.1

# 2 - configure to build for wasm32-wasi

./configure \
    --host=wasm32-wasi \
    --prefix=$GMP_PREFIX

# 3 - build

make -j$cores

# 4 - install

make install -j$cores
