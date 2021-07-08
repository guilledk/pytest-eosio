#!/bin/bash

export PATH="$WASMTIME_HOME/bin:$PATH"
cores="$(nproc --all)"

# 1 - wget ntl sources, untar & enter directory

wget https://libntl.org/ntl-11.4.3.tar.gz

tar xf ntl-11.4.3.tar.gz

pushd ntl-11.4.3/src

sed -i 's/.\/GenConfigInfo/wasmtime GenConfigInfo/g' DoConfig
sed -i 's/.\/$name/wasmtime --dir=. $name/g' DoConfig
sed -i 's/.\/CheckFeatures/wasmtime --dir=. CheckFeatures/g' MakeCheckFeatures 

# 2 - configure to build for wasm32-wasi

./configure \
    CXX=$CXX \
    AR=$AR \
    RANLIB=$RANLIB \
    CXXFLAGS="$CXXFLAGS" \
    NATIVE=off \
    PREFIX=$NTL_PREFIX \
    DEF_PREFIX=$WASI_SYSROOT \
    NTL_THREADS=off \
    NTL_GMP_LIP=on \
    NTL_SAFE_VECTORS=off \
    GMP_PREFIX=$GMP_PREFIX

sed -i 's/.\/MakeDesc/wasmtime --dir=. MakeDesc/g' makefile
sed -i 's/.\/gen_gmp_aux/wasmtime --dir=. gen_gmp_aux/g' makefile
sed -i 's/.\/QuickTest/wasmtime --dir=. QuickTest/g' makefile

# 3 - build

make -j$cores

# 4 - install

make install -j$cores
