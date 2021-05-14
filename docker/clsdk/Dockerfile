FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -yq \
    binaryen                \
    build-essential         \
    cmake                   \
    git                     \
    libboost-all-dev        \
    libcurl4-openssl-dev    \
    libgmp-dev              \
    libssl-dev              \
    libusb-1.0-0-dev        \
    pkg-config              \
    wget                    \
    curl

RUN curl https://wasmtime.dev/install.sh -sSf | bash

ENV WASMTIME_HOME=/root/.wasmtime

WORKDIR /opt

RUN wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk-12.0-linux.tar.gz
RUN tar xf wasi-sdk-12.0-linux.tar.gz

RUN wget https://github.com/eoscommunity/Eden/releases/download/sdk-v0.0.2-alpha/clsdk-ubuntu-20-04.tar.gz
RUN tar xf clsdk-ubuntu-20-04.tar.gz

WORKDIR /root/tmp

ENV WASI_SDK_PREFIX=/opt/wasi-sdk-12.0
ENV WASI_SYSROOT=$WASI_SDK_PREFIX/share/wasi-sysroot
ENV CLSDK_PREFIX=/opt/clsdk
ENV PATH=$CLSDK_PREFIX/bin:$PATH

ENV CC=$WASI_SDK_PREFIX/bin/clang
ENV AR=$WASI_SDK_PREFIX/bin/llvm-ar
ENV CXX=$WASI_SDK_PREFIX/bin/clang++
ENV RANLIB=$WASI_SDK_PREFIX/bin/llvm-ranlib

ENV CFLAGS="--sysroot=$WASI_SYSROOT -D_WASI_EMULATED_SIGNAL"
ENV CXXFLAGS="--sysroot=$WASI_SYSROOT -fno-exceptions"
ENV LDFLAGS=-lwasi-emulated-signal

ENV GMP_PREFIX=/opt/gmp-wasi
ENV NTL_PREFIX=/opt/ntl-wasi

COPY install-gmp.sh .
RUN ./install-gmp.sh

COPY install-ntl.sh .
RUN ./install-ntl.sh
