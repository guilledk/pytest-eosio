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
    wget

WORKDIR /opt

RUN wget https://github.com/WebAssembly/wasi-sdk/releases/download/wasi-sdk-12/wasi-sdk-12.0-linux.tar.gz
RUN tar xf wasi-sdk-12.0-linux.tar.gz

RUN wget https://github.com/eoscommunity/Eden/releases/download/sdk-v0.0.2-alpha/clsdk-ubuntu-20-04.tar.gz
RUN tar xf clsdk-ubuntu-20-04.tar.gz

ENV WASI_SDK_PREFIX=/opt/wasi-sdk-12.0
ENV WASI_SYSROOT=/opt/wasi-sdk-12.0/share/wasi-sysroot
ENV CLSDK_PREFIX=/opt/clsdk

ENV PATH=$CLSDK_PREFIX/bin:$PATH

ENV CC=/opt/wasi-sdk-12.0/bin/clang
ENV CXX=/opt/wasi-sdk-12.0/bin/clang++
ENV CFLAGS="--sysroot=$WASI_SYSROOT -D_WASI_EMULATED_SIGNAL"
ENV LDFLAGS=-lwasi-emulated-signal
