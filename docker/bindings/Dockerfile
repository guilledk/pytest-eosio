FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# https://developers.eos.io/welcome/latest/getting-started/development-environment/introduction

RUN apt-get update && apt-get install -y \
    git \
    wget \
    make \
    curl \
    sudo \
    ruby \
    clang \
    python3 \
    libtool \
    doxygen \
    autoconf \
    automake \
    graphviz \
    python2.7 \
    pkg-config \
    llvm-7-dev \
    zlib1g-dev \
    libicu-dev \
    libbz2-dev \
    libssl-dev \
    libgmp3-dev \
    python3-dev \
    libncurses5 \
    python2.7-dev \
    autotools-dev \
    build-essential \
    libusb-1.0-0-dev \
    libboost-all-dev \
    libcurl4-gnutls-dev

RUN mkdir /root/work
WORKDIR /root/work

RUN wget https://github.com/Kitware/CMake/releases/download/v3.22.0/cmake-3.22.0.tar.gz
RUN tar xvf cmake-3.22.0.tar.gz
WORKDIR /root/work/cmake-3.22.0
RUN ./boostrap
RUN make
RUN make install

RUN git clone --recursive --branch shared_build https://github.com/guilledk/eos.git
RUN git clone --recursive --branch pybind11_backend https://github.com/guilledk/pytest-eosio.git

RUN cp -r pytest-eosio/bindings eos/libraries/testing/bindings

RUN sed -i 's/rm -rf/echo/' eos/scripts/helpers/eosio.sh

WORKDIR /root/work/eos

RUN scripts/eosio_build.sh -y -i /usr/opt/eosio -s TLOS
