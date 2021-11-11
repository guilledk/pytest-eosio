FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# https://developers.eos.io/welcome/latest/getting-started/development-environment/introduction

RUN apt-get update && apt-get install -y \
    git \
    wget \
    make \
    curl \
    sudo \
    ruby \
    cmake \
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

# compile and install system contracts
RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.6.3/eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN git clone https://github.com/telosnetwork/telos.contracts
RUN cp -r telos.contracts /usr/opt/telos.contracts

WORKDIR /usr/opt/telos.contracts

# remove testing target from CMake
RUN head -n -10 CMakeLists.txt > .tmp_cmake && \
    mv .tmp_cmake CMakeLists.txt 

RUN cmake .
RUN make -j$(nproc --all)

# cleanup contracts directory
WORKDIR /usr/opt/telos.contracts/contracts
RUN rm -rdf icons CMakeFiles

# install eosio tools
RUN mkdir /tmp/eosio
WORKDIR /tmp/eosio

# download source
RUN git clone --depth 1 --recursive --branch v2.0.13 https://github.com/EOSIO/eos.git

# development command to make docker not cache
# change echo msg to build from here
RUN echo 'cool tech v5'

# install testing plugin
WORKDIR /tmp/eosio/eos/plugins
RUN git clone https://github.com/guilledk/eosio-testing-plugin.git

WORKDIR /tmp/eosio/eos
RUN git apply plugins/eosio-testing-plugin/install.patch

# build & install
WORKDIR /tmp/eosio/eos
RUN scripts/eosio_build.sh -y -i /usr/opt/eosio -s TLOS 
RUN scripts/eosio_install.sh
ENV PATH /usr/opt/eosio/bin:$PATH

# setup wallet dir
RUN mkdir -p /root/eosio-wallet

# cleanup source files
WORKDIR /
RUN rm -rdf /tmp/eosio/eos

EXPOSE 8888

CMD sleep 99999999999
