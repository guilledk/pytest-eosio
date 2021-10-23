FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y git build-essential wget make software-properties-common

# install latest cmake from kitware repo
RUN wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /etc/apt/trusted.gpg.d/kitware.gpg >/dev/null
RUN apt-add-repository 'deb https://apt.kitware.com/ubuntu/ bionic main'
RUN apt-get update && apt-get install -y cmake 

RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.7.0/eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb

# install wasm-ld wrapper to disable threads
WORKDIR /usr/opt/eosio.cdt/1.7.0/bin
RUN mv wasm-ld wasm-ld.real
COPY ld-wrapper.sh wasm-ld
RUN chmod +x wasm-ld

WORKDIR /root

CMD sleep 9999999999
