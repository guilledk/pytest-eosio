FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y build-essential wget make cmake

RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.6.3/eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN wget https://github.com/telosnetwork/telos.contracts/archive/refs/tags/v1.7.0.tar.gz -O telos.contracts.tar.gz
RUN tar xf telos.contracts.tar.gz
RUN cp -r telos.contracts-1.7.0 /usr/opt/telos.contracts

CMD sleep 9999999999
