FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y build-essential wget make cmake

RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.6.3/eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN wget https://github.com/EOSIO/eosio.contracts/archive/v1.8.3.tar.gz -O eosio.contracts.tar.gz
RUN tar xf eosio.contracts.tar.gz
WORKDIR /eosio.contracts-1.8.3
RUN cp -r contracts /usr/opt/eosio.contracts
WORKDIR /usr/opt/eosio.contracts
RUN rm -rdf icons CMakeLists.txt
WORKDIR /

CMD sleep 9999999999
