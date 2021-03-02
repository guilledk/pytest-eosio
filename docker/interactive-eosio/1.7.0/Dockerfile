FROM ubuntu:18.04

ARG USER_ID
ARG GROUP_ID

RUN addgroup --gid $GROUP_ID user
RUN adduser --disabled-password --gecos '' --uid $USER_ID --gid $GROUP_ID user

ENV DEBIAN_FRONTEND=noninteractive

# https://developers.eos.io/welcome/latest/getting-started/development-environment/introduction

RUN apt-get update && apt-get install -y wget make cmake python3

RUN wget https://github.com/EOSIO/eos/releases/download/v2.0.9/eosio_2.0.9-1-ubuntu-18.04_amd64.deb

RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.7.0/eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio_2.0.9-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.7.0-1-ubuntu-18.04_amd64.deb

RUN wget https://github.com/EOSIO/eosio.contracts/archive/v1.9.2.tar.gz -O eosio.contracts.tar.gz
RUN tar xf eosio.contracts.tar.gz
WORKDIR /eosio.contracts-1.9.2
RUN cp -r contracts /usr/opt/eosio.contracts
WORKDIR /usr/opt/eosio.contracts
RUN rm -rdf icons
WORKDIR /

ENV CC=eosio-cc
ENV CXX=eosio-cpp

COPY entrypoint.sh /

USER user

ENTRYPOINT ["/entrypoint.sh"]

HEALTHCHECK --interval=5s --timeout=10s --retries=3 CMD tail -n 1 /tmp/nodeos.log | grep Produced
