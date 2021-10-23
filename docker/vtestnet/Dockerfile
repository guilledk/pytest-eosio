FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

# https://developers.eos.io/welcome/latest/getting-started/development-environment/introduction

RUN apt-get update && apt-get install -y git build-essential wget make cmake

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
RUN wget https://github.com/EOSIO/eos/releases/download/v2.0.9/eosio_2.0.9-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio_2.0.9-1-ubuntu-18.04_amd64.deb

COPY entrypoint.sh /

EXPOSE 8888

ENTRYPOINT ["/entrypoint.sh"]

HEALTHCHECK --interval=5s --timeout=10s --retries=3 CMD tail -n 1 /tmp/nodeos.log | grep Produced
