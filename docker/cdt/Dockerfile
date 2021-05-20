FROM ubuntu:18.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y build-essential wget make cmake

RUN wget https://github.com/EOSIO/eosio.cdt/releases/download/v1.6.3/eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio.cdt_1.6.3-1-ubuntu-18.04_amd64.deb

RUN wget https://github.com/telosnetwork/telos.contracts/archive/refs/tags/v1.7.0.tar.gz -O telos.contracts.tar.gz
RUN tar xf telos.contracts.tar.gz
RUN cp -r telos.contracts-1.7.0 /usr/opt/telos.contracts

WORKDIR /usr/opt/telos.contracts

# remove testing target from CMake
RUN head -n -10 CMakeLists.txt > .tmp_cmake && \
    mv .tmp_cmake CMakeLists.txt 

RUN cmake .
RUN make -j$(nproc --all)

# cleanup contracts directory
WORKDIR /usr/opt/telos.contracts/contracts
RUN rm -rdf icons CMakeFiles

WORKDIR /root

CMD sleep 9999999999
