FROM ubuntu:18.04

ARG USER_ID
ARG GROUP_ID

RUN addgroup --gid $GROUP_ID user
RUN adduser --disabled-password --gecos '' --uid $USER_ID --gid $GROUP_ID user

ENV DEBIAN_FRONTEND=noninteractive

# https://developers.eos.io/welcome/latest/getting-started/development-environment/introduction

RUN apt-get update && apt-get install -y wget

RUN wget https://github.com/EOSIO/eos/releases/download/v2.0.9/eosio_2.0.9-1-ubuntu-18.04_amd64.deb

RUN apt-get install -y ./eosio_2.0.9-1-ubuntu-18.04_amd64.deb

COPY entrypoint.sh /

USER user

EXPOSE 8888

ENTRYPOINT ["/entrypoint.sh"]

HEALTHCHECK --interval=5s --timeout=10s --retries=3 CMD tail -n 1 /tmp/nodeos.log | grep Produced
