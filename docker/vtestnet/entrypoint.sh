#!/bin/bash

# Start keosd and nodeos
# link: https://docs.telos.net/developers/platform/development-environment/start-your-node-setup

set -e

# Step 1.1: Start keosd
keosd &

# Step 1.2: Start nodeos
nodeos -e -p eosio \
--plugin eosio::producer_plugin \
--plugin eosio::producer_api_plugin \
--plugin eosio::chain_api_plugin \
--plugin eosio::http_plugin \
--plugin eosio::history_plugin \
--plugin eosio::history_api_plugin \
--http-server-address='0.0.0.0:8888' \
--p2p-listen-endpoint='0.0.0.0:9876' \
--http-max-response-time-ms=10000 \
--abi-serializer-max-time-ms=100000 \
--filter-on="*" \
--access-control-allow-origin='*' \
--contracts-console \
--http-validate-host=false \
--max-transaction-time=100000 \
--verbose-http-errors
