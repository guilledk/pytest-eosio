#!/usr/bin/env python3


def test_internal_get_version(eosio_testnet):
    assert eosio_testnet.get_internal_plugin_version() == 'v0.1a0'
