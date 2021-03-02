#!/usr/bin/env python3


def test_decide_setup(eosio_testnet):
    ec, _ = eosio_testnet.tlos_decide_setup()
    assert ec == 0
