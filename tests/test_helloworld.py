#!/usr/bin/env python3


def test_hi(eosio_testnet):
    account = "testacc"
    ec, out = eosio_testnet.push_action(
        'helloworld', 'hi', [account], 'helloworld@active'
    )
    assert ec == 0