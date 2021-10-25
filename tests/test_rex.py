#!/usr/bin/env python3

from pytest_eosio.telos import telos_token
from pytest_eosio.sugar import Asset


def test_rex_init(eosio_testnet):
    eosio_testnet.deploy_contract(
        'exrsrv.tf',
        f'{eosio_testnet.sys_contracts_path}/contracts/eosio.tedp',
    )

    eosio_testnet.give_token(
        'exrsrv.tf',
        Asset(20000000, telos_token))

    ec, out = eosio_testnet.push_action(
        'exrsrv.tf',
        'setrex',
        [1164],
        'eosio@active'
    )
    assert ec == 0
    
