#!/usr/bin/env python3


def test_rex_init(eosio_testnet):
    eosio_testnet.deploy_contract(
        'exrsrv.tf',
        f'{eosio_testnet.sys_contracts_path}/contracts/eosio.tedp',
    )
