#!/usr/bin/env python3

import logging

from time import time, sleep

from pytest_eosio import collect_stdout


def test_fake_time(eosio_testnet):
    begin = time()
    with eosio_testnet.speed_up_time(100.0):
        sleep(4)
        ec, out = eosio_testnet.push_action(
            'testcontract',
            'timestamp',
            [],
            'eosio@active')
    
    contract_time = int(collect_stdout(out))
    delta = contract_time - begin
    end = time()

    logging.info(f'contract: {delta}')
    logging.info(f'elapsed:  {end - begin}')

    assert ec == 0
    assert delta > 100
