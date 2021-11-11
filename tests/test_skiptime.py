#!/usr/bin/env python3

import logging

from time import time, sleep

from pytest_eosio import collect_stdout


def test_skip_time(eosio_testnet):
    
    time_in_seg = 200
    time_in_us = time_in_seg * 1000000

    begin = time()

    eosio_testnet.skip_time(time_in_us)
    ec, out = eosio_testnet.push_action(
        'testcontract',
        'timestamp',
        [],
        'eosio@active')

    contract_time = int(collect_stdout(out))
    end = time()

    real_delta = end - begin
    fake_delta = contract_time - begin

    logging.info(f'real delta: {real_delta}')
    logging.info(f'fake delta:  {fake_delta}')

    assert ec == 0
    assert fake_delta > real_delta
    assert fake_delta - real_delta > (time_in_seg * .95)
