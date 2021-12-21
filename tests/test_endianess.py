#!/usr/bin/env python3

import json
import logging


def test_secondary_index_endianess(eosio_testnet):

    def pack(a, b):
        return (a << 64) | b

    def get_table(val):
        ec, out = eosio_testnet.run([
            'cleos', 'get', 'table',
            'testcontract', 'testcontract', 'sectest',
            '-l', '1',
            '--index', '2',
            '--key-type', 'i128',
            '--lower', '0x' + format(val, '032x')])
        if ec != 0:
            logging.critical(out)

        assert ec == 0
        return json.loads(out)

    other = 0 
   
    for i in range(10):
        ec, _ = eosio_testnet.push_action(
            'testcontract', 'addsecidx',
            [other], 'eosio@active'
        )

        assert ec == 0

    rows = get_table(pack(1, 0))['rows']

    logging.info(rows)

    assert len(rows) == 1

    breakpoint()
