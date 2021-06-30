#!/usr/bin/env python3

from pytest_eosiocdt import random_token_symbol


def test_multi_sig_transaction_ok(eosio_testnet):
    
    partners = [
        eosio_testnet.new_account()
        for _ in range(3)
    ]

    owner_perms = [f'{name}@active' for name in partners]
    owner_perms.sort()

    multi_acc = eosio_testnet.create_multi_sig_account(owner_perms)

    symbol = random_token_symbol()
    amount = '1000.00'
    max_supply = f'{amount} {symbol}'

    pay_amount = '50.00'

    ec, out = eosio_testnet.create_token(multi_acc, max_supply)
    assert ec == 0

    ec, out = eosio_testnet.issue_token(multi_acc, max_supply, '')
    assert ec == 0

    pay_asset = f'{pay_amount} {symbol}'

    proposal = eosio_testnet.multi_sig_propose(
        partners[0],
        owner_perms,
        [f'{multi_acc}@active'],
        'eosio.token',
        'transfer',
        {
            'from': multi_acc,
            'to': partners[0],
            'quantity': pay_asset,
            'memo': 'multi payment'
        }
    )

    for partner in partners:
        ec, _ = eosio_testnet.multi_sig_approve(
            partners[0],
            proposal,
            [f'{partner}@active'],
            partner
        )
        assert ec == 0

    ec, out = eosio_testnet.multi_sig_exec(
        partners[0],
        proposal,
        f'{partners[0]}@active'
    )
    assert ec == 0

    breakpoint()

    assert eosio_testnet.get_balance(partners[0]) == pay_asset


def test_multi_sig_transaction_error(eosio_testnet):
    
    partners = [
        eosio_testnet.new_account()
        for _ in range(3)
    ]

    owner_perms = [f'{name}@active' for name in partners]
    owner_perms.sort()

    multi_acc = eosio_testnet.create_multi_sig_account(owner_perms)

    symbol = random_token_symbol()
    amount = '1000.00'
    max_supply = f'{amount} {symbol}'

    pay_amount = '50.00'

    ec, out = eosio_testnet.create_token(multi_acc, max_supply)
    assert ec == 0

    ec, out = eosio_testnet.issue_token(multi_acc, max_supply, '')
    assert ec == 0

    pay_asset = f'{pay_amount} {symbol}'

    proposal = eosio_testnet.multi_sig_propose(
        partners[0],
        owner_perms,
        [f'{multi_acc}@active'],
        'eosio.token',
        'transfer',
        {
            'from': multi_acc,
            'to': partners[0],
            'quantity': pay_asset,
            'memo': 'multi payment'
        }
    )

    for partner in partners[:-1]:
        ec, _ = eosio_testnet.multi_sig_approve(
            partners[0],
            proposal,
            [f'{partner}@active'],
            partner
        )
        assert ec == 0

    ec, out = eosio_testnet.multi_sig_exec(
        partners[0],
        proposal,
        f'{partners[0]}@active'
    )
    assert ec == 1
