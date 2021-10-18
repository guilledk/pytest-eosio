#!/usr/bin/env python3

from pytest_eosio import random_token_symbol, string_to_name


def test_multi_sig_contract(eosio_testnet):

    a, b = (
        eosio_testnet.new_account()
        for _ in range(2)
    )

    owner_perms = [f'{name}@active' for name in (a, b)]
    owner_perms.sort()
    
    # multi_acc = eosio_testnet.create_multi_sig_account(owner_perms)

    proposal = eosio_testnet.multi_sig_propose(
        a,
        owner_perms,
        owner_perms,
        'testcontract',
        'testmultisig',
        {
            'a': a,
            'b': b
        }
    )

    for name in (a, b):
        ec, _ = eosio_testnet.multi_sig_approve(
            a,
            proposal,
            [f'{name}@active'],
            name
        )
        assert ec == 0

    ec, _ = eosio_testnet.push_action(
        'testcontract',
        'initcfg',
        [0],
        'eosio@active'
    )
    assert ec == 0

   
    conf = eosio_testnet.get_table(
        'testcontract',
        'testcontract',
        'config'
    )[0]

    assert conf['value'] == '0'

    ec, _ = eosio_testnet.multi_sig_exec(
        a,
        proposal,
        f'{a}@active'
    )
    assert ec == 0
   
    conf = eosio_testnet.get_table(
        'testcontract',
        'testcontract',
        'config'
    )[0]

    assert int(conf['value']) == string_to_name(a) + string_to_name(b)


def test_multi_sig_transaction_ok(eosio_testnet):
    
    issuer, worker = (
        eosio_testnet.new_account()
        for _ in range(2)
    )

    symbol = random_token_symbol()
    amount = '1000.00'
    max_supply = f'{amount} {symbol}'

    first_amount = 20
    second_amount = 30

    fpay_amount = f'{first_amount}.00'
    spay_amount = f'{second_amount}.00'

    total_pay = f'{first_amount + second_amount}.00 {symbol}'
    
    ec, _ = eosio_testnet.create_token(issuer, max_supply)
    assert ec == 0

    ec, _ = eosio_testnet.issue_token(issuer, max_supply, '')
    assert ec == 0

    ec, _ = eosio_testnet.transfer_token(
        issuer, worker, f'{fpay_amount} {symbol}', 'first pay')

    pay_asset = f'{spay_amount} {symbol}'

    proposal = eosio_testnet.multi_sig_propose(
        worker,
        [f'{issuer}@active'],
        [f'{issuer}@active'],
        'eosio.token',
        'transfer',
        {
            'from': issuer,
            'to': worker,
            'quantity': pay_asset,
            'memo': 'multi payment'
        }
    )

    ec, out = eosio_testnet.multi_sig_approve(
        worker,
        proposal,
        [f'{issuer}@active'],
        issuer
    )
    assert ec == 0

    ec, out = eosio_testnet.multi_sig_exec(
        worker,
        proposal,
        worker
    )
    assert ec == 0

    balance = eosio_testnet.get_balance(worker)

    assert balance
    assert balance == total_pay


def test_multi_sig_transaction_error(eosio_testnet):
    
    issuer, worker = (
        eosio_testnet.new_account()
        for _ in range(2)
    )

    symbol = random_token_symbol()
    amount = '1000.00'
    max_supply = f'{amount} {symbol}'

    first_amount = 20
    second_amount = 30

    fpay_amount = f'{first_amount}.00'
    spay_amount = f'{second_amount}.00'

    ec, _ = eosio_testnet.create_token(issuer, max_supply)
    assert ec == 0

    ec, _ = eosio_testnet.issue_token(issuer, max_supply, '')
    assert ec == 0

    fpay_asset = f'{fpay_amount} {symbol}'

    ec, _ = eosio_testnet.transfer_token(
        issuer, worker, fpay_asset, 'first pay')

    proposal = eosio_testnet.multi_sig_propose(
        worker,
        [f'{issuer}@active'],
        [f'{issuer}@active'],
        'eosio.token',
        'transfer',
        {
            'from': issuer,
            'to': worker,
            'quantity': f'{spay_amount} {symbol}',
            'memo': 'multi payment'
        }
    )
    
    ec, out = eosio_testnet.multi_sig_exec(
        worker,
        proposal,
        worker
    )
    assert ec == 1

    balance = eosio_testnet.get_balance(worker)

    assert balance
    assert balance == fpay_asset
