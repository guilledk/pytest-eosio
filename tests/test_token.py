#!/usr/bin/env python3

from pytest_eosiocdt import (
    random_string,
    random_token_symbol
)


def test_create_token(eosio_testnet):
    account = eosio_testnet.new_account()
    
    symbol = random_token_symbol()
    max_supply = f'1000.00 {symbol}'
    ec, out = eosio_testnet.create_token(account, max_supply)

    assert ec == 0

    stats = eosio_testnet.get_token_stats(symbol)

    assert stats is not None
    assert stats['supply'] == f'0.00 {symbol}'
    assert stats['max_supply'] == max_supply
    assert stats['issuer'] == account


def test_issue_token(eosio_testnet):
    account = eosio_testnet.new_account()

    symbol = random_token_symbol()
    max_supply = f'1000.00 {symbol}'
    eosio_testnet.create_token(account, max_supply)

    ec, out = eosio_testnet.issue_token(
        account,
        max_supply,
        random_string()
    )

    assert ec == 0

    stats = eosio_testnet.get_token_stats(symbol)

    assert stats['supply'] == max_supply

    assert eosio_testnet.get_balance(account) == max_supply


def test_transfer(eosio_testnet):
    account = eosio_testnet.new_account()

    symbol = random_token_symbol()
    max_supply = f'1000.00 {symbol}'
    eosio_testnet.create_token(account, max_supply)
    eosio_testnet.issue_token(
        account,
        max_supply,
        random_string()
    )

    peasant = eosio_testnet.new_account()

    charity = f'0.01 {symbol}'

    ec, out = eosio_testnet.transfer_token(
        account,
        peasant,
        charity,
        random_string()
    )

    assert ec == 0

    assert eosio_testnet.get_balance(account) == f'999.99 {symbol}'
    assert eosio_testnet.get_balance(peasant) == charity
