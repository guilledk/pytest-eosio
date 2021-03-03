#!/usr/bin/env python3

import time

from datetime import datetime, timedelta

from pytest_eosiocdt.telos import (
    telosdecide,
    init_telos_token
)
from pytest_eosiocdt.sugar import (
    eosio_format_date,
    eosio_parse_date,
    random_token_symbol,
    random_eosio_name
)


def test_decide_init(telosdecide):
    ec, _ = telosdecide.init('2.0.0')
    assert ec == 0

    config = telosdecide.get_config()

    assert config['app_name'] == 'Telos Decide'
    assert config['app_version'] == 'v2.0.0'


def test_decide_new_tresaury(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)

    vote_supply = f'{10000000000:.4f} {random_token_symbol()}'
    ec, _ = telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    assert ec == 0

    treasuries = telosdecide.get_treasuries()

    treasury = next((
        row for row in treasuries
        if row['manager'] == 'eosio' and
        row['max_supply'] == vote_supply),
        None
    )

    assert treasury is not None


def test_decide_register_voter(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    treasury_sym = f'4,{sym}'
    voter = telosdecide.testnet.new_account()
    ec, _ = telosdecide.register_voter(voter, treasury_sym, voter)

    assert ec == 0

    voter_regs = telosdecide.get_voter(voter)

    voter_reg = next((
        row for row in voter_regs
        if sym in row['liquid']),
        None
    )
    assert voter_reg is not None


def test_decide_mint(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    treasury_sym = f'4,{sym}'
    voter = telosdecide.testnet.new_account()
    telosdecide.register_voter(voter, treasury_sym, voter)

    minted = f'{100:.4f} {sym}'
    ec, _ = telosdecide.mint(voter, minted, 'have at it friend')

    assert ec == 0

    voter_regs = telosdecide.get_voter(voter)

    voter_reg = next((
        row for row in voter_regs
        if sym in row['liquid']),
        None
    )
    assert voter_reg is not None
    assert voter_reg['liquid'] == minted


def test_decide_new_ballot(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    treasury_sym = f'4,{sym}'
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    telosdecide.register_voter('eosio', treasury_sym, 'eosio')

    ballot_name = random_eosio_name()
    category = 'poll'
    options = ['yes', 'no', 'abstain']
    ec, _ = telosdecide.new_ballot(
        ballot_name,
        category,
        'eosio',
        treasury_sym,
        '1token1vote',
        options 
    )

    assert ec == 0
    
    ballot = telosdecide.get_ballot(ballot_name)

    assert ballot is not None
    assert ballot['category'] == category
    assert ballot['treasury_symbol'] == treasury_sym
    assert ballot['voting_method'] == '1token1vote'

    for option in ballot['options']:
        assert option['key'] in options
        options.remove(option['key'])
        
    assert len(options) == 0


def test_decide_open_voting(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    treasury_sym = f'4,{sym}'
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    telosdecide.register_voter('eosio', treasury_sym, 'eosio')

    ballot_name = random_eosio_name()
    category = 'poll'
    options = ['yes', 'no', 'abstain']
    telosdecide.new_ballot(
        ballot_name,
        category,
        'eosio',
        treasury_sym,
        '1token1vote',
        options 
    )

    begin_time = datetime.utcnow()
    end_time = begin_time + timedelta(minutes=15)
    ec, _ = telosdecide.open_voting(
        ballot_name,
        eosio_format_date(end_time)
    )

    assert ec == 0

    ballot = telosdecide.get_ballot(ballot_name)

    assert ballot is not None
    assert ballot['status'] == 'voting'
    assert (
        eosio_parse_date(ballot['begin_time']) - begin_time
    ) < timedelta(seconds=2)
    assert (
        eosio_parse_date(ballot['end_time']) - end_time
    ) < timedelta(seconds=2)


def test_decide_close_voting(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    treasury_sym = f'4,{sym}'
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    telosdecide.register_voter('eosio', treasury_sym, 'eosio')

    ballot_name = random_eosio_name()
    category = 'poll'
    options = ['yes', 'no', 'abstain']
    telosdecide.new_ballot(
        ballot_name,
        category,
        'eosio',
        treasury_sym,
        '1token1vote',
        options 
    )

    begin_time = datetime.utcnow()
    end_time = begin_time + timedelta(seconds=4)
    telosdecide.open_voting(
        ballot_name,
        eosio_format_date(end_time)
    )

    time.sleep(5)

    ec, _ = telosdecide.close_voting(ballot_name)

    ballot = telosdecide.get_ballot(ballot_name)

    assert ballot is not None
    assert ballot['status'] == 'closed'


def test_decide_cast_vote(telosdecide):
    init_telos_token(telosdecide.testnet)
    fonds = f'{10000:.4f} TLOS'
    telosdecide.testnet.transfer_token(
        'eosio.token',
        'eosio',
        fonds,
        ''
    )

    telosdecide.init('2.0.0')
    telosdecide.deposit('eosio', fonds)
    
    sym = random_token_symbol()
    treasury_sym = f'4,{sym}'
    vote_supply = f'{10000000000:.4f} {sym}'
    telosdecide.new_treasury(
        'eosio',
        vote_supply,
        'public'
    )

    total_voters = 3
    voters = [
        telosdecide.testnet.new_account()
        for x in range(total_voters)
    ]
    telosdecide.register_voter('eosio', treasury_sym, 'eosio')
    minted = f'{100:.4f} {sym}'
    for voter in voters:
        telosdecide.register_voter(voter, treasury_sym, voter)
        telosdecide.mint(voter, minted, 'vote!')

    ballot_name = random_eosio_name()
    category = 'poll'
    options = ['yes', 'no', 'abstain']
    telosdecide.new_ballot(
        ballot_name,
        category,
        'eosio',
        treasury_sym,
        '1token1vote',
        options 
    )

    begin_time = datetime.utcnow()
    end_time = begin_time + timedelta(seconds=4)
    telosdecide.open_voting(
        ballot_name,
        eosio_format_date(end_time)
    )

    start = time.time()

    for i, voter in enumerate(voters):
        ec, _ = telosdecide.cast_vote(
            voter,
            ballot_name,
            [options[i]]
        )
        assert ec == 0

    end = time.time()

    time.sleep(5 - (end - start))

    ec, _ = telosdecide.close_voting(ballot_name)

    ballot = telosdecide.get_ballot(ballot_name)

    assert ballot is not None
    
    for option in ballot['options']:
        assert option['value'] == minted

    assert ballot['total_voters'] == total_voters

