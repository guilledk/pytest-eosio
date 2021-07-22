#!/usr/bin/env python3

from typing import List, Union

import pytest

from .sugar import Symbol, Asset, asset_from_str, symbol_from_str
from .plugin import EOSIOTestSession
from .contract import SmartContract


telos_token = Symbol('TLOS', 4)
vote_token = Symbol('VOTE', 4)


class TelosDecide(SmartContract):

    @property
    def contract_name(self) -> str:
        return 'telos.decide'

    _did_init = False
    def init(self, version: str):
        if not self._did_init:
            self._did_init = True
            return self.push_action(
                'init',
                [f'v{version}'],
                f'{self.contract_name}@active'
            )
        else:
            return (0, '')

    def get_config(self):
        configs = self.get_table(
            self.contract_name,
            'config'
        )
        assert len(configs) == 1  # singleton
        return configs[0]

    def deposit(
        self,
        _from,
        amount
    ):
        return self.testnet.transfer_token(
            _from, self.contract_name, amount, 'deposit'
        )

    def new_treasury(
        self,
        manager: str,
        max_supply: str,
        access: str
    ):
        return self.push_action(
            'newtreasury',
            [manager, max_supply, access],
            f'{manager}@active'
        )

    def get_treasuries(self):
        return self.get_table(
            self.contract_name,
            'treasuries'
        )

    def get_treasury(self, sym: Union[str, Symbol]):
        if isinstance(sym, str):
            sym = symbol_from_str(sym) 

        treasuries = self.get_treasuries()
        return next((
            row for row in treasuries
            if sym.code in row['max_supply']),
            None
        )

    def toggle(self, sym: [str, Symbol], setting: str):
        if isinstance(sym, str):
            sym = sym.split(',')[1]

        treasury = self.get_treasury(sym)
        assert treasury is not None
        return self.push_action(
            'toggle',
            [sym, setting],
            f'{treasury["manager"]}@active'
        )

    def register_voter(
        self,
        voter: str,
        treasury_sym: str,
        referrer: str
    ):
        return self.push_action(
            'regvoter',
            [voter, treasury_sym, referrer],
            f'{voter}@active'
        )

    def unregister_voter(
        self,
        voter: str,
        treasury_sym: str
    ):
        return self.push_action(
            'unregvoter',
            [voter, treasury_sym],
            f'{voter}@active'
        )

    def get_voter(
        self,
        voter: str
    ):
        voter = self.get_table(
            voter,
            'voters'
        )
        assert len(voter) == 1
        return voter[0]
   
    def mint(
        self,
        to: str,
        quantity: Union[str, Asset],
        memo: str
    ):
        if isinstance(quantity, Asset):
            sym = quantity.symbol
        else:
            sym = asset_from_str(quantity).symbol 
        
        treasury = self.get_treasury(sym)
        assert treasury is not None
        
        return self.push_action(
            'mint',
            [to, quantity, memo],
            f'{treasury["manager"]}@active'
        )

    def burn(
        self,
        quantity: Union[str, Asset],
        memo: str
    ):
        if isinstance(quantity, Asset):
            sym = quantity.symbol
        else:
            sym = asset_from_str(quantity).symbol 
        
        treasury = self.get_treasury(sym)
        assert treasury is not None

        return self.push_action(
            'burn',
            [quantity, memo],
            f'{treasury["manager"]}@active'
        )

    def burn_all(
        self,
        sym: Union[str, Symbol],
        memo: str = 'testing burn'
    ):
        manager = self.get_treasury(sym)['manager']
        return self.burn(
            self.get_voter(manager)['liquid'],
            memo
        )

    def reclaim(
        self,
        voter: str,
        quantity: Union[str, Asset],
        memo: str = 'testing reclaim'
    ):
        if isinstance(quantity, Asset):
            sym = quantity.symbol
        else:
            sym = asset_from_str(quantity).symbol 
        
        treasury = self.get_treasury(sym)
        assert treasury is not None
        return self.push_action(
            'reclaim',
            [voter, quantity, memo],
            f'{treasury["manager"]}@active'
        )

    def reclaim_all(self, voter: str, memo: str = 'testing reclaim'):
        return self.reclaim(
            voter,
            asset_from_str(self.get_voter(voter)['liquid']),
            memo
        )

    def stake(
        self,
        voter: str,
        quantity: Union[str, Asset]
    ):
        return self.push_action(
            'stake',
            [voter, quantity],
            f'{voter}@active'
        )

    def unstake(
        self,
        voter: str,
        quantity: Union[str, Asset]
    ):
        return self.push_action(
            'unstake',
            [voter, quantity],
            f'{voter}@active'
        )

    def unstake_all(self, voter: str):
        return self.unstake(voter, asset_from_str(self.get_voter(voter)['staked']))

    def new_ballot(
        self,
        ballot_name: str,
        category: str,
        publisher: str,
        treasury_sym: str,
        voting_method: str,
        init_options: List[str]
    ):
        return self.push_action(
            'newballot',
            [
                ballot_name,
                category,
                publisher,
                treasury_sym,
                voting_method,
                init_options
            ],
            f'{publisher}@active'
        )

    def get_ballot(
        self,
        ballot_name: str
    ):
        ballots = self.get_table(
            self.contract_name,
            'ballots'
        )
        return next((
            row for row in ballots
            if row['ballot_name'] == ballot_name),
            None
        )

    def open_voting(
        self,
        ballot_name: str,
        end_time: str
    ):
        ballot = self.get_ballot(ballot_name)
        return self.push_action(
            'openvoting',
            [ballot_name, end_time],
            f'{ballot["publisher"]}@active'
        )

    def close_voting(
        self,
        ballot_name: str,
        broadcast: bool = True
    ):
        ballot = self.get_ballot(ballot_name)
        return self.push_action(
            'closevoting',
            [ballot_name, str(int(broadcast))],
            f'{ballot["publisher"]}@active'
        )

    def cast_vote(
        self,
        voter: str,
        ballot_name: str,
        options: str
    ):
        return self.push_action(
            'castvote',
            [voter, ballot_name, options],
            f'{voter}@active'
        )


@pytest.fixture(scope="session")
def telosdecide(eosio_testnet):
    contract = TelosDecide(eosio_testnet)
    yield contract


_token_init = False
def init_telos_token(api: EOSIOTestSession):
    global _token_init
    if not _token_init:
        _token_init = True
        max_supply = f'{2100000000:.4f} TLOS'
        ec, _ = api.create_token('eosio.token', max_supply)
        assert ec == 0
        ec, _ = api.issue_token('eosio.token', max_supply, __name__)
        assert ec == 0
