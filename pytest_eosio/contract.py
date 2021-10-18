#!/usr/bin/env python3

from abc import ABC, abstractmethod
from typing import List


class SmartContract(ABC):

    def __init__(self, eosio_testnet):
        self.testnet = eosio_testnet
    
    @property
    @abstractmethod
    def contract_name(self) -> str:
        ...

    def get_table(
        self,
        scope: str, table: str,
        *args, **kwargs
    ):
        return self.testnet.get_table(
            self.contract_name,
            scope,
            table,
            *args, **kwargs
        )

    def push_action(
        self,
        action: str,
        args: List[str],
        permissions: str,
        *vargs, **kwargs
    ):
        return self.testnet.push_action(
            self.contract_name,
            action,
            args,
            permissions,
            *vargs, **kwargs
        )
