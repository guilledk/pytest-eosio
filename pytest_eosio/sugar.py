#!/usr/bin/env python3

from __future__ import annotations

import re
import string
import random
import logging

from typing import Dict, Optional
from decimal import Decimal
from pathlib import Path
from hashlib import sha1
from datetime import datetime
from binascii import hexlify
from contextlib import contextmanager

from natsort import natsorted
from docker.errors import NotFound


EOSIO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


def string_to_sym_code(sym):
    ret = 0
    for i, char in enumerate(sym):
        if char >= 'A' or char <= 'Z':
            code = ord(char)
            ret |= code << 8 * i

    return ret


class Symbol:

    def __init__(self, code: str, precision: int):
        self.code = code
        self.precision = precision

    @property
    def unit(self) -> float:
        return 1 / (10 ** self.precision)

    def __eq__(self, other) -> bool:
        return (
            self.code == other.code and
            self.precision == other.precision
        )

    def __str__(self) -> str:
        return f'{self.precision},{self.code}'


def symbol_from_str(str_sym: str):
    prec, code = str_sym.split(',')
    return Symbol(code, int(prec))


class Asset:

    def __init__(self, amount: float, symbol: Symbol):
        self.amount = amount
        self.symbol = symbol

    def __eq__(self, other) -> bool:
        return (
            self.amount == other.amount and
            self.symbol == other.symbol
        )

    def __str__(self) -> str:
        number = format(self.amount, f'.{self.symbol.precision}f')
        return f'{number} {self.symbol.code}'


def asset_from_str(str_asset: str):
    numeric, sym = str_asset.split(' ')
    precision = len(numeric) - numeric.index('.') - 1
    return Asset(float(numeric), Symbol(sym, precision))


def asset_from_decimal(dec: Decimal, precision: int, sym: str):
    result = str(dec)
    pindex = result.index('.')
    return f'{result[:pindex + 1 + precision]} {sym}'


def asset_from_ints(amount: int, precision: int, sym: str):
    result = str(amount)
    return f'{result[:-precision]}.{result[-precision:]} {sym}'


def eosio_format_date(date: datetime) -> str:
    return date.strftime(EOSIO_DATE_FORMAT)


def eosio_parse_date(date: str) -> datetime:
    return datetime.strptime(date, EOSIO_DATE_FORMAT)


class Name:

    def __init__(self, _str: str):
        
        assert len(_str) <= 13
        assert not bool(re.compile(r'[^a-z0-9.]').search(_str))

        self._str = _str

    def __str__(self) -> str:
        return self._str

    @property
    def value(self) -> int:
        """Convert name to its number repr
        """

        def str_to_hex(c):
            hex_data = hexlify(bytearray(c, 'ascii')).decode()
            return int(hex_data, 16)


        def char_subtraction(a, b, add):
            x = str_to_hex(a)
            y = str_to_hex(b)
            ans = str((x - y) + add)
            if len(ans) % 2 == 1:
                ans = '0' + ans
            return int(ans)


        def char_to_symbol(c):
            ''' '''
            if c >= 'a' and c <= 'z':
                return char_subtraction(c, 'a', 6)
            if c >= '1' and c <= '5':
                return char_subtraction(c, '1', 1)
            return 0

        i = 0
        name = 0
        while i < len(self._str) :
            name += (char_to_symbol(self._str[i]) & 0x1F) << (64-5 * (i + 1))
            i += 1
        if i > 12 :
            name |= char_to_symbol(self._str[11]) & 0x0F
        return name


def name_from_value(n: int) -> Name:
    """Convert valid eosio name value to the internal representation
    """
    charmap = '.12345abcdefghijklmnopqrstuvwxyz'
    name = ['.'] * 13
    i = 0
    while i <= 12:
        c = charmap[n & (0x0F if i == 0 else 0x1F)]
        name[12-i] = c
        n >>= 4 if i == 0 else 5
        i += 1
    return Name(''.join(name).rstrip('.'))


def str_to_hex(c):
    hex_data = hexlify(bytearray(c, 'ascii')).decode()
    return int(hex_data, 16)


def char_subtraction(a, b, add):
    x = str_to_hex(a)
    y = str_to_hex(b)
    ans = str((x - y) + add)
    if len(ans) % 2 == 1:
        ans = '0' + ans
    return int(ans)


def char_to_symbol(c):
    ''' '''
    if c >= 'a' and c <= 'z':
        return char_subtraction(c, 'a', 6)
    if c >= '1' and c <= '5':
        return char_subtraction(c, '1', 1)
    return 0


def string_to_name(s: str) -> int:
    """Convert valid eosio name to its number repr
    """
    i = 0
    name = 0
    while i < len(s) :
        name += (char_to_symbol(s[i]) & 0x1F) << (64-5 * (i + 1))
        i += 1
    if i > 12 :
        name |= char_to_symbol(s[11]) & 0x0F
    return name


def name_to_string(n: int) -> str:
    """Convert valid eosio name to its ascii repr
    """
    charmap = '.12345abcdefghijklmnopqrstuvwxyz'
    name = ['.'] * 13
    i = 0
    while i <= 12:
        c = charmap[n & (0x0F if i == 0 else 0x1F)]
        name[12-i] = c
        n >>= 4 if i == 0 else 5
        i += 1
    return ''.join(name).rstrip('.')


def find_in_balances(balances, symbol):
    for balance in balances:
        asset = asset_from_str(balance['balance'])
        if asset.symbol == symbol:
            return asset

    return None


def collect_stdout(out: Dict):
    assert isinstance(out, dict)
    output = ''
    for action_trace in out['processed']['action_traces']:
        if 'console' in action_trace:
            output += action_trace['console']

    return output


# SHA-1 hash of file
def hash_file(path: Path) -> bytes:
    BUF_SIZE = 65536
    hasher = sha1()
    with open(path, 'rb') as target_file:
        while True:
            data = target_file.read(BUF_SIZE)
            if not data:
                break
            hasher.update(data)

    return hasher.digest()


def hash_dir(target: Path, includes=[]):
    logging.info(f'hashing: {target}')
    hashes = []
    files_done = set()
    files_todo = {
        *[node.resolve() for node in target.glob('**/*.cpp')],
        *[node.resolve() for node in target.glob('**/*.hpp')],
        *[node.resolve() for node in target.glob('**/*.c')],
        *[node.resolve() for node in target.glob('**/*.h')]
    }
    while len(files_todo) > 0:
        new_todo = set()
        for node in files_todo:

            if node in files_done:
                continue

            if not node.is_file():
                files_done.add(node)
                continue

            hashes.append(hash_file(node))
            files_done.add(node)
            with open(node, 'r') as source_file:
                src_contents = source_file.read()

            # Find all includes in source & add to todo list
            for match in re.findall('(#include )(.+)\n', src_contents):
                assert len(match) == 2
                match = match[1]
                include = match.split('<')
                if len(include) == 1:
                    include = match.split('\"')[1]
                else:
                    include = include[1].split('>')[0]

                for include_path in includes:
                    new_path = Path(f'{include_path}/{include}').resolve()
                    if new_path in files_done:
                        continue
                    new_todo.add(new_path)
                
                logging.info(f'found include: {include}')

        files_todo = new_todo

    # Order hashes and compute final hash
    hasher = sha1()
    for file_digest in natsorted(hashes, key=lambda x: x.lower()):
        hasher.update(file_digest)

    _hash = hasher.hexdigest()
    return _hash

#
# data generators for testing
#

def random_string(size=256):
    return ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for _ in range(size)
    )

def random_local_url():
    return f'http://localhost/{random_string(size=16)}'


def random_token_symbol():
    return ''.join(
        random.choice(string.ascii_uppercase)
        for _ in range(3)
    )

def random_eosio_name():
    return ''.join(
        random.choice('12345abcdefghijklmnopqrstuvwxyz')
        for _ in range(12)
    )


# pytest-dockerctl helpers

@contextmanager
def get_container(dockerctl, repo: str, tag: str, *args, **kwargs):
    """
    Get already running container or start one up using an existing dockerctl
    instance.
    """
    image = f'{repo}:{tag}'
    found = dockerctl.client.containers.list(
        filters={
            'ancestor': image,
            'status': 'running'
        }
    )
    if len(found) > 0:

        if len(found) > 1:
            logging.warning('Found more than one posible cdt container')

        yield found[0]

    else:
        local_images = [
            img.tags
            for img in dockerctl.client.images.list(repo)
        ]

        if image not in local_images:
            updates = {}
            for update in dockerctl.client.api.pull(
                repo, tag=tag, stream=True, decode=True
            ):
                if 'id' in update:
                    _id = update['id']
                    if _id not in updates or (updates[_id] != update['status']):
                        updates[_id] = update['status']
                        logging.info(f'{_id}: {update["status"]}')

        with dockerctl.run(image, *args, **kwargs) as containers:
            yield containers[0]
