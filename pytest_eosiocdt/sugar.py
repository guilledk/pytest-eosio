#!/usr/bin/env python3

import string
import random

from typing import Dict, Optional
from pathlib import Path
from hashlib import sha1
from datetime import datetime


EOSIO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


def eosio_format_date(date: datetime) -> str:
    return date.strftime(EOSIO_DATE_FORMAT)


def eosio_parse_date(date: str) -> datetime:
    return datetime.strptime(date, EOSIO_DATE_FORMAT)


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


#
# data generators for testing
#

def random_string(size=256):
    return ''.join(
        random.choice(string.ascii_lowercase + string.digits)
        for _ in range(size)
    )

def random_local_url():
    return 'http://localhost/{random_string()}'


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
