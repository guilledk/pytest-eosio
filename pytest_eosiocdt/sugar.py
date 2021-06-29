#!/usr/bin/env python3

import re
import string
import random
import logging

from typing import Dict, Optional
from decimal import Decimal
from pathlib import Path
from hashlib import sha1
from datetime import datetime
from contextlib import contextmanager

from natsort import natsorted
from docker.errors import NotFound


EOSIO_DATE_FORMAT = '%Y-%m-%dT%H:%M:%S'


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
