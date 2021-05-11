#!/usr/bin/env python3

import re
import time
import json
import string
import random
import logging
import subprocess

from typing import Optional, List, Dict
from hashlib import sha1
from pathlib import Path
from difflib import SequenceMatcher
from subprocess import PIPE, STDOUT
from contextlib import ExitStack

import pytest
import psutil

from natsort import natsorted
from docker.types import Mount
from docker.errors import NotFound
from pytest_dockerctl import DockerCtl, waitfor

from .sugar import collect_stdout, hash_file, random_eosio_name


def pytest_addoption(parser):
    parser.addoption(
        '--endpoint', action='store', default='', help='blockchain api endpoint to target'
    )
    parser.addoption(
        '--skip-build', action='store_true', default=False, help='dont\'t build contract'
    )
    parser.addoption(
        '--force-build', action='store_true', default=False, help='ignore .binfo files & build all contracts'
    )


class EOSIOTestSession:

    def __init__(
        self,
        vtestnet,  # vtestnet container
        request,  # pytest session config
        dockerctl: DockerCtl,
        docker_mounts: List[Mount]
    ):
        endpoint = request.config.getoption('--endpoint')
        if endpoint:
            self.endpoint = endpoint
        else:
            ports = waitfor(vtestnet, ('NetworkSettings', 'Ports', '8888/tcp'))
            container_port = ports[0]['HostPort']

            self.endpoint = f'http://localhost:{container_port}'

        self.skip_build = request.config.getoption('--skip-build')
        self.force_build = request.config.getoption('--force-build')

        self.vtestnet = vtestnet
        self.dockerctl = dockerctl
        self.docker_mounts = docker_mounts

        self.user_keys = dict()

    def run(self, *args, **kwargs):
        ec, out = self.vtestnet.exec_run(*args, **kwargs)
        return ec, out.decode('utf-8')

    def build_contracts(self):
        """Build Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """
        with self.dockerctl.run(
            'guilledk/pytest-eosiocdt:cdt',
            mounts=self.docker_mounts
        ) as containers:

            def run(*args, **kwargs):
                ec, out = containers[0].exec_run(*args, **kwargs)
                return ec, out.decode('utf-8')

            sys_contracts_path = '/usr/opt/eosio.contracts'

            for contract_node in Path('contracts').resolve().glob('*'):
                if contract_node.is_dir():
                    work_dir = f'/home/user/contracts/{contract_node.name}'
                    build_dir = f'{work_dir}/build'

                    ec, out = run(['ls', sys_contracts_path])
                    assert ec == 0

                    sys_contracts = out.rstrip().split('\n')
                    include_dirs = [
                        '.',
                        './include',
                        '../include',
                        '../../include',
                        *[
                            f'{sys_contracts_path}/{contract}/include'
                            for contract in sys_contracts
                        ]
                    ]

                    """Smart build system: only recompile contracts whose
                    code as  changed, to do this we hash  every file that
                    we can find that is used in compilation, we order the
                    hash list and then use each hash to compute a  global
                    hash.
                    """

                    binfo_path = contract_node / '.binfo'
                    try:
                        with open(binfo_path, 'r') as build_info:
                            prev_hash = build_info.read()

                    except FileNotFoundError:
                        prev_hash = ''

                    logging.info(f'prev hash: {prev_hash}')

                    # Reopen to truncate contents
                    with open(binfo_path, 'w') as build_info:
                        hashes = []
                        files_done = set()
                        files_todo = {
                            *[node.resolve() for node in contract_node.glob('**/*.cpp')],
                            *[node.resolve() for node in contract_node.glob('**/*.hpp')],
                            *[node.resolve() for node in contract_node.glob('**/*.c')],
                            *[node.resolve() for node in contract_node.glob('**/*.h')]
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

                                    for include_path in include_dirs:
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

                        current_hash = hasher.hexdigest()
                        logging.info(f'proyect hash: {current_hash}')
                        build_info.write(current_hash)

                    if (prev_hash != current_hash) or self.force_build:
                        logging.info('\tperform build...')
                        # Clean contract
                        logging.info('\t\tclean build')
                        ec, out = run(
                            ['rm', '-rf', build_dir]
                        )
                        assert ec == 0

                        # Make build dir
                        logging.info('\t\tmake build dir')
                        ec, out = run(
                            ['mkdir', '-p', 'build'],
                            workdir=work_dir
                        )
                        logging.info(out)
                        assert ec == 0

                        # Build contract
                        if (contract_node / Path('CMakeLists.txt')).is_file():  # CMake
                            cxxflags = ' '.join([f'-I{incl}' for incl in include_dirs])
                        
                            cmd = ['cmake', work_dir]
                            logging.info(f'\t\t{" ".join(cmd)}')
                            ec, out = run(
                                cmd,
                                workdir=build_dir,
                                environment={'CXXFLAGS': cxxflags}
                            )
                            logging.info(out)
                            assert ec == 0

                            cmd = ['make', f'-j{psutil.cpu_count()}']
                            logging.info(f'\t\t{" ".join(cmd)}')
                            ec, out = run(
                                cmd,
                                workdir=build_dir,
                                environment={'CXXFLAGS': cxxflags}
                            )
                            logging.info(out)
                            assert ec == 0

                        else:  # Custom build
                            cflags = [
                                *[f'-I{incl}' for incl in include_dirs],
                                '--abigen', '-Wall'
                            ]
                            sources = [n.name for n in contract_node.resolve().glob('*.cpp')]
                            cmd = ['eosio-cpp', *cflags, '-o', f'build/{contract_node.name}.wasm', *sources]
                            logging.info(f'\t\t{" ".join(cmd)}')
                            ec, out = run(
                                cmd,
                                workdir=work_dir,
                                environment={'CXXFLAGS': cxxflags}
                            )
                            logging.info(out)

                            assert ec == 0

    def deploy_contracts(self):
        contracts = [
            node
            for node in Path('contracts').glob('*')
            if node.is_dir()
        ]
        for contract in contracts:
            logging.info(f'contract {contract.name}:')

            # Create account for contract
            logging.info('\tcreate account...')
            self.create_account('eosio', contract.name)
            logging.info('\taccount created')

            logging.info('\tgive .code permissions...')
            cmd = [
                'cleos', 'set', 'account', 'permission', contract.name,
                'active', '--add-code'
            ]
            ec, out = self.run(cmd)
            assert ec == 0
            logging.info('\tpermissions granted.')

            build_dir = f'/home/user/contracts/{contract.name}/build'

            ec, out = self.run(
                ['find', build_dir, '-type', 'f', '-name', '*.wasm']
            )
            logging.info(f'wasm candidates:\n{out}')
            wasms = out.rstrip().split('\n')

            # Fuzzy match all .wasm files, select one most similar to {contract.name} 
            matches = sorted(
                [Path(wasm) for wasm in wasms],
                key=lambda match: SequenceMatcher(
                    None, contract.name, match.stem).ratio(),
                reverse=True
            )
            if len(matches) == 0: 
                raise FileNotFoundError(
                    f'Couldn\'t find {contract.name}.wasm')

            wasm_path = matches[0]
            wasm_file = str(wasm_path).split('/')[-1]
            abi_file = wasm_file.replace('.wasm', '.abi')

            logging.info('deploy...')
            logging.info(f'wasm path: {wasm_path}')
            logging.info(f'wasm: {wasm_file}')
            logging.info(f'abi: {abi_file}')
            cmd = [
                'cleos', 'set', 'contract', contract.name,
                str(wasm_path.parent),
                wasm_file,
                abi_file,
                '-p', f'{contract.name}@active'
            ]
            retry = 1
            while retry < 4:
                logging.info(f'deplot attempt {retry}')

                ec, out = self.run(cmd)
                logging.info(out)
                    
                if ec == 0:
                    break

                retry += 1

            if ec == 0:
                logging.info('deployed')

    def create_key_pair(self):
        ec, out = self.run(['cleos', 'create', 'key', '--to-console'])
        assert ec == 0
        assert ('Private key' in out) and ('Public key' in out)
        lines = out.split('\n')
        logging.info(out)
        return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

    def import_key(self, private_key):
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', private_key]
        )
        logging.info(out)
        return ec

    def setup_wallet(self):
        """Create Development Wallet
        link: https://docs.telos.net/developers/platform/
        development-environment/create-development-wallet
        """

        # Step 1: Create a Wallet
        logging.info('create wallet...')
        ec, out = self.run(['cleos', 'wallet', 'create', '--to-console'])
        wallet_key = out.split('\n')[-2].strip('\"')
        logging.info('wallet created')

        assert ec == 0
        assert len(wallet_key) == 53

        # Step 2: Open the Wallet
        logging.info('open wallet...')
        ec, _ = self.run(['cleos', 'wallet', 'open'])
        assert ec == 0
        ec, out = self.run(['cleos', 'wallet', 'list'])
        assert ec == 0
        assert 'default' in out
        logging.info('wallet opened')

        # Step 3: Unlock it
        logging.info('unlock wallet...')
        ec, out = self.run(
            ['cleos', 'wallet', 'unlock', '--password', wallet_key]
        )
        assert ec == 0

        ec, out = self.run(['cleos', 'wallet', 'list'])
        assert ec == 0
        assert 'default *' in out
        logging.info('wallet unlocked')

        # Step 4:  Import keys into your wallet
        logging.info('import key...')
        ec, out = self.run(['cleos', 'wallet', 'create_key'])
        public_key = out.split('\"')[1]
        assert ec == 0
        assert len(public_key) == 53
        self.dev_wallet_pkey = public_key
        logging.info(f'imported {public_key}')

        # Step 5: Import the Development Key
        logging.info('import development key...')
        ec = self.import_key('5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3')
        assert ec == 0
        logging.info('imported dev key')

    def __enter__(self):
        self.setup_wallet()

        if not self.skip_build:
            self.build_contracts()
        
        self.deploy_contracts()

        return self

    def __exit__(self, type, value, traceback):
        ...

    def push_action(
        self,
        contract: str,
        action: str,
        args: 'List',
        permissions: str,
        retry: int = 2
    ):
        logging.info(f"push action: {action}({args}) as {permissions}")
        cmd = [
            'cleos', 'push', 'action', contract, action,
            json.dumps(args), '-p', permissions, '-j', '-f'
        ]
        for i in range(retry + 1):
            ec, out = self.run(cmd)
            try:
                out = json.loads(out)
                logging.info(collect_stdout(out))
                
            except (json.JSONDecodeError, TypeError):
                logging.error(f'\n{out}')
                logging.error(f'cmd line: {cmd}')

            if ec == 0:
                break

        return ec, out

    def create_account(
        self,
        owner: str,
        name: str,
        key: Optional[str] = None,
    ):
        if not key:
            key = self.dev_wallet_pkey
        ec, out = self.run(['cleos', 'create', 'account', owner, name, key])
        logging.info(out)
        assert ec == 0
        assert 'warning: transaction executed locally' in out
        return ec, out


    def get_table(
        self,
        account: str,
        scope: str,
        table: str,
        *args
    ) -> List[Dict]:
        done = False
        rows = []
        while not done:
            ec, out = self.run(
                ['cleos', 'get', 'table', account, scope, table, '-l', '1000', *args]
            )
            if ec != 0:
                logging.critical(out)
            assert ec == 0
            out = json.loads(out)
            rows.extend(out['rows']) 
            done = not out['more']

        return rows 

    def get_info(self):
        ec, out = self.run(['cleos', 'get', 'info'])
        assert ec == 0
        return json.loads(out)

    def new_account(self, name: Optional[str] = None):
        if name:
            account_name = name
        else:
            account_name = random_eosio_name()

        private_key, public_key = self.create_key_pair()
        self.import_key(private_key)
        self.create_account('eosio', account_name, public_key)
        return account_name

    """
    Token helpers
    """
    def get_token_stats(
        self,
        sym: str,
        token_contract='eosio.token'
    ) -> Dict:
        return self.get_table(
            token_contract,
            sym,
            'stat'
        )[0]

    def get_balance(
        self,
        account: str,
        token_contract='eosio.token'
    ) -> str:
        return self.get_table(
            token_contract,
            account,
            'accounts'
        )[0]['balance']

    def create_token(
        self,
        issuer: str,
        max_supply: str,
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'create',
            [issuer, max_supply],
            'eosio.token'
        )

    def issue_token(
        self,
        issuer: str,
        quantity: str,
        memo: str,
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'issue',
            [issuer, quantity, memo],
            f'{issuer}@active'
        )

    def transfer_token(
        self,
        _from: str,
        _to: str,
        quantity: str,
        memo: str,
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'transfer',
            [_from, _to, quantity, memo],
            f'{_from}@active'
        )

    def give_token(
        self,
        _to: str,
        quantity: str,
        memo: str = '',
        token_contract='eosio.token'
    ):
        return self.transfer_token(
            token_contract,
            _to,
            quantity,
            memo,
            token_contract=token_contract
        )


_additional_mounts = []

CONTRACTS_ROOTDIR = '/home/user/contracts'

def append_mount(target: str, source: str):
    _additional_mounts.append(
        Mount(
            target,
            str(Path(source).resolve()),
            'bind'
        )
    )


@pytest.fixture(scope='session')
def eosio_testnet(request):

    dockerctl = DockerCtl(request.config.option.dockerurl)
    dockerctl.client.ping()
    
    docker_mounts = [
        Mount(
            CONTRACTS_ROOTDIR,  # target
            str(Path('contracts').resolve()),  # source
            'bind'
        )
    ] + _additional_mounts  

    if dockerctl.client.info()['NCPU'] < 2:
        logging.warning('eosio-cpp needs at least 2 logical cores')
   
    with ExitStack() as stack:
        try:
            container = dockerctl.client.containers.get('guilledk/pytest-eosiocdt:vtestnet')

        except NotFound:
            containers = stack.enter_context(
                dockerctl.run(
                    'guilledk/pytest-eosiocdt:vtestnet',
                    mounts=docker_mounts,
                    publish_all_ports=True
                )
            )
            container = containers[0]
        
        yield stack.enter_context(
            EOSIOTestSession(container, request, dockerctl, docker_mounts)
        )
