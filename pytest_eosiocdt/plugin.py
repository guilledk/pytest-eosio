#!/usr/bin/env python3

import re
import time
import json
import string
import random
import logging
import tarfile
import subprocess

from typing import Optional, List, Dict
from hashlib import sha1
from pathlib import Path
from difflib import SequenceMatcher
from subprocess import PIPE, STDOUT
from contextlib import ExitStack

import pytest
import psutil
import requests

from natsort import natsorted
from docker.types import Mount
from docker.errors import NotFound
from pytest_dockerctl import DockerCtl, waitfor

from .sugar import collect_stdout, hash_file, random_eosio_name


PLUGIN_PREFIX = 'contracts/.pytest-eosiocdt'


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

        self.sys_contracts_path = '/usr/opt/telos.contracts'
        self.sys_contracts = []

        self._sys_token_init = False

    def run(self, *args, **kwargs):
        ec, out = self.vtestnet.exec_run(*args, **kwargs)
        return ec, out.decode('utf-8')

    def build_contract(
        self,
        cdt,
        contract_name,
        work_dir,
        includes=[]
    ):

        def run(*args, **kwargs):
            ec, out = cdt.exec_run(*args, **kwargs)
            return ec, out.decode('utf-8')

        logging.info('\tperform build...')
        # Clean contract
        logging.info('\t\tclean build')
        ec, out = run(
            ['rm', '-rf', f'{work_dir}/build']
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
        _, is_cmake = run([
            'sh',
            '-c',
            f'test -f {work_dir}/CMakeLists.txt && echo True'
        ])
        if is_cmake == 'True\n':  #CMake
            cxxflags = ' '.join([f'-I{incl}' for incl in includes])
        
            cmd = ['cmake', work_dir]
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, out = run(
                cmd,
                workdir=f'{work_dir}/build',
                environment={'CXXFLAGS': cxxflags}
            )
            logging.info(out)
            assert ec == 0

            cmd = ['make', f'-j{psutil.cpu_count()}']
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, out = run(
                cmd,
                workdir=f'{work_dir}/build',
                environment={'CXXFLAGS': cxxflags}
            )
            logging.info(out)
            assert ec == 0

        else:  # Custom build
            assert contract_name
            cxxflags = [
                *[f'-I{incl}' for incl in includes],
                '--abigen', '-Wall'
            ]
            ec, sources = run(
                ['find', '.', '-type', 'f',
                    '-name', '*.cpp', '-o',
                    '-name', '*.cc', '-o',
                    '-name', '*.c'],
                workdir=work_dir
            )
            sources = sources.split('\n') 
            cmd = [
                'eosio-cpp', *cxxflags, '-o', f'build/{contract_name}.wasm', *sources
            ]
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, out = run(
                cmd,
                workdir=work_dir,
                environment={'CXXFLAGS': cxxflags}
            )
            logging.info(out)

            assert ec == 0

    def build_contracts(self):
        """Build Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """
        with self.dockerctl.run(
            'guilledk/pytest-eosiocdt:cdt',
            mounts=self.docker_mounts
        ) as containers:

            cdt = containers[0]

            def run(*args, **kwargs):
                ec, out = cdt.exec_run(*args, **kwargs)
                return ec, out.decode('utf-8')

            ec, out = run(
                ['sh', '-c', 'echo */'],
                workdir=f'{self.sys_contracts_path}/contracts'
            )
            assert ec == 0
            self.sys_contracts = [path[:path.find('/')] for path in out.split(' ')]
            include_dirs = [
                '.',
                './include',
                '../include',
                '../../include',
                *[
                    f'{self.sys_contracts_path}/contracts/{contract}/include'
                    for contract in self.sys_contracts
                ]
            ]

            # build user contracts
            for contract_node in Path('contracts').resolve().glob('*'):
                if (contract_node.is_dir() and
                        contract_node.name != '.pytest-eosiocdt'):
                    work_dir = f'/home/user/contracts/{contract_node.name}'

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
                        self.build_contract(
                            containers[0],
                            contract_node.name,
                            work_dir,
                            includes=include_dirs
                        )

            # save sys contracts wasm & abi from cdt container
            plugin_path = Path(PLUGIN_PREFIX)
            plugin_path.mkdir(exist_ok=True)

            for contract in self.sys_contracts:
                try:
                    (plugin_path / contract).mkdir()
                except FileExistsError:
                    continue

                with open(plugin_path / contract / 'wasm.tar', 'wb') as f_wasm:
                    bits, stat = cdt.get_archive(
                        f'{self.sys_contracts_path}/contracts/{contract}/{contract}.wasm'
                    )
                    for chunk in bits:
                        f_wasm.write(chunk)

                with tarfile.open(
                    plugin_path / contract / 'wasm.tar', mode='r:'
                ) as tar_wasm:
                    tar_wasm.extractall(path=plugin_path / contract)
                Path(plugin_path / contract / 'wasm.tar').unlink()

                with open(plugin_path / contract / 'abi.tar', 'wb') as f_abi:
                    bits, stat = cdt.get_archive(
                        f'{self.sys_contracts_path}/contracts/{contract}/{contract}.abi'
                    )
                    for chunk in bits:
                        f_abi.write(chunk)

                with tarfile.open(
                    plugin_path / contract / 'abi.tar', mode='r:'
                ) as tar_abi:
                    tar_abi.extractall(path=plugin_path / contract)
                Path(plugin_path / contract / 'abi.tar').unlink()

    def deploy_contract(
        self,
        contract_name,
        build_dir,
        privileged=False,
        account_name=None,
        create_account=True,
        staked=True
    ):
        logging.info(f'contract {contract_name}:')

        account_name = contract_name if not account_name else account_name

        if create_account:
            logging.info('\tcreate account...')
            if staked:
                self.create_account_staked('eosio', account_name)
            else:
                self.create_account('eosio', account_name)
            logging.info('\taccount created')

        if privileged:
            self.push_action(
                'eosio', 'setpriv',
                [account_name, 1],
                'eosio@active'
            )

        logging.info('\tgive .code permissions...')
        cmd = [
            'cleos', 'set', 'account', 'permission', account_name,
            'active', '--add-code'
        ]
        ec, out = self.run(cmd)
        assert ec == 0
        logging.info('\tpermissions granted.')

        ec, out = self.run(
            ['find', build_dir, '-type', 'f', '-name', '*.wasm']
        )
        logging.info(f'wasm candidates:\n{out}')
        wasms = out.rstrip().split('\n')

        # Fuzzy match all .wasm files, select one most similar to {contract.name} 
        matches = sorted(
            [Path(wasm) for wasm in wasms],
            key=lambda match: SequenceMatcher(
                None, contract_name, match.stem).ratio(),
            reverse=True
        )
        if len(matches) == 0: 
            raise FileNotFoundError(
                f'Couldn\'t find {contract_name}.wasm')

        wasm_path = matches[0]
        wasm_file = str(wasm_path).split('/')[-1]
        abi_file = wasm_file.replace('.wasm', '.abi')

        logging.info('deploy...')
        logging.info(f'wasm path: {wasm_path}')
        logging.info(f'wasm: {wasm_file}')
        logging.info(f'abi: {abi_file}')
        cmd = [
            'cleos', 'set', 'contract', account_name,
            str(wasm_path.parent),
            wasm_file,
            abi_file,
            '-p', f'{account_name}@active'
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

    def boot_sequence(self):
        # https://developers.eos.io/welcome/latest/tutorials/bios-boot-sequence

        sys_contracts_mount = '/home/user/contracts/.pytest-eosiocdt'

        for name in [
            'eosio.bpay',
            'eosio.names',
            'eosio.ram',
            'eosio.ramfee',
            'eosio.saving',
            'eosio.stake',
            'eosio.vpay',
            'eosio.rex'
        ]:
            ec, _ = self.create_account('eosio', name)
            assert ec == 0 

        self.deploy_contract(
            'eosio.token',
            f'{sys_contracts_mount}/eosio.token',
            staked=False
        )

        self.deploy_contract(
            'eosio.msig',
            f'{sys_contracts_mount}/eosio.msig',
            staked=False
        )

        self.deploy_contract(
            'eosio.wrap',
            f'{sys_contracts_mount}/eosio.wrap',
            staked=False
        )

        self.init_sys_token()

        self.activate_feature_v1('PREACTIVATE_FEATURE')

        self.deploy_contract(
            'eosio.system',
            f'{sys_contracts_mount}/eosio.system',
            account_name='eosio',
            create_account=False
        )

        self.activate_feature('ONLY_BILL_FIRST_AUTHORIZER')
        self.activate_feature('RAM_RESTRICTIONS')

        ec, _ = self.push_action(
            'eosio', 'setpriv',
            ['eosio.msig', 1],
            'eosio@active'
        )
        assert ec == 0

        ec, _ = self.push_action(
            'eosio', 'init',
            ['0', '4,SYS'],
            'eosio@active'
        )
        assert ec == 0

        # ec, _ = self.buy_ram_bytes('eosio', 1000000000)
        # assert ec == 0

        contracts = [
            node
            for node in Path('contracts').glob('*')
            if node.is_dir() and node.name != '.pytest-eosiocdt'
        ] 
        for contract in contracts:
            self.deploy_contract(
                contract.name,
                f'/home/user/contracts/{contract.name}'
            )

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

    def get_feature_digest(self, feature_name):
        r = requests.post(
            f'{self.endpoint}/v1/producer/get_supported_protocol_features',
            json={}
        )
        for item in r.json():
            if item['specification'][0]['value'] == feature_name:
                digest = item['feature_digest']
                break
        else:
            raise ValueError(f'{feature_name} feature not found.')

        logging.info(f'{feature_name} digest: {digest}')
        return digest

    def activate_feature_v1(self, feature_name):
        digest = self.get_feature_digest(feature_name)
        logging.info(f'activating {feature_name}...')
        r = requests.post(
            f'{self.endpoint}/v1/producer/schedule_protocol_feature_activations',
            json={
                'protocol_features_to_activate': [digest]
            }
        ).json()
        
        logging.info(json.dumps(r, indent=4))

        assert 'result' in r
        assert r['result'] == 'ok'

        logging.info(f'{digest} active.')

    def activate_feature(self, feature_name):
        logging.info(f'activating {feature_name}...')
        digest = self.get_feature_digest(feature_name)
        ec, _ = self.push_action(
            'eosio', 'activate',
            [digest],
            'eosio@active'
        )
        assert ec == 0
        logging.info(f'{digest} active.')

    def __enter__(self):
        self.setup_wallet()

        if not self.skip_build:
            self.build_contracts()
        
        self.boot_sequence()

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

    def create_account_staked(
        self,
        owner: str,
        name: str,
        net: str = '1000.0000 SYS',
        cpu: str = '1000.0000 SYS',
        ram: int = 8192,
        key: Optional[str] = None
    ):
        if not key:
            key = self.dev_wallet_pkey
        ec, out = self.run([
            'cleos',
            'system',
            'newaccount',
            owner,
            '--transfer',
            name, key,
            '--stake-net', net,
            '--stake-cpu', cpu,
            '--buy-ram-kbytes', str(ram)
        ])
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
            ec, out = self.run([
                'cleos', 'get', 'table',
                account, scope, table,
                '-l', '1000', *args
            ])
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

    def get_resources(self, account: str):
        return self.get_table('eosio', account, 'userres')

    def new_account(self, name: Optional[str] = None):
        if name:
            account_name = name
        else:
            account_name = random_eosio_name()

        private_key, public_key = self.create_key_pair()
        self.import_key(private_key)
        self.create_account_staked('eosio', account_name, key=public_key)
        return account_name

    def buy_ram_bytes(
        self,
        payer,
        amount,
        receiver=None
    ):
        if not receiver:
            receiver = payer

        return self.push_action(
            'eosio', 'buyrambytes',
            [payer, receiver, amount],
            f'{payer}@active'
        )

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


    def init_sys_token(self):
        if not self._sys_token_init:
            self._sys_token_init = True
            max_supply = f'{10000000000:.4f} SYS'
            ec, _ = self.create_token('eosio', max_supply)
            assert ec == 0
            ec, _ = self.issue_token('eosio', max_supply, __name__)
            assert ec == 0

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
