#!/usr/bin/env python3

import re
import time
import json
import string
import random
import logging
import subprocess

from queue import Queue, Empty
from typing import Optional, List, Dict
from hashlib import sha1
from pathlib import Path
from threading  import Thread
from subprocess import PIPE, STDOUT

import pytest
import psutil

from natsort import natsorted
from docker.types import Mount
from pytest_dockerctl import DockerCtl

from .sugar import collect_stdout, hash_file


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


def pytest_addoption(parser):
    parser.addoption(
        '--skip-build', action='store_true', default=False, help='dont\'t build contract'
    )
    parser.addoption(
        '--force-build', action='store_true', default=False, help='ignore .binfo files & build all contracts'
    )
    parser.addoption(
        '--native', action='store_true', default=False, help='run blockchain outside vm'
    )


class NodeOSException(Exception):
    ...


class CLEOSWrapper:

    def __init__(self, container: Optional = None):
        self.container = container

    def run(self, *args, **kwargs):
        if self.container:
            ec, out = self.container.exec_run(*args, **kwargs)
            return ec, out.decode('utf-8')
        else:
            if ('popen' in kwargs) and kwargs['popen']:
                del kwargs['popen']
                return subprocess.Popen(
                    *args,
                    stdout=PIPE, stderr=STDOUT, encoding='utf-8',
                    **kwargs
                )
            else:
                pinfo = subprocess.run(
                    *args, 
                    stdout=PIPE, stderr=STDOUT, encoding='utf-8',
                    **kwargs
                )
                return pinfo.returncode, pinfo.stdout

    def start_services(self):
        logging.info('starting eosio services...')
        logging.info('keosd start...')
        self.proc_keosd = subprocess.Popen(
            ['keosd'],
            stdout=PIPE, stderr=STDOUT, encoding='utf-8'
        )
        logging.info('nodeos start...')
        self.proc_nodeos = subprocess.Popen(
            [
                'nodeos', '-e', '-p', 'eosio',
                '--plugin', 'eosio::producer_plugin',
                '--plugin', 'eosio::producer_api_plugin',
                '--plugin', 'eosio::chain_api_plugin',
                '--plugin', 'eosio::http_plugin',
                '--plugin', 'eosio::history_plugin',
                '--plugin', 'eosio::history_api_plugin',
                '--filter-on=\"*\"',
                '--access-control-allow-origin=\"*\"',
                '--contracts-console',
                '--http-validate-host=false',
                '--verbose-http-errors'
            ], stdout=PIPE, stderr=STDOUT, encoding='utf-8'
        )

        def enqueue_output(out, queue):
            for line in out:
                queue.put(line)
            out.close()

        stdout_queue = Queue()
        reader_thread = Thread(
            target=enqueue_output,
            args=(self.proc_nodeos.stdout, stdout_queue)
        )
        reader_thread.daemon = True
        reader_thread.start()

        initalized = False
        init_timeout = 15  # seg
        start_time = time.time()
        while not initalized:
            try:
                line = stdout_queue.get(timeout=0.4)
                logging.info(line.rstrip())
            except Empty:
                if time.time() - start_time > init_timeout:
                    self.stop_services()
                    raise NodeOSException('init timeout')
                else:
                    continue
            else:
                initalized = 'Produced' in line

        logging.info('eosio services started.')

    def dump_services_output(self):
        outs, errs = self.proc_keosd.communicate(timeout=1)
        logging.error(f'keosd exit code: {self.proc_keosd.poll()}')
        logging.error('keosd outs:')
        logging.error(outs)
        logging.error('keosd errs:')
        logging.error(errs)

        outs, errs = self.proc_nodeos.communicate(timeout=1)
        logging.error(f'nodeos exit code: {self.proc_nodeos.poll()}')
        logging.error('nodeos outs:')
        logging.error(outs)
        logging.error('nodeos errs:')
        logging.error(errs)

    def stop_services(self):
        logging.info('stopping eosio services...')
        self.proc_nodeos.kill()
        self.proc_keosd.kill()
        logging.info('eosio services stopped.')

    def wallet_setup(self):
        """Create Development Wallet
        link: https://docs.telos.net/developers/platform/
        development-environment/create-development-wallet
        """

        # Step 1: Create a Wallet
        logging.info('create wallet...')
        ec, out = self.run(['cleos', 'wallet', 'create', '--to-console'])
        wallet_key = out.split('\n')[-2].strip('\"')
        logging.info('walet created')

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
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3']
        )
        assert ec == 0
        logging.info('imported dev key')

    def deploy_contracts(
        self,
        skip_build: bool = False,
        force_build: bool = False
    ):
        """Deploy Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """

        logging.info('start contract deployment...')
        for contract_node in Path('contracts').resolve().glob('*'):
            if contract_node.is_dir():
                container_dir = f'/home/user/contracts/{contract_node.name}'
                logging.info(f'contract {contract_node.name}:')

                # Create account for contract
                logging.info('\tcreate account...')
                cmd = [
                    'cleos', 'create', 'account', 'eosio', contract_node.name,
                    self.dev_wallet_pkey, '-p', 'eosio@active'
                ]
                ec, out = self.run(cmd)
                assert ec == 0
                logging.info('\taccount created')

                logging.info('\tgive .code permissions...')
                cmd = [
                    'cleos', 'set', 'account', 'permission', contract_node.name,
                    'active', '--add-code'
                ]
                ec, out = self.run(cmd)
                assert ec == 0
                logging.info('\tpermissions granted.')

                workdir_param = {}
                if self.container:
                    workdir_param['workdir'] = container_dir
                    build_dir = f'{container_dir}/build'
                else:
                    contract_node_dir = contract_node.resolve()
                    workdir_param['cwd'] = str(contract_node_dir)
                    build_dir = f'{contract_node_dir}/build'

                logging.info(f'\twork param: {workdir_param}')
                logging.info(f'\tbuild dir: \'{build_dir}\'')

                include_dirs = [
                    '.',
                    './include',
                    '../include',
                    '../../include',
                    '/usr/opt/eosio.cdt/1.7.0/include/',
                ]

                if not skip_build:

                    """Smart build system: only recompile contracts whose
                    code as  changed, to do this we hash  every file that
                    we can find that is used in compilation, we order the
                    hash list and then use each hash to compute a  global
                    hash.
                    """

                    binfo_path = contract_node / '.binfo'
                    with open(binfo_path, 'r') as build_info:
                        prev_hash = build_info.read()
                    
                    logging.info(f'prev hash: {prev_hash}')

                    # Reopen to truncate contents
                    with open(binfo_path, 'w') as build_info:
                        hashes = []
                        files_done = set()
                        files_todo = {
                            *[node.resolve() for node in contract_node.glob('*.cpp')],
                            *[node.resolve() for node in contract_node.glob('*.hpp')],
                            *[node.resolve() for node in contract_node.glob('*.c')],
                            *[node.resolve() for node in contract_node.glob('*.h')]
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

                    if (prev_hash != current_hash) or force_build:
                        logging.info('\tperform build...')
                        # Clean contract
                        logging.info('\t\tclean build')
                        ec, out = self.run(
                        ['rm', '-rf', build_dir]
                        )
                        assert ec == 0

                        # Make build dir
                        logging.info('\t\tmake build dir')
                        ec, out = self.run(
                            ['mkdir', '-p', 'build'],
                            **workdir_param
                        )
                        assert ec == 0

                        # Build contract
                        cflags = [
                            *[f'-I{incl}' for incl in include_dirs],
                            '--abigen', '-Wall'
                        ]
                        sources = [n.name for n in contract_node.resolve().glob('*.cpp')]
                        cmd = ['eosio-cpp', *cflags, '-o', f'build/{contract_node.name}.wasm', *sources]
                        logging.info(f'\t\t{" ".join(cmd)}')
                        if self.container:
                            ec, out = self.run(cmd, **workdir_param)
                            logging.info(out)
                        else:
                            cc_process = self.run(cmd, popen=True, **workdir_param)
                            for line in iter(lambda: cc_process.stdout.readline(), ''):
                                logging.info(f'\t\t\t{line.rstrip()}')
                                if cc_process.poll():
                                    break
                            
                            cc_process.wait(timeout=5)
                            ec = cc_process.poll()

                        assert ec == 0
    
                # Deploy
                logging.info('deploy...')
                cmd = [
                    'cleos', 'set', 'contract', contract_node.name,
                    build_dir,
                    f'{contract_node.name}.wasm',
                    f'{contract_node.name}.abi',
                    '-p', f'{contract_node.name}@active'
                ]
                ec, out = self.run(cmd)
                logging.info(out)
                assert ec == 0
                logging.info('deployed')

    def push_action(
        self,
        contract: str,
        action: str,
        args: 'List',
        permissions: str,
        retry: int = 2
    ):
        logging.info(f"push action: {action}({args}) as {permissions}")
        for i in range(retry):
            ec, out = self.run(
                [
                    'cleos', 'push', 'action', contract, action,
                    json.dumps(args), '-p', permissions, '-j', '-f'
                ]
            )
            try:
                out = json.loads(out)
                logging.info(collect_stdout(out))
                
            except (json.JSONDecodeError, TypeError):
                logging.error(f'\n{out}')

            if ec == 0:
                break

        return ec, out

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

    def create_account(
        self,
        owner: str,
        name: str,
        key: str,
    ):
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
            account_name = ''.join(
                random.choice(string.ascii_lowercase + '12345')
                for _ in range(12)
            )
        private_key, public_key = self.create_key_pair()
        self.import_key(private_key)
        self.create_account('eosio', account_name, public_key)
        return account_name

    """
    Token helpers
    """
    def get_token_stats(self, sym: str) -> Dict:
        return self.get_table(
            'eosio.token',
            sym,
            'stat'
        )[0]

    def get_balance(self, account: str) -> str:
        return self.get_table(
            'eosio.token',
            account,
            'accounts'
        )[0]['balance']

    def create_token(self, issuer: str, max_supply: str):
        return self.push_action(
            'eosio.token',
            'create',
            [issuer, max_supply],
            'eosio.token'
        )

    def issue_token(
        self,
        issuer: str,
        quantity: str,
        memo: str
    ):
        return self.push_action(
            'eosio.token',
            'issue',
            [issuer, quantity, memo],
            f'{issuer}@active'
        )

    def transfer_token(
        self,
        _from: str,
        _to: str,
        quantity: str,
        memo: str
    ):
        return self.push_action(
            'eosio.token',
            'transfer',
            [_from, _to, quantity, memo],
            f'{_from}@active'
        )

    def tlos_token_setup(self):
        max_supply = f'{21000000:.8f} TLOS'
        ec, _ = self.create_token('eosio.token', max_supply)
        assert ec == 0
        ec, _ = self.issue_token('eosio.token', max_supply, 'tlos_token_setup')
        assert ec == 0


@pytest.fixture(scope='session')
def eosio_testnet(request):
    if request.config.getoption('--native'):
        cleos_api = CLEOSWrapper()

        try:
            cleos_api.start_services()
            cleos_api.wallet_setup()
            cleos_api.deploy_contracts(
                skip_build=request.config.getoption('--skip-build'),
                force_build=request.config.getoption('--force-build')
            )
            
            yield cleos_api

            cleos_api.stop_services()

        except BaseException as ex:
            cleos_api.stop_services()
            cleos_api.dump_services_output()
            raise

    else:

        dockerctl = DockerCtl(request.config.option.dockerurl)
        dockerctl.client.ping()       

        contracts_wd = Mount(
            CONTRACTS_ROOTDIR,  # target
            str(Path('contracts').resolve()),  # source
            'bind'
        )

        with dockerctl.run(
            'guilledk/pytest-eosiocdt:vtestnet-eosio',
            mounts=[contracts_wd] + _additional_mounts
        ) as containers:
            cleos_api = CLEOSWrapper(container=containers[0])
            cleos_api.wallet_setup()
            cleos_api.deploy_contracts(
                skip_build=request.config.getoption('--skip-build'),
                force_build=request.config.getoption('--force-build')
            )
        
            yield cleos_api
