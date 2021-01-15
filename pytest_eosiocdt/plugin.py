#!/usr/bin/env python3

import time
import json
import string
import random
import logging
import subprocess

from queue import Queue, Empty
from typing import Optional, List, Dict
from pathlib import Path
from threading  import Thread
from subprocess import PIPE, STDOUT

import pytest
import psutil

from docker.types import Mount
from pytest_dockerctl import DockerCtl


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
        "--quick", action="store_true", default=False, help="dont't rebuild contract"
    )
    parser.addoption(
        "--native", action="store_true", default=False, help="run blockchain outside vm"
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

    def deploy_contracts(self, quick: bool = False):
        """Deploy Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """

        logging.info('start contract deployment...')
        for node in Path('contracts').resolve().glob('*'):
            if node.is_dir():
                container_dir = f'/home/user/contracts/{node.name}'
                logging.info(f'contract {node.name}:')

                # Create account for contract
                logging.info('\tcreate account...')
                cmd = [
                    'cleos', 'create', 'account', 'eosio', node.name,
                    self.dev_wallet_pkey, '-p', 'eosio@active'
                ]
                ec, out = self.run(cmd)
                assert ec == 0
                logging.info('\taccount created')

                workdir_param = {}
                if self.container:
                    workdir_param['workdir'] = container_dir
                    build_dir = f'{container_dir}/build'
                else:
                    node_dir = node.resolve()
                    workdir_param['cwd'] = str(node_dir)
                    build_dir = f'{node_dir}/build'

                logging.info(f'\twork param: {workdir_param}')
                logging.info(f'\tbuild dir: \'{build_dir}\'')

                if not quick:
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
                    cflags = ['-I.', '-I../../include', '--abigen']
                    sources = [n.name for n in node.resolve().glob('*.cpp')]
                    cmd = ['eosio-cpp', *cflags, '-o', f'build/{node.name}.wasm', *sources]
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
                    'cleos', 'set', 'contract', node.name,
                    build_dir,
                    f'{node.name}.wasm',
                    f'{node.name}.abi',
                    '-p', f'{node.name}@active'
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
        print(f"push action: {action}({args}) as {permissions}")
        for i in range(retry):
            ec, out = self.run(
                [
                    'cleos', 'push', 'action', contract, action,
                    json.dumps(args), '-p', permissions, '-j', '-f'
                ]
            )
            try:
                out = json.loads(out)
                print(json.dumps(out, indent=4, sort_keys=True))
                
            except (json.JSONDecodeError, TypeError):
                print(out)

            if ec == 0:
                break

        return ec, out

    def create_key_pair(self):
        ec, out = self.run(['cleos', 'create', 'key', '--to-console'])
        assert ec == 0
        assert ('Private key' in out) and ('Public key' in out)
        lines = out.split('\n')
        print(out)
        return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

    def import_key(self, private_key):
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', private_key]
        )
        print(out)
        return ec

    def create_account(
        self,
        owner: str,
        name: str,
        key: str,
    ):
        ec, out = self.run(['cleos', 'create', 'account', owner, name, key])
        print(out)
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


@pytest.fixture(scope="session")
def eosio_testnet(request):
    if request.config.getoption("--native"):
        cleos_api = CLEOSWrapper()

        try:
            cleos_api.start_services()
            cleos_api.wallet_setup()
            cleos_api.deploy_contracts(quick=request.config.getoption("--quick"))
            
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
            cleos_api.deploy_contracts(quick=request.config.getoption("--quick"))
        
            yield cleos_api
