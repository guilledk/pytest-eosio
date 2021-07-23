#!/usr/bin/env python3

import time
import json
import string
import random
import logging
import tarfile
import subprocess

from typing import Iterator, Optional, Union, Tuple, List, Dict
from pathlib import Path
from difflib import SequenceMatcher
from subprocess import PIPE, STDOUT
from contextlib import ExitStack

import toml
import pytest
import psutil
import requests

from docker.types import Mount
from pytest_dockerctl import DockerCtl, waitfor

from .sugar import (
    collect_stdout,
    hash_file,
    hash_dir,
    random_eosio_name,
    get_container,
    Asset,
    Symbol
)


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
    parser.addoption(
        '-I', '--include', action='append', default=[], help='add custom include location for contract build'
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
        self.custom_includes = request.config.getoption('--include')

        self.vtestnet = vtestnet
        self.dockerctl = dockerctl
        self.docker_mounts = docker_mounts

        self.user_keys = dict()
        self.manifest = {}

        self.sys_contracts_path = '/usr/opt/telos.contracts'
        self.sys_contracts = []

        self._sys_token_init = False

    def run(
        self,
        cmd: List[str],
        retry: int = 3,
        *args, **kwargs
    ):
        """Run command inside the virtual testnet docker container, warning:
            its normal for blockchain interactions to timeout so by default
            this method retries commands 3 times. ``retry=0`` should be passed
            to avoid retry.
        """

        for i in range(1, 2 + retry):
            ec, out = self.vtestnet.exec_run(cmd, *args, **kwargs)
            if ec == 0:
                break

            logging.warning(f'cmd run retry num {i}...')
                
        return ec, out.decode('utf-8')

    def open_process(
        self,
        cmd: List[str],
        **kwargs
    ):
        """Begin running the command inside the virtual container, return the
        internal docker process id, and a stream for the standard output.
        """
        exec_id = self.dockerctl.client.api.exec_create(self.vtestnet.id, cmd, **kwargs)
        exec_run = self.dockerctl.client.api.exec_start(exec_id=exec_id, stream=True)
        return exec_id, exec_run

    def wait_process(
        self,
        exec_id,
        exec_stream
    ):
        """Collect output from process stream, then inspect process and return
        exitcode.
        """
        out = ''
        for chunk in exec_stream:
            out += chunk.decode('utf-8')

        info = self.dockerctl.client.api.exec_inspect(exec_id)
        return info['ExitCode'], out

    def get_manifest(self):
        if self.manifest == {}:
            for sub_manifest_path in Path('contracts').glob('**/manifest.toml'):
                contract_node = sub_manifest_path.parent
                with open(sub_manifest_path, 'r') as sub_manifest_file:
                    sub_manifest = toml.loads(sub_manifest_file.read())
                    for contract, config in sub_manifest.items():                       
                        sub_manifest[contract]['dir'] = (
                            str(contract_node / config["dir"])
                            if 'dir' in config
                            else f'{contract_node}/{contract}'
                        )

                        splt_path = sub_manifest[contract]['dir'].split('/')
                        splt_path[0] = CONTRACTS_ROOTDIR
                        sub_manifest[contract]['cdir'] = '/'.join(splt_path)

                    self.manifest.update(sub_manifest)

        return self.manifest

    def build_contract(
        self,
        cdt_v,
        exit_stack,
        work_dir,
        includes=[]
    ):

        cdt = exit_stack.enter_context(
            get_container(
                self.dockerctl,
                'guilledk/pytest-eosiocdt',
                f'cdt-{cdt_v}',
                mounts=self.docker_mounts
            )
        )

        def run(cmd, **kwargs):
            exec_id = self.dockerctl.client.api.exec_create(cdt.id, cmd, **kwargs)
            exec_run = self.dockerctl.client.api.exec_start(exec_id=exec_id, stream=True)
            out = ''
            for line in exec_run:
                line = line.decode('utf-8')
                out += line
                logging.info(line.rstrip())

            info = self.dockerctl.client.api.exec_inspect(exec_id)
            return info['ExitCode'], out

        logging.info('\tperform build...')
        # Clean contract
        logging.info('\t\tclean build')
        ec, _ = run(['rm', '-rf', f'{work_dir}/build'])
        assert ec == 0

        # Make build dir
        logging.info('\t\tmake build dir')
        ec, _ = run(
            ['mkdir', '-p', 'build'],
            workdir=work_dir
        )
        assert ec == 0

        # Build contract
        _, is_cmake = run([
            'sh',
            '-c',
            f'test -f {work_dir}/CMakeLists.txt && echo True'
        ])
        if is_cmake == 'True\n':  #CMake
            cmd = [
                'cmake',
                f'-DSYS_CONTRACTS_DIR={self.sys_contracts_path}',
                f'-DCUSTOM_INCLUDES_DIR={CUSTOM_INCLUDES_DIR}',
                work_dir
            ]
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, _ = run(
                cmd,
                workdir=f'{work_dir}/build'
            )
            assert ec == 0

            cxxflags = ' '.join([f'-I{incl}' for incl in includes])
            logging.info(f'\t\tcxxflags: {cxxflags}')
            cmd = ['make', f'-j{psutil.cpu_count()}']
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, _ = run(
                cmd,
                workdir=f'{work_dir}/build',
                environment={'CXXFLAGS': cxxflags}
            )
            assert ec == 0

        else:
            raise FileNotFoundError(
                "Expected CMakeLists.txt file in the contract directory.")

    def build_contracts(self, default_cdt='1.6.3'):
        """Build Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """

        ec, out = self.run(
            ['sh', '-c', 'echo */include'],
            retry=0,
            workdir=f'{SYS_CONTRACTS_ROOTDIR}/contracts'
        )
        assert ec == 0

        include_dirs = [
            '.',
            './include',
            '../include',
            *[
                f'{SYS_CONTRACTS_ROOTDIR}/contracts/{path}'
                for path in out.rstrip().split(' ')
            ]
        ]
        self.sys_contracts = [
            path.replace('/include', '')
            for path in out.rstrip().split(' ')
        ]

        manifest = self.get_manifest() 

        with ExitStack() as stack:

            for contract_name, config in manifest.items():
                """Smart build system: only recompile contracts whose
                code as  changed, to do this we hash  every file that
                we can find that is used in compilation, we order the
                hash list and then use each hash to compute a  global
                hash.
                """
                contract_node = Path(config['dir'])
                binfo_path = contract_node / '.binfo'
                try:
                    with open(binfo_path, 'r') as build_info:
                        prev_hash = build_info.read()

                except FileNotFoundError:
                    prev_hash = None

                curr_hash = hash_dir(contract_node, includes=include_dirs)
                
                logging.info(f'prev hash: {prev_hash}')
                logging.info(f'curr hash: {curr_hash}')

                # Reopen to truncate contents
                with open(binfo_path, 'w') as build_info: 
                    build_info.write(curr_hash)

                if (prev_hash != curr_hash) or self.force_build:
                    self.build_contract(
                        manifest[contract_name]['cdt'],
                        stack,
                        config['cdir'],
                        includes=include_dirs
                    )

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
        logging.info(f'\tcmd: {cmd}')
        logging.info(f'\t{out}')
        assert ec == 0
        logging.info('\tpermissions granted.')

        ec, out = self.run(
            ['find', build_dir, '-type', 'f', '-name', '*.wasm'],
            retry=0
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
        
        logging.info('contract deploy: ')
        ec, out = self.run(cmd, retry=6)
        logging.info(out)

        if ec == 0:
            logging.info('deployed')

        else:
            raise AssertionError(f'Couldn\'t deploy {account_name} contract.')


    def boot_sequence(self):
        # https://developers.eos.io/welcome/latest/tutorials/bios-boot-sequence

        sys_contracts_mount = f'{SYS_CONTRACTS_ROOTDIR}/contracts'

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

        manifest = self.get_manifest()

        for contract_name, config in manifest.items():
            acc_name = config['name'] if 'name' in config else None

            self.deploy_contract(
                contract_name, config['cdir'], account_name=acc_name)

    def create_key_pair(self):
        ec, out = self.run(['cleos', 'create', 'key', '--to-console'])
        assert ec == 0
        assert ('Private key' in out) and ('Public key' in out)
        lines = out.split('\n')
        logging.info('created key pair')
        return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

    def create_key_pairs(self, n: int):
        procs = [
            self.open_process(['cleos', 'create', 'key', '--to-console'])
            for _ in range(n)
        ]
        results = [
            self.wait_process(proc_id, proc_stream)
            for proc_id, proc_stream in procs
        ]
        keys = []
        for ec, out in results:
            assert ec == 0
            assert ('Private key' in out) and ('Public key' in out)
            lines = out.split('\n')
            keys.append((lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()))

        logging.info(f'created {n} key pairs')
        return keys

    def import_key(self, private_key: str):
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', private_key]
        )
        assert ec == 0
        logging.info('key imported')

    def import_keys(self, private_keys: List[str]):
        procs = [
            self.open_process(
                ['cleos', 'wallet', 'import', '--private-key', private_key])
            for private_key in private_keys
        ]
        results = [
            self.wait_process(proc_id, proc_stream)
            for proc_id, proc_stream in procs
        ]
        for ec, _ in results:
            assert ec == 0

        logging.info(f'imported {len(private_keys)} keys')

    def setup_wallet(self):
        """Create Development Wallet
        link: https://docs.telos.net/developers/platform/
        development-environment/create-development-wallet
        """

        # Step 1: Create a Wallet
        logging.info('create wallet...')
        ec, out = self.run(['cleos', 'wallet', 'create', '--to-console'])
        wallet_key = out.split('\n')[-2].strip('\"')
        assert ec == 0
        assert len(wallet_key) == 53
        logging.info('wallet created')

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
        self.import_key('5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3')
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
        args: List[str],
        permissions: str,
        retry=3
    ):
        args = [
            str(arg)
            if (
                isinstance(arg, Symbol) or
                isinstance(arg, Asset)
            )
            else arg
            for arg in args
        ]
        logging.info(f"push action: {action}({args}) as {permissions}")
        cmd = [
            'cleos', 'push', 'action', contract, action,
            json.dumps(args), '-p', permissions, '-j', '-f'
        ]
        ec, out = self.run(cmd, retry=retry)
        try:
            out = json.loads(out)
            logging.info(collect_stdout(out))
            
        except (json.JSONDecodeError, TypeError):
            logging.error(f'\n{out}')
            logging.error(f'cmd line: {cmd}')

        return ec, out

    def parallel_push_action(
        self,
        actions: Tuple[
            Iterator[str],   # contract name
            Iterator[str],   # action name
            Iterator[List],  # params
            Iterator[str]    # permissions
        ]
    ):
        procs = [
            self.open_process([
                'cleos', 'push', 'action', contract, action,
                json.dumps(args), '-p', permissions, '-j', '-f'
            ]) for contract, action, args, permissions in zip(*actions)
        ]
        return [
            self.wait_process(proc_id, proc_stream)
            for proc_id, proc_stream in procs
        ]

    def create_account(
        self,
        owner: str,
        name: str,
        key: Optional[str] = None,
    ):
        if not key:
            key = self.dev_wallet_pkey
        ec, out = self.run(['cleos', 'create', 'account', owner, name, key])
        assert ec == 0
        logging.info(f'created account: {name}')
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
        assert ec == 0
        logging.info(f'created staked account: {name}')
        return ec, out

    def create_accounts_staked(
        self,
        owner: str,
        names: List[str],
        keys: List[str],
        net: str = '1000.0000 SYS',
        cpu: str = '1000.0000 SYS',
        ram: int = 8192
    ):
        assert len(names) == len(keys)
        procs = [
            self.open_process([
                'cleos',
                'system',
                'newaccount',
                owner,
                '--transfer',
                name, key,
                '--stake-net', net,
                '--stake-cpu', cpu,
                '--buy-ram-kbytes', str(ram)
            ]) for name, key in zip(names, keys)
        ]
        results = [
            self.wait_process(proc_id, proc_stream)
            for proc_id, proc_stream in procs
        ]
        for ec, _ in results:
            assert ec == 0
        logging.info(f'created {len(names)} staked accounts.')

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

    def new_accounts(self, n: int):
        names = [random_eosio_name() for _ in range(n)]
        keys = self.create_key_pairs(n)
        self.import_keys([priv_key for priv_key, pub_key in keys])
        self.create_accounts_staked(
            'eosio', names, [pub_key for priv_key, pub_key in keys])
        return names

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

    def wait_blocks(self, n: int):
        start = self.get_info()['head_block_num']
        while (info := self.get_info())['head_block_num'] - start < n:
            time.sleep(0.1)

    def multi_sig_propose(
        self,
        proposer,
        req_permissions: List[str],  # [ 'name1@active', 'name2@active' ]
        tx_petmissions: List[str],
        contract,
        action_name,
        data
    ) -> str:

        proposal_name = random_eosio_name()
        cmd = [
            'cleos',
            'multisig',
            'propose',
            proposal_name,
            json.dumps([
                {'actor': perm[0], 'permission': perm[1]}
                for perm in [p.split('@') for p in req_permissions]
            ]),
            json.dumps([
                {'actor': perm[0], 'permission': perm[1]}
                for perm in [p.split('@') for p in tx_petmissions]
            ]),
            contract,
            action_name,
            json.dumps(data),
            '-p', proposer
        ]
        ec, out = self.run(cmd)
        assert ec == 0

        return proposal_name

    def multi_sig_approve(
        self,
        proposer,
        proposal_name,
        permissions,
        approver
    ):
        cmd = [
            'cleos',
            'multisig',
            'approve',
            proposer,
            proposal_name,
            *[
                json.dumps({'actor': perm[0], 'permission': perm[1]})
                for perm in [p.split('@') for p in permissions]
            ],
            '-p', approver
        ]
        ec, out = self.run(cmd)
        return ec, out

    def multi_sig_exec(
        self,
        proposer,
        proposal_name,
        permission,
        wait=3
    ):
        cmd = [
            'cleos',
            'multisig',
            'exec',
            proposer,
            proposal_name,
            '-p', permission
        ]
        ec, out = self.run(cmd)

        if ec == 0:
            self.wait_blocks(wait)

        return ec, out

    def multi_sig_review(
        self,
        proposer,
        proposal_name
    ):
        cmd = [
            'cleos',
            'multisig',
            'review',
            proposer,
            proposal_name
        ]
        ec, out =  self.run(cmd)
        return ec, out

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
        balances = self.get_table(
            token_contract,
            account,
            'accounts'
        )
        if len(balances) == 1:
            return balances[0]['balance']
        elif len(balances) > 1:
            return balances
        else:
            return None

    def create_token(
        self,
        issuer: str,
        max_supply: Union[str, Asset],
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'create',
            [issuer, str(max_supply)],
            'eosio.token'
        )

    def issue_token(
        self,
        issuer: str,
        quantity: Union[str, Asset],
        memo: str,
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'issue',
            [issuer, str(quantity), memo],
            f'{issuer}@active'
        )

    def transfer_token(
        self,
        _from: str,
        _to: str,
        quantity: Union[str, Asset],
        memo: str,
        token_contract='eosio.token'
    ):
        return self.push_action(
            token_contract,
            'transfer',
            [_from, _to, str(quantity), memo],
            f'{_from}@active'
        )

    def give_token(
        self,
        _to: str,
        quantity: Union[str, Asset],
        memo: str = '',
        token_contract='eosio.token'
    ):
        return self.transfer_token(
            token_contract,
            _to,
            str(quantity),
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


SYS_CONTRACTS_ROOTDIR = '/usr/opt/telos.contracts'
CONTRACTS_ROOTDIR = '/root/contracts'
CUSTOM_INCLUDES_DIR = '/root/includes'


@pytest.fixture(scope='session')
def eosio_testnet(request):

    dockerctl = DockerCtl(request.config.option.dockerurl)
    dockerctl.client.ping()
    
    docker_mounts = [
        Mount(
            CONTRACTS_ROOTDIR,  # target
            str(Path('contracts').resolve()),  # source
            'bind'
        ),
        *[Mount(
            f'{CUSTOM_INCLUDES_DIR}/{i}',
            str(Path(inc_dir).resolve()),
            'bind'
        ) for i, inc_dir in enumerate(request.config.getoption('--include'))],
        Mount(
            SYS_CONTRACTS_ROOTDIR,
            'pytest-eosiocdt.syscontracts'
        )
    ]

    if dockerctl.client.info()['NCPU'] < 2:
        logging.warning('eosio-cpp needs at least 2 logical cores')
   
    with get_container(
        dockerctl,
        'guilledk/pytest-eosiocdt',
        'vtestnet',
        mounts=docker_mounts,
        publish_all_ports=True
    ) as container:
        with EOSIOTestSession(container, request, dockerctl, docker_mounts) as session:
            yield session
