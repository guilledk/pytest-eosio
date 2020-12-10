#!/usr/bin/env python3

import json
import string
import random
import subprocess

from typing import Optional
from pathlib import Path

import pytest
import psutil

from docker.types import Mount


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


class CLEOSWrapper:

    def __init__(self, container: Optional = None):
        self.container = container

    def run(self, *args, **kwargs):
        if self.container:
            if 'demux' in kwargs:
                ec, outs = self.container.exec_run(*args, **kwargs)
                stdout, stderr = outs
                return ec, stdout, stderr

            ec, out = self.container.exec_run(*args, **kwargs)
            return ec, out.decode('utf-8')
        else:
            pinfo = subprocess.run(*args, capture_output=True, encoding='utf-8', **kwargs)
            if 'demux' in kwargs:
                return pinfo.returncode, pinfo.stdout, pinfo.stderr
            return pinfo.returncode, pinfo.stdout

    def wallet_setup(self):
        """Create Development Wallet
        link: https://docs.telos.net/developers/platform/
        development-environment/create-development-wallet
        """

        # Step 1: Create a Wallet
        ec, out = self.run(['cleos', 'wallet', 'create', '--to-console'])
        wallet_key = out.split('\n')[-2].strip('\"')

        assert ec == 0
        assert len(wallet_key) == 53

        # Step 2: Open the Wallet
        ec, _ = self.run(['cleos', 'wallet', 'open'])
        assert ec == 0
        ec, out = self.run(['cleos', 'wallet', 'list'])
        assert ec == 0
        assert 'default' in out

        # Step 3: Unlock it
        ec, out = self.run(
            ['cleos', 'wallet', 'unlock', '--password', wallet_key]
        )
        assert ec == 0

        ec, out = self.run(['cleos', 'wallet', 'list'])
        assert ec == 0
        assert 'default *' in out

        # Step 4:  Import keys into your wallet
        ec, out = self.run(['cleos', 'wallet', 'create_key'])
        public_key = out.split('\"')[1]
        assert ec == 0
        assert len(public_key) == 53
        self.dev_wallet_pkey = public_key

        # Step 5: Import the Development Key
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3']
        )
        assert ec == 0

    def deploy_contracts(self, quick: bool = False):
        """Deploy Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """

        for node in Path('contracts').resolve().glob('*'):
            if node.is_dir():
                container_dir = f"/home/user/contracts/{node.name}"

                # Create account for contract
                cmd = [
                    'cleos', 'create', 'account', 'eosio', node.name,
                    self.dev_wallet_pkey, '-p', 'eosio@active'
                ]
                ec, out = self.run(cmd)
                print(f"Account creation: {' '.join(cmd)}")
                print(out)
                assert ec == 0

                workdir_param = {}
                if self.container:
                    workdir_param['workdir'] = container_dir
                    build_dir = f'{container_dir}/build'
                else:
                    node_dir = node.resolve()
                    workdir_param['cwd'] = node_dir
                    build_dir = f'{node_dir}/build'

                if not quick:
                    # Clean contract
                    ec, out = self.run(
                       ['make', 'clean'],
                        **workdir_param
                    )
                    assert ec == 0

                    # Build contract
                    ec, out = self.run(
                        ['make', 'build', '-j', str(psutil.cpu_count())],
                        **workdir_param
                    )
                    print("Build contract:")
                    print(out)
                    assert ec == 0

                # Deploy
                cmd = [
                    'cleos', 'set', 'contract', node.name,
                    build_dir,
                    f'{node.name}.wasm',
                    f'{node.name}.abi',
                    '-p', f'{node.name}@active'
                ]
                ec, out = self.run(cmd)
                print(f"Contract Deploy: {' '.join(cmd)}")
                print(out)
                assert ec == 0

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
                
            except json.JSONDecodeError:
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
        ec, out = self.run(
            ['cleos', 'create', 'account', owner, name, key]
        )
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
    ):
        ec, stdout, stderr = self.run(
            ['cleos', 'get', 'table', account, scope, table, *args],
            demux=True
        )
        if stderr:
            print(stderr)
        assert ec == 0
        return json.loads(stdout)

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
def eosio_testnet(dockerctl, request):
    if request.config.getoption("--native"):
        cleos_api = CLEOSWrapper()
        cleos_api.wallet_setup()
        cleos_api.deploy_contracts(quick=request.config.getoption("--quick"))

        yield cleos_api

    else:
        contracts_wd = Mount(
            CONTRACTS_ROOTDIR,  # target
            str(Path('contracts').resolve()),  # source
            'bind'
        )

        with dockerctl.run(
            'vtestnet:eosio',
            mounts=[contracts_wd] + _additional_mounts
        ) as containers:
            cleos_api = CLEOSWrapper(container=containers[0])
            cleos_api.wallet_setup()
            cleos_api.deploy_contracts(quick=request.config.getoption("--quick"))
        
            yield cleos_api