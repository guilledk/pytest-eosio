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


@pytest.fixture(scope="session")
def eosio_testnet(dockerctl, request):

    contracts_dir = Path('contracts').resolve()

    if request.config.getoption("--native"):
        """Create Development Wallet
        link: https://docs.telos.net/developers/platform/
        development-environment/create-development-wallet
        """

        class NativeAPI:
            ...

        native_api = NativeAPI()

        # Step 1: Create a Wallet
        pinfo = subprocess.run(
            ['cleos', 'wallet', 'create', '--to-console'],
            capture_output=True, encoding='utf-8'
        )
        wallet_key = pinfo.stdout.split('\n')[-2].strip('\"')

        assert pinfo.returncode == 0
        assert len(wallet_key) == 53

        # Step 2: Open the Wallet
        pinfo = subprocess.run(['cleos', 'wallet', 'open'])
        assert pinfo.returncode == 0
        pinfo = subprocess.run(
            ['cleos', 'wallet', 'list'],
            capture_output=True, encoding='utf-8'
        )
        assert 'default' in pinfo.stdout

        # Step 3: Unlock it
        pinfo = subprocess.run(
            ['cleos', 'wallet', 'unlock', '--password', wallet_key]
        )
        assert pinfo.returncode == 0

        pinfo = subprocess.run(
            ['cleos', 'wallet', 'list'],
            capture_output=True, encoding='utf-8'
        )
        assert 'default *' in pinfo.stdout

        # Step 4:  Import keys into your wallet
        pinfo = subprocess.run(
            ['cleos', 'wallet', 'create_key'],
            capture_output=True, encoding='utf-8'
        )
        public_key = pinfo.stdout.split('\"')[1]
        assert pinfo.returncode == 0
        assert len(public_key) == 53
        native_api.dev_wallet_pkey = public_key

        # Step 5: Import the Development Key
        pinfo = subprocess.run(
            ['cleos', 'wallet', 'import', '--private-key', '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3']
        )
        assert pinfo.returncode == 0

        """Deploy Contracts
        link: https://developers.eos.io/welcome/latest/
        getting-started/smart-contract-development/hello-world
        """

        for node in contracts_dir.glob('*'):
            if node.is_dir():

                node_full_dir = node.resolve()

                # Create account for contract
                cmd = [
                    'cleos', 'create', 'account', 'eosio', node.name,
                    native_api.dev_wallet_pkey, '-p', 'eosio@active'
                ]
                pinfo = subprocess.run(cmd, capture_output=True, encoding='utf-8')
                print(f"Account creation: {' '.join(cmd)}")
                print(pinfo.stdout)
                assert pinfo.returncode == 0

                if not request.config.getoption("--quick"):
                    # Clean contract
                    pinfo = subprocess.run(
                       ['make', 'clean'],
                        cwd=node_full_dir
                    )
                    assert pinfo.returncode == 0

                    # Build contract
                    pinfo = subprocess.run(
                        ['make', 'build', '-j', str(psutil.cpu_count())],
                        cwd=node_full_dir, capture_output=True, encoding='utf-8'
                    )
                    print("Build contract:")
                    print(pinfo.stdout)
                    assert pinfo.returncode == 0

                # Deploy
                cmd = [
                    'cleos', 'set', 'contract', node.name,
                    f"{node_full_dir}/build",
                    f"{node.name}.wasm",
                    f"{node.name}.abi",
                    '-p', f"{node.name}@active"
                ]
                pinfo = subprocess.run(cmd, capture_output=True, encoding='utf-8')
                print(f"Contract Deploy: {' '.join(cmd)}")
                print(pinfo.stdout)
                assert pinfo.returncode == 0

        # for syntactic sugar
        def _push_action(
            contract: str,
            action: str,
            args: 'List',
            permissions: str,
            retry: int = 2
        ):
            print(f"push action: {action}({args}) as {permissions}")
            for i in range(retry):
                pinfo = subprocess.run(
                    [
                        'cleos', 'push', 'action', contract, action,
                        json.dumps(args), '-p', permissions, '-j', '-f'
                    ], capture_output=True, encoding='utf-8'
                )
                try:
                    out = json.loads(pinfo.stdout)
                    print(json.dumps(out, indent=4, sort_keys=True))
                    
                except json.JSONDecodeError:
                    print(pinfo.stdout)

                if pinfo.returncode == 0:
                    break

            return pinfo.returncode, out

        def _create_key_pair():
            pinfo = subprocess.run(
                ['cleos', 'create', 'key', '--to-console'],
                capture_output=True, encoding='utf-8'
            )
            assert pinfo.returncode == 0
            assert ('Private key' in pinfo.stdout) and ('Public key' in pinfo.stdout)
            lines = pinfo.stdout.split('\n')
            print(pinfo.stdout)
            return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

        def _import_key(private_key):
            pinfo = subprocess.run(
                ['cleos', 'wallet', 'import', '--private-key', private_key],
                capture_output=True, encoding='utf-8'
            )
            print(pinfo.stdout)
            return pinfo.returncode

        def _create_account(
            owner: str,
            name: str,
            key: str,
        ):
            pinfo = subprocess.run(
                ['cleos', 'create', 'account', owner, name, key],
                capture_output=True, encoding='utf-8'
            )
            print(pinfo.stdout)
            assert pinfo.returncode == 0
            assert 'warning: transaction executed locally' in pinfo.stdout
            return pinfo.returncode, pinfo.stdout


        def _get_table(
            account: str,
            scope: str,
            table: str,
            *args
        ):
            pinfo = subprocess.run(
                ['cleos', 'get', 'table', account, scope, table, *args],
                capture_output=True, encoding='utf-8'
            )
            print(pinfo.stderr)
            assert pinfo.returncode == 0
            return json.loads(pinfo.stdout)

        def _get_info():
            pinfo = subprocess.run(
                ['cleos', 'get', 'info'],
                capture_output=True, encoding='utf-8'
            )
            assert pinfo.returncode == 0
            return json.loads(pinfo.stdout)


        native_api.push_action = _push_action
        native_api.create_key_pair = _create_key_pair
        native_api.import_key = _import_key
        native_api.create_account = _create_account
        native_api.get_table = _get_table
        native_api.get_info = _get_info

        def _new_account(name: Optional[str] = None):
            if name:
                account_name = name
            else:
                account_name = ''.join(
                    random.choice(string.ascii_lowercase + '12345')
                    for _ in range(12)
                )
            private_key, public_key = native_api.create_key_pair()
            native_api.import_key(private_key)
            native_api.create_account('eosio', account_name, public_key)
            return account_name

        native_api.new_account = _new_account

        yield native_api  

    else:
        contracts_wd = Mount(
            CONTRACTS_ROOTDIR,  # target
            str(contracts_dir),  # source
            'bind'
        )

        with dockerctl.run(
            'vtestnet:eosio',
            mounts=[contracts_wd] + _additional_mounts
        ) as containers:
            container = containers[0]

            """Create Development Wallet
            link: https://docs.telos.net/developers/platform/
            development-environment/create-development-wallet
            """

            # Step 1: Create a Wallet
            ec, out = container.exec_run(
                'cleos wallet create --to-console'
            )
            wallet_key = out.split(b'\n')[-2].decode('utf-8').strip('\"')

            assert ec == 0
            assert len(wallet_key) == 53

            # Step 2: Open the Wallet
            ec, _ = container.exec_run('cleos wallet open')
            assert ec == 0
            ec, out = container.exec_run('cleos wallet list')
            assert b'default' in out

            # Step 3: Unlock it
            ec, out = container.exec_run(
                ['cleos', 'wallet', 'unlock', '--password', wallet_key]
            )
            assert ec == 0

            ec, out = container.exec_run('cleos wallet list')
            assert ec == 0
            assert b'default *' in out

            # Step 4:  Import keys into your wallet
            ec, out = container.exec_run('cleos wallet create_key')
            public_key = out.decode('utf-8').split('\"')[1]
            assert ec == 0
            assert len(public_key) == 53
            container.dev_wallet_pkey = public_key

            # Step 5: Import the Development Key
            ec, out = container.exec_run(
                ['cleos', 'wallet', 'import', '--private-key', '5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3']
            )
            assert ec == 0

            """Deploy Contracts
            link: https://developers.eos.io/welcome/latest/
            getting-started/smart-contract-development/hello-world
            """

            for node in contracts_dir.glob('*'):
                if node.is_dir():
                    container_dir = f"/home/user/contracts/{node.name}"

                    # Create account for contract
                    cmd = [
                        'cleos', 'create', 'account', 'eosio', node.name,
                        container.dev_wallet_pkey, '-p', 'eosio@active'
                    ]
                    ec, out = container.exec_run(cmd)
                    print(f"Account creation: {' '.join(cmd)}")
                    print(out.decode('utf-8'))
                    assert ec == 0

                    if not request.config.getoption("--quick"):
                        # Clean contract
                        ec, out = container.exec_run(
                           ['make', 'clean'],
                            workdir=container_dir
                        )
                        assert ec == 0

                        # Build contract
                        ec, out = container.exec_run(
                            ['make', 'build', '-j', str(psutil.cpu_count())],
                            workdir=container_dir
                        )
                        print("Build contract:")
                        print(out.decode('utf-8'))
                        assert ec == 0

                    # Deploy
                    cmd = [
                        'cleos', 'set', 'contract', node.name,
                        f"{container_dir}/build",
                        f"{node.name}.wasm",
                        f"{node.name}.abi",
                        '-p', f"{node.name}@active"
                    ]
                    ec, out = container.exec_run(cmd)
                    print(f"Contract Deploy: {' '.join(cmd)}")
                    print(out.decode('utf-8'))
                    assert ec == 0

            # for syntactic sugar
            def _push_action(
                contract: str,
                action: str,
                args: 'List',
                permissions: str,
                retry: int = 2
            ):
                print(f"push action: {action}({args}) as {permissions}")
                for i in range(retry):
                    ec, out = container.exec_run(
                        [
                            'cleos', 'push', 'action', contract, action,
                            json.dumps(args), '-p', permissions, '-j', '-f'
                        ]
                    )
                    try:
                        out = json.loads(out.decode('utf-8'))
                        print(json.dumps(out, indent=4, sort_keys=True))
                        
                    except json.JSONDecodeError:
                        print(out.decode('utf-8'))

                    if ec == 0:
                        break

                return ec, out

            def _create_key_pair():
                ec, out = container.exec_run('cleos create key --to-console')
                assert ec == 0
                assert b'Private key' in out and b'Public key' in out
                lines = out.decode('utf-8').split('\n')
                print(out.decode('utf-8'))
                return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

            def _import_key(private_key):
                ec, out = container.exec_run(
                    ['cleos', 'wallet', 'import', '--private-key', private_key]
                )
                print(out.decode('utf-8'))
                return ec

            def _create_account(
                owner: str,
                name: str,
                key: str,
            ):
                ec, out = container.exec_run(
                    ['cleos', 'create', 'account', owner, name, key]
                )
                print(out.decode('utf-8'))
                assert ec == 0
                assert b'warning: transaction executed locally' in out
                return ec, out


            def _get_table(
                account: str,
                scope: str,
                table: str,
                *args
            ):
                ec, outs = container.exec_run(
                    ['cleos', 'get', 'table', account, scope, table, *args],
                    demux=True
                )
                stdout, stderr = outs
                if stderr:
                    print(stderr.decode('utf-8'))
                assert ec == 0
                return json.loads(stdout.decode('utf-8'))

            def _get_info():
                ec, out = container.exec_run('cleos get info')
                assert ec == 0
                return json.loads(out.decode('utf-8'))


            container.push_action = _push_action
            container.create_key_pair = _create_key_pair
            container.import_key = _import_key
            container.create_account = _create_account
            container.get_table = _get_table
            container.get_info = _get_info

            def _new_account(name: Optional[str] = None):
                if name:
                    account_name = name
                else:
                    account_name = ''.join(
                        random.choice(string.ascii_lowercase + '12345')
                        for _ in range(12)
                    )
                private_key, public_key = container.create_key_pair()
                container.import_key(private_key)
                container.create_account('eosio', account_name, public_key)
                return account_name

            container.new_account = _new_account

            yield container