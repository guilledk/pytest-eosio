#!/usr/bin/env python3

from __future__ import annotations

import sys
import time
import json
import select 
import string
import random
import logging
import tarfile
import subprocess

from sys import platform
from typing import Iterator, Optional, Union, Tuple, List, Dict
from pathlib import Path
from difflib import SequenceMatcher
from subprocess import PIPE, STDOUT
from contextlib import ExitStack

import toml
import pytest
import psutil
import requests

import _pytest

from docker.types import Mount
from docker.errors import DockerException
from docker.models.containers import Container

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

from .globals import (
    get_exit_stack,
    set_session,
    get_session
)

from .typing import (
    ExecutionResult, ExecutionStream, ActionResult
)


def pytest_addoption(parser):
    parser.addoption(
        '--endpoint', action='store', default='', help='blockchain api endpoint to target'
    )
    parser.addoption(
        '--sys-dir', action='store', default='/usr/opt/telos.contracts', help='system contracts dir'
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
    parser.addoption(
        '--keep-alive', action='store_true', default=False, help='after running test session, keep blockchain open'
    )


class EOSIOTestSession:
    """Main fixture used to access the testnet and manage the test session.
    """

    def __init__(
        self,
        vtestnet: Container,  # vtestnet container
        config: _pytest.config.Config,
        dockerctl: DockerCtl,
        docker_mounts: List[Mount]
    ):
        endpoint = config.getoption('--endpoint')
        if endpoint:
            self.endpoint = endpoint
        else:
            if platform == 'linux':
                container_port = 8888 
                self.endpoint = f'http://localhost:{container_port}'
                
            else:
                ports = waitfor(vtestnet, ('NetworkSettings', 'Ports', '8888/tcp'))
                container_port = ports[0]['HostPort']

                self.endpoint = f'http://localhost:{container_port}'

        self.skip_build = config.getoption('--skip-build')
        self.force_build = config.getoption('--force-build')
        self.custom_includes = config.getoption('--include')

        self.reporter = config.pluginmanager.get_plugin('terminalreporter')
        self.capture_manager = config.pluginmanager.get_plugin('capturemanager')

        self.vtestnet = vtestnet
        self.dockerctl = dockerctl
        self.docker_mounts = docker_mounts

        self.user_keys = dict()
        self.manifest = {}

        self.sys_contracts_path = config.getoption('--sys-dir') 
        self.sys_contracts = []

        self._sys_token_init = False

    def run(
        self,
        cmd: List[str],
        retry: int = 3,
        *args, **kwargs
    ) -> ExecutionResult:
        """Run command inside the virtual testnet docker container.

        :param cmd: Command and parameters separated in chunks in a list.
        :param retry: It's normal for blockchain interactions to timeout so by default
            this method retries commands 3 times. ``retry=0`` should be passed
            to avoid retry.
        :param args: This method calls ``container.exec_run`` docker APIs under the
            hood so you can pass extra arguments to it according to this (`docs
            <https://docker-py.readthedocs.io/en/stable/containers.html#docker.m
            odels.containers.Container.exec_run>`_).
        :param kwargs: Same as ``args`` but for keyword arguments.

        :return: A tuple with the process exitcode and output.
        :rtype: :ref:`typing_exe_result`
        """

        for i in range(1, 2 + retry):
            ec, out = self.vtestnet.exec_run(
                [str(chunk) for chunk in cmd], *args, **kwargs)
            if ec == 0:
                break

            logging.warning(f'cmd run retry num {i}...')
                
        return ec, out.decode('utf-8')

    def open_process(
        self,
        cmd: List[str],
        **kwargs
    ) -> ExecutionStream:
        """Begin running the command inside the virtual container, return the
        internal docker process id, and a stream for the standard output.

        :param cmd: List of individual string forming the command to execute in
            the testnet container shell.
        :param kwargs: A variable number of key word arguments can be
            provided, as this function uses `exec_create & exec_start docker APIs
            <https://docker-py.readthedocs.io/en/stable/api.html#module-dock
            er.api.exec_api>`_.

        :return: A tuple with the process execution id and the output stream to
            be consumed.
        :rtype: :ref:`typing_exe_stream`
        """
        exec_id = self.dockerctl.client.api.exec_create(self.vtestnet.id, cmd, **kwargs)
        exec_sock = self.dockerctl.client.api.exec_start(exec_id=exec_id, socket=True)
        exec_sock._sock.setblocking(False)
        return exec_id['Id'], exec_sock

    def wait_process(
        self,
        exec_id: str,
        exec_sock: Iterator[str],
        watchdog_timeout: float = 0.3
    ) -> ExecutionResult:
        """Collect output from process stream, then inspect process and return
        exitcode.

        Normaly used with :func:`~pytest_eosio.EOSIOTestSession.open_process`

        :param exec_id: Process execution id provided by docker engine.
        :param exec_stream: Process output stream to be consumed.

        :return: Exitcode and process output.
        :rtype: :ref:`typing_exe_result`
        """
        info = { 'Running': True }

        out = ''
        while info['Running']:
            ready = select.select([exec_sock._sock], [], [], watchdog_timeout)
            if ready[0]:
                raw = exec_sock.readline()
                # consume header
                raw = raw[8:]
                out += raw.decode('utf-8')

            info = self.dockerctl.client.api.exec_inspect(exec_id)

        return info['ExitCode'], out

    def get_manifest(self) -> Dict[str, str]:
        """Parse or return already parsed contract manifest.

        Will search on all subfolders inside ``contracts/`` dir for manifest
        files with toml format, with the name:

            ``manifest.toml``

        And will stich them up in one big dict.

        :return: A dictionary with contract account and source information.
        :rtype: Dict[str, str]
        """
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
        cdt_v: str,
        exit_stack: ExitStack,
        work_dir: str,
        includes: List[str] = []
    ):
        """Build an individual contract from a cmake project directory using a
        specific container.

        :param cdt_v: A string with the contract development kit version to use.
        :param exit_stack: The exit stack under which all builds are happening.
        :param work_dir: A string with the path to the project source directory.
        :param includes: A list of additional include paths to set in ``CXXFLAGS``
            environment variable.
        """

        cdt = exit_stack.enter_context(
            get_container(
                self.dockerctl,
                'guilledk/pytest-eosio',
                f'cdt-{cdt_v}',
                mounts=self.docker_mounts
            )
        )

        def run(cmd, **kwargs) -> Tuple[int, str]:
            exec_id = self.dockerctl.client.api.exec_create(cdt.id, cmd, **kwargs)
            exec_sock = self.dockerctl.client.api.exec_start(exec_id=exec_id, socket=True)

            info = { 'Running': True }
            exec_sock._sock.setblocking(False)
    
            out = ''
            while info['Running']:
                ready = select.select([exec_sock._sock], [], [], 0.3)
                if ready[0]:
                    raw = exec_sock.readline()
                    # consume header
                    raw = raw[8:]
                    chunk = raw.decode('utf-8')
                    logging.info(chunk.rstrip())
                    out += chunk

                info = self.dockerctl.client.api.exec_inspect(exec_id)
               
            logging.info(f'cmd: {" ".join(cmd)}')
            logging.info(out)

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
            cxxflags = ' '.join([f'-I{incl}' for incl in includes])
            logging.info(f'\t\tcxxflags: {cxxflags}')
            self.reporter.write("\tcmake... ", flush=True)
            cmd = [
                'cmake',
                f'-DSYS_CONTRACTS_DIR={self.sys_contracts_path}',
                f'-DCUSTOM_INCLUDES_DIR={CUSTOM_INCLUDES_DIR}',
                f'-DCMAKE_CXX_FLAGS={cxxflags}',
                work_dir
            ]
            logging.info(f'\t\t{" ".join(cmd)}')
            ec, _ = run(
                cmd, workdir=f'{work_dir}/build')
            assert ec == 0
            self.reporter.write(" done.\n", flush=True)

            cmd = ['make', 'VERBOSE=1', f'-j{psutil.cpu_count()}']
            logging.info(f'\t\t{" ".join(cmd)}')
            self.reporter.write("\tmake... ", flush=True)
            ec, _ = run(
                cmd,
                workdir=f'{work_dir}/build',
                environment={
                    'CXXFLAGS': cxxflags
                }
            )
            assert ec == 0
            self.reporter.write(" done.\n", flush=True)

        else:
            raise FileNotFoundError(
                "Expected CMakeLists.txt file in the contract directory.")

    def build_contracts(
        self,
        default_cdt: str = '1.6.3'
    ):
        """Build contracts in project folder.

        \"Smart\" build system: only recompile contracts whose code as  changed,
        to do this we hash  every file that we can find that is used in
        compilation, we order the hash list and then use each hash to compute a
        global hash.
        
        :param default_cdt: Default contract development toolkit version.
        """
            

        ec, out = self.run(
            ['sh', '-c', 'echo */include'],
            retry=0,
            workdir=f'{self.sys_contracts_path}/contracts'
        )
        assert ec == 0

        include_dirs = [
            '.',
            './include',
            '../include',
            *[
                f'{self.sys_contracts_path}/contracts/{path}'
                for path in out.rstrip().split(' ')
            ]
        ]
        self.sys_contracts = [
            path.replace('/include', '')
            for path in out.rstrip().split(' ')
        ]

        manifest = self.get_manifest() 

        with ExitStack() as stack:
            with self.capture_manager.global_and_fixture_disabled():
                self.sys_contracts_mount = self.sys_contracts_path + '/contracts'
                if self.sys_contracts_path != '/usr/opt/telos.contracts':
                    self.sys_contracts_mount = self.sys_contracts_path + '/build/contracts'
                    self.build_contract(
                        '1.6.3',
                        stack,
                        self.sys_contracts_path
                    )

                for contract_name, config in manifest.items():
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
                   
                    short_prev_hash = prev_hash[:8] if prev_hash else 'none'
                    short_curr_hash = curr_hash[:8] if curr_hash else 'none'

                    self.reporter.write(
                        f"contract: {contract_name}, hashes: {short_prev_hash}, {short_curr_hash}\n",
                        flush=True)

                    if (prev_hash != curr_hash) or self.force_build:
                        self.reporter.write("building...\n", flush=True)
                        self.build_contract(
                            manifest[contract_name]['cdt'],
                            stack,
                            config['cdir'],
                            includes=include_dirs
                        )

                        # write modified hash
                        with open(binfo_path, 'w') as build_info: 
                            build_info.write(curr_hash)

    def deploy_contract(
        self,
        contract_name: str,
        build_dir: str,
        privileged: bool = False,
        account_name: Optional[str] = None,
        create_account: bool = True,
        staked: bool = True
    ):
        """Deploy a built contract to an already.

        :param contract_name: Name of contract wasm file. 
        :param build_dir: Path to the directory the wasm and abi files are
            located. Fuzzy searches all subdirectories for the .wasm and then
            picks the one most similar to ``contract_name``, asumes .abi has
            the same name and is in same directory.
        :param privileged: ``True`` if contract should be privileged (system
            contracts).
        :param account_name: Name of the target account of the deployment.
        :param create_account: ``True`` if target account should be created.
        :param staked: ``True`` if this account should use RAM & NET resources.
        """
        logging.info(f'contract {contract_name}:')
        
        account_name = contract_name if not account_name else account_name

        self.reporter.write(f"deploying {account_name}...", flush=True)

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
            '-p', f'{account_name}@active', '-x', '90'
        ]
        
        logging.info('contract deploy: ')
        ec, out = self.run(cmd, retry=20)
        logging.info(out)

        if ec == 0:
            logging.info('deployed')
            self.reporter.write(f" done.\n", flush=True)

        else:
            raise AssertionError(f'Couldn\'t deploy {account_name} contract.')


    def boot_sequence(self):
        """Perform enterprise operating system bios sequence acording to:

            https://developers.eos.io/welcome/latest/tutorials/bios-boot-sequence

        This includes:

            1) Creating the following accounts:
            
                - ``eosio.bpay``
                - ``eosio.names``
                - ``eosio.ram``
                - ``eosio.ramfee``
                - ``eosio.saving``
                - ``eosio.stake``
                - ``eosio.vpay``
                - ``eosio.rex``

            2) Deploy the following contracts that come in vtestnet image:

                ``eosio.token``, ``eosio.msig``, ``eosio.wrap``

            3) Initialize the ``SYS`` token.
            4) Activate v1 feature ``PREACTIVATE_FEATURE``.
            5) Deploy ``eosio.system`` to ``eosio`` account.
            6) Activate v2 features ``ONLY_BILL_FIRST_AUTHORIZER`` and ``RAM_RESTRICTIONS``.
            7) Set ``eosio.msig`` account as privileged in order to delegate permissions.
            8) System init.
            9) Parse contract manifest and deploy user contracts.

        """

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
            f'{self.sys_contracts_mount}/eosio.token',
            staked=False
        )

        self.deploy_contract(
            'eosio.msig',
            f'{self.sys_contracts_mount}/eosio.msig',
            staked=False
        )

        self.deploy_contract(
            'eosio.wrap',
            f'{self.sys_contracts_mount}/eosio.wrap',
            staked=False
        )

        self.init_sys_token()

        self.activate_feature_v1('PREACTIVATE_FEATURE')

        self.deploy_contract(
            'eosio.system',
            f'{self.sys_contracts_mount}/eosio.system',
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

    def create_key_pair(self) -> Tuple[str, str]:
        """Generate a new EOSIO key pair.

        :return: Public and private key.
        :rtype: Tuple[str, str]
        """
        ec, out = self.run(['cleos', 'create', 'key', '--to-console'])
        assert ec == 0
        assert ('Private key' in out) and ('Public key' in out)
        lines = out.split('\n')
        logging.info('created key pair')
        return lines[0].split(' ')[2].rstrip(), lines[1].split(' ')[2].rstrip()

    def create_key_pairs(self, n: int) -> List[Tuple[str, str]]:
        """Generate ``n`` EOSIO key pairs, faster than calling
        :func:`~pytest_eosio.EOSIOTestSession.create_key_pair` on a loop.

        :return: List of key pairs with a length of ``n``.
        :rtype: List[Tuple[str, str]]
        """
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
        """Import a private key into wallet inside testnet container.
        """
        ec, out = self.run(
            ['cleos', 'wallet', 'import', '--private-key', private_key]
        )
        assert ec == 0
        logging.info('key imported')

    def import_keys(self, private_keys: List[str]):
        """Import a list of private keys into wallet inside testnet container.
        Faster than calling :func:`~pytest_eosio.EOSIOTestSession.import_key` on a loop.
        """
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
        """Setup wallet acording to `telos docs <https://docs.telos.net/develope
        rs/platform/development-environment/create-development-wallet>`_.
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

    def get_feature_digest(self, feature_name: str) -> str:
        """Given a feature name, query the v1 API endpoint: 
        
            ``/v1/producer/get_supported_protocol_features``

        to retrieve hash digest.

        :return: Feature hash digest.
        :rtype: str
        """
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

    def activate_feature_v1(self, feature_name: str):
        """Given a v1 feature name, activate it.
        """

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

    def activate_feature(self, feature_name: str):
        """Given a v2 feature name, activate it.
        """

        logging.info(f'activating {feature_name}...')
        digest = self.get_feature_digest(feature_name)
        ec, _ = self.push_action(
            'eosio', 'activate',
            [digest],
            'eosio@active'
        )
        assert ec == 0
        logging.info(f'{digest} active.')

    # python context manager proto 
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
        retry: int = 3
    ) -> ActionResult:
        """Execute an action defined in a given contract, in case of failure retry.

        :param contract: Contract were action is defined.
        :param action: Name of the action to execute.
        :param args: List of action arguments.
        :param permissions: Authority with which to sign this transaction.
        :param retry: Max amount of retries allowed, can be zero for no retries.

        :return: Always returns a tuple with the exit code at the beggining and
            depending if the transaction was exectued, either the resulting json dict,
            or the full output including errors as a string at the end.
        :rtype: :ref:`typing_action_result`
        """

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
    ) -> List[ActionResult]:
        """Push several actions in parallel and collect their results. 

        Example code:

        .. code-block:: python

            results = eosio_testnet.parallel_push_action((
                (contract for contract in contract_names),
                (action for action in action_names),
                (params for params in param_lists),
                (f'{auth}@active' for auth in authorities)
            ))
            for ec, _ in results:
                assert ec == 0

        :param actions: A tuple of four iterators, each iterator when consumed
            produces one of the following attriubutes:
                
            ``contract name``, ``action name``, ``arguments list`` and ``permissions``

        :return: A list the results for each action execution.
        :rtype: List[:ref:`typing_action_result`]
        """
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
    ) -> ExecutionResult:
        """Create an unstaked eosio account, usualy used by system contracts.

        :param owner: The system account that authorizes the creation of a new account.
        :param name: The name of the new account conforming to account naming conventions.
        :param key: The owner public key or permission level for the new account (optional).

        :return: Exitcode and output.
        :rtype: :ref:`typing_exe_result`
        """

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
    ) -> ExecutionResult:
        """Create a staked eosio account.

        :param owner: The system account that authorizes the creation of a new
            account.
        :param name: The name of the new account conforming to account naming
            conventions.
        :param net: Amount of system tokens to stake to reserve network bandwith.
        :param cpu: Amount of system tokens to stake to reserve cpu time.
        :param ram: Amount of bytes of ram to buy for this account.
        :param key: The owner public key or permission level for the new account
            (optional).

        :return: Exitcode and output.
        :rtype: :ref:`typing_exe_result`
        """

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
            '--buy-ram-kbytes', ram
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
    ) -> List[ExecutionResult]:
        """Same as :func:`~pytest_eosio.EOSIOTestSession.create_account_staked`,
        but takes lists of names and keys, to create the accounts in parallel,
        which is faster than calling :func:`~pytest_eosio.EOSIOTestSession.creat
        e_account_staked` in a loop.

        :param owner: The system account that authorizes the creation of a new
            account.
        :param names: List of names for the new accounts conforming to account naming
            conventions.
        :param keys: List of public keys or permission levels for the new accounts.
        :param net: Amount of system tokens to stake to reserve network bandwith.
        :param cpu: Amount of system tokens to stake to reserve cpu time.
        :param ram: Amount of bytes of ram to buy for each account.

        :return: A list the results for each command execution.
        :rtype: List[ExecutionResult]
        """

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
                '--buy-ram-kbytes', ram
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
        """Get table rows from the blockchain.

        :param account: Account name of contract were table is located.
        :param scope: Table scope in EOSIO name format.
        :param table: Table name.
        :param args: Additional arguments to pass to ``cleos get table`` (`cleos 
            docs <https://developers.eos.io/manuals/eos/latest/cleos/command-ref
            erence/get/table>`_).

        :return: List of rows matching query.
        :rtype: List[Dict]
        """

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

    def get_info(self) -> Dict[str, Union[str, int]]:
        """Get blockchain statistics.

            - ``server_version``
            - ``head_block_num``
            - ``last_irreversible_block_num``
            - ``head_block_id``
            - ``head_block_time``
            - ``head_block_producer``
            - ``recent_slots``
            - ``participation_rate``

        :return: A dictionary with blockchain information.
        :rtype: Dict[str, Union[str, int]]
        """

        ec, out = self.run(['cleos', 'get', 'info'])
        assert ec == 0
        return json.loads(out)

    def get_resources(self, account: str) -> List[Dict]:
        """Get account resources.

        :param account: Name of account to query resources.

        :return: A list with a single dictionary which contains, resource info.
        :rtype: List[Dict]
        """

        return self.get_table('eosio', account, 'userres')

    def new_account(self, name: Optional[str] = None) -> str:
        """Create a new account with a random key and name, import the private
        key into the wallet.

        :param name: To set a specific name and not a random one.

        :return: New account name.
        :rtype: str
        """

        if name:
            account_name = name
        else:
            account_name = random_eosio_name()

        private_key, public_key = self.create_key_pair()
        self.import_key(private_key)
        self.create_account_staked('eosio', account_name, key=public_key)
        return account_name

    def new_accounts(self, n: int) -> List[str]:
        """Same as :func:`~pytest_eosio.EOSIOTestSession.new_account` but to
        create multiple accounts at the same time, faster than calling :func:`~p
        ytest_eosio.EOSIOTestSession.new_account` on a loop.

        :param n: Number of accounts to create.

        :return: List of names of the new accounts.
        :rtype: List[str]
        """

        names = [random_eosio_name() for _ in range(n)]
        keys = self.create_key_pairs(n)
        self.import_keys([priv_key for priv_key, pub_key in keys])
        self.create_accounts_staked(
            'eosio', names, [pub_key for priv_key, pub_key in keys])
        return names

    def buy_ram_bytes(
        self,
        payer: str,
        amount: int,
        receiver: Optional[str] = None
    ) -> ActionResult:
        """Buy a number of RAM bytes for an account.

        :param payer: Account to bill.
        :param amount: Amount of RAM to buy in bytes.
        :param receiver: In case its present buy RAM bytes for this account
            instead of receiver.

        :return: Exitcode and output of ``buyrambytes`` push action call.
        :rtype: :ref:`typing_action_result`
        """

        if not receiver:
            receiver = payer

        return self.push_action(
            'eosio', 'buyrambytes',
            [payer, receiver, amount],
            f'{payer}@active'
        )

    def wait_blocks(self, n: int, sleep_time: float = 0.25):
        """Busy wait till ``n`` amount of blocks are produced on the chain.

        :param n: Number of blocks to wait.
        :param sleep_time: Time to re-check chain.
        """
        start = self.get_info()['head_block_num']
        while (info := self.get_info())['head_block_num'] - start < n:
            time.sleep(sleep_time)

    def multi_sig_propose(
        self,
        proposer: str,
        req_permissions: List[str],
        tx_petmissions: List[str],
        contract: str,
        action_name: str,
        data: Dict[str, str]
    ) -> str:
        """Create a multi signature proposal with a random name.

        :param proposer: Account to authorize the proposal.
        :param req_permissions: List of permissions required to run proposed
            transaction.
        :param tx_permissions: List of permissions that will be applied to
            transaction when executed.
        :param contract: Contract were action is defined.
        :param action_name: Action name.
        :param data: Dictionary with transaction to execute with multi signature.

        :return: New proposal name.
        :rtype: str
        """

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
        proposer: str,
        proposal_name: str,
        permissions: List[str],
        approver: str
    ) -> ActionResult:
        """Approve a multisig proposal.

        :param proposer: Account that created the proposal.
        :param proposal_name: Name of the proposal.
        :param permissions: List of permissions to append to proposal.
        :param approver: Permissions to run this action.

        :return: Exitcode and output of ``multisig.approve`` push action call.
        :rtype: :ref:`typing_action_result`
        """

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
        proposer: str,
        proposal_name: str,
        permission: str,
        wait: int = 3
    ) -> ActionResult:
        """Execute multi signature transaction proposal.

        :param proposer: Account that created the proposal.
        :param proposal_name: Name of the proposal.
        :param permission: Permissions to run this action.
        :param wait: Number of blocks to wait after executing.

        :return: Exitcode and output of ``multisig.exec`` push action call.
        :rtype: :ref:`typing_action_result`
        """

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
        proposer: str,
        proposal_name: str
    ) -> ActionResult:
        """Review a multisig proposal.

        :param proposer: Account that created the proposal.
        :param proposal_name: Name of the proposal.

        :return: Exitcode and output of ``multisig.review`` push action call.
        :rtype: :ref:`typing_action_result`
        """

        cmd = [
            'cleos',
            'multisig',
            'review',
            proposer,
            proposal_name
        ]
        ec, out =  self.run(cmd)
        return ec, out

    def get_token_stats(
        self,
        sym: str,
        token_contract: str = 'eosio.token'
    ) -> Dict[str, str]:
        """Get token statistics.

        :param sym: Token symbol.
        :param token_contract: Token contract.
        
        :return: A dictionary with ``\'supply\'``, ``\'max_supply\'`` and
            ``\'issuer\'`` as keys.
        :rtype: Dict[str, str]
        """

        return self.get_table(
            token_contract,
            sym,
            'stat'
        )[0]

    def get_balance(
        self,
        account: str,
        token_contract: str = 'eosio.token'
    ) -> Optional[str]:
        """Get account balance.
        
        :param account: Account to query.
        :param token_contract: Token contract.

        :return: Account balance in asset form, ``None`` if user has no balance
            entry.
        :rtype: Optional[str]
        """

        balances = self.get_table(
            token_contract,
            account,
            'accounts'
        )
        if len(balances) == 1:
            return balances[0]['balance']
        else:
            return None

    def create_token(
        self,
        issuer: str,
        max_supply: Union[str, Asset],
        token_contract: str = 'eosio.token'
    ) -> ActionResult:
        """Create a new token issued by ``issuer``.

        :param issuer: Account that issues new token.
        :param max_supply: Max token supply in asset form.
        :param token_contract: Token contract.

        :return: ``token_contract.create`` execution result.
        :rtype: :ref:`typing_action_result`
        """

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
        token_contract: str = 'eosio.token'
    ) -> ActionResult:
        """Issue a specific quantity of tokens.

        :param issuer: Account that issues new tokens.
        :param quantity: Quantity of tokens to issue in asset form.
        :param memo: Memo string to attach to transaction.
        :param token_contract: Token contract.

        :return: ``token_contract.issue`` execution result.
        :rtype: :ref:`typing_action_result`
        """

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
        token_contract: str = 'eosio.token'
    ) -> ActionResult:
        """Transfer tokens.

        :param _from: Account that sends the tokens.
        :param _to: Account that recieves the tokens.
        :param quantity: Quantity of tokens to issue in asset form.
        :param memo: Memo string to attach to transaction.
        :param token_contract: Token contract.

        :return: ``token_contract.issue`` execution result.
        :rtype: :ref:`typing_action_result`
        """

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
    ) -> ActionResult:
        """Transfer tokens from token contract to an account.

        :param _to: Account that recieves the tokens.
        :param quantity: Quantity of tokens to issue in asset form.
        :param memo: Memo string to attach to transaction.
        :param token_contract: Token contract.

        :return: ``token_contract.issue`` execution result.
        :rtype: :ref:`typing_action_result`
        """
        return self.transfer_token(
            token_contract,
            _to,
            str(quantity),
            memo,
            token_contract=token_contract
        )


    def init_sys_token(self):
        """Initialize ``SYS`` token, with a supply of 
        10000000000 units and four digits of precision.
        """

        if not self._sys_token_init:
            self._sys_token_init = True
            max_supply = f'{10000000000:.4f} SYS'
            ec, _ = self.create_token('eosio', max_supply)
            assert ec == 0
            ec, _ = self.issue_token('eosio', max_supply, __name__)
            assert ec == 0


CONTRACTS_ROOTDIR = '/root/contracts'
CUSTOM_INCLUDES_DIR = '/root/includes'



def pytest_sessionstart(session):

    terminal_reporter = session.config.pluginmanager.get_plugin('terminalreporter')
    capture_manager = session.config.pluginmanager.get_plugin('capturemanager')
    with capture_manager.global_and_fixture_disabled():

        terminal_reporter.write("connecting to docker daemon...", flush=True)

        try:
            dockerctl = DockerCtl(session.config.option.dockerurl)
            dockerctl.client.ping()

        except DockerException:
            terminal_reporter.write(" error!\n", flush=True)
            pytest.exit("Is docker daemon running?")

        terminal_reporter.write(" done.\n", flush=True)
    
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
            ) for i, inc_dir in enumerate(session.config.getoption('--include'))]
        ]

        if dockerctl.client.info()['NCPU'] < 2:
            logging.warning('eosio-cpp needs at least 2 logical cores')

        terminal_reporter.write("launching virtual testnet...", flush=True)

        kwargs = {}
        if platform == 'linux':
            kwargs['network'] = 'host'
        else:
            kwargs['publish_all_ports'] = True
            kwargs['network'] = 'bridge'

        container = get_exit_stack().enter_context(
            get_container(
                dockerctl,
                'guilledk/pytest-eosio',
                'vtestnet',
                mounts=docker_mounts,
                **kwargs
            )
        )

        terminal_reporter.write(" done.\n", flush=True)

        session = get_exit_stack().enter_context(
            EOSIOTestSession(
                container,
                session.config,
                dockerctl,
                docker_mounts
            )
        )
        set_session(session)


@pytest.fixture(scope='session')    
def eosio_testnet():
    yield get_session() 


def pytest_sessionfinish(session, exitstatus):

    terminal_reporter = session.config.pluginmanager.get_plugin('terminalreporter')
    capture_manager = session.config.pluginmanager.get_plugin('capturemanager')
    session_obj = get_session()
    with capture_manager.global_and_fixture_disabled():
        if session_obj and session.config.getoption('--keep-alive'):
            ports = waitfor(session_obj.vtestnet, ('NetworkSettings', 'Ports', '8888/tcp'))
            container_port = ports[0]['HostPort']
            endpoint = f'http://localhost:{container_port}'

            terminal_reporter.ensure_newline()
            terminal_reporter.write(f"\nAccess the running testnet at {endpoint}\n")
            terminal_reporter.write("--keep-alive PRESENT, awaiting Ctrl+C...", flush=True)

            try:
                while True:
                    time.sleep(100000)

            except KeyboardInterrupt:
                pass

        terminal_reporter.write("\n\nstopping chain...", flush=True)

        get_exit_stack().pop_all().close()

        terminal_reporter.write(" done.", flush=True)
