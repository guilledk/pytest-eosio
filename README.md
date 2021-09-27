
# pytest-eosiocdt

### A pytest plugin for end-to-end testing EOSIO smart contracts

## What it does for you

- Compile contracts (detects deltas on source files)

- Create (or manage) a single node testnet acording to [bios specification](https://developers.eos.io/welcome/latest/tutorials/bios-boot-sequence)

- Create staked accounts & deploy contracts acording to a manifest

- Run tests that use one or more smart contracts against that fresh testnet

- Write readable tests with python syntactic sugar

## What it requires of you

- Docker

- Use `cmake` and `eosiocdt` `1.6.3` or `1.7.0` to compile your smart contracts (`CMakeList.txt` template available!)

- Follow this directory structure on your project (command to init project with this structure planned):

```
project_root
│
└─── contracts
│    │
│    └─── contract1
│    │    │
│    │    └─── CMakeLists.txt
│    │    └─── other source files
│    │
│    |─── contract2
│    │    │
│    │    └─── CMakeLists.txt
│    │    └─── other source files
│    |
│    └─── manifest.toml
│
└─── tests, and other project files
```

## Ok! but who uses it? give me an example

This plugin was created during the development of [vapaee's](https://github.com/vapaee) smart contract [suite](https://github.com/vapaee/vapaee-smart-contracts).

[Checkout the tests directory](https://github.com/vapaee/vapaee-smart-contracts/tree/dev/tests)

That suite includes contracts and tests for:

- A generic event tracking smart contract

- A token-pool-converter with an open protocol

- A decentralized book-style token market

- Some of this contracts use [Telos Decide](https://docs.telos.net/developers/telos_contracts/telos-decide) ballot features

- And more...

## Cool! But, How does it work?

`TODO`

## Install

1 - Install docker & python 3 (pyenv recommended)

2 - With ``python3`` installed, run:

    pip install git+git://github.com/guilledk/pytest-eosiocdt.git

## Usage

###### (IMPORTANT: Docker must be installed and running)

Run tests:

    pytest $test_dir


### Docker development commands

- docker build:

    `docker build --tag guilledk/pytest-eosiocdt:  docker/`

- docker push:

    `docker push guilledk/pytest-eosiocdt:`

- docker stop all:

    `docker stop $(docker ps -q)`

- docker clear:

    `docker rmi $(docker images -a -q)`
    
    `docker rm $(docker ps -a -q)`


