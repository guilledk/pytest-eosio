.. index

pytest-eosio documentation
==========================

.. toctree::
    tutorial/install
    reference



A pytest plugin for end-to-end testing EOSIO smart contracts

What it does for you
********************

- Compile contracts (detects deltas on source files)
- Create (or manage) a single node testnet acording to `bios specification <https://developers.eos.io/welcome/latest/tutorials/bios-boot-sequence>`_
- Create staked accounts & deploy contracts acording to a manifest
- Run tests that use one or more smart contracts against that fresh testnet
- Write readable tests with python syntactic sugar

What it requires of you
***********************

- Docker
- Use `cmake` and `eosiocdt` `1.6.3` or `1.7.0` to compile your smart contracts (`CMakeList.txt` template available!)
- Follow this directory structure on your project (command to init project with this structure planned):

.. code-block:: none

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

Ok! but who uses it? give me an example
***************************************

This plugin was created during the development of `vapaee's <https://github.com/vapaee>`_ smart contract `suite <https://github.com/vapaee/vapaee-smart-contracts>`_.

`Checkout the tests directory <https://github.com/vapaee/vapaee-smart-contracts/tree/dev/tests>`_

That suite includes contracts and tests for:

- A generic event tracking smart contract
- A token-pool-converter with an open protocol
- A decentralized book-style token market
- Some of this contracts use `Telos Decide <https://docs.telos.net/developers/telos_contracts/telos-decide>`_ ballot features
- And more...

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`
