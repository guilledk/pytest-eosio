.. install

Installation
============

Requirements
############

Docker
******

`Install docker <https://docs.docker.com/engine/install/>`_, this should be
pretty straightforward but instructions vary depending on your operating system,
also you might need to run ``pytest`` commands with super user privileges.

Python
******

*Warning for EOSIO developers not used to Python*: many operative systems come
with ``python`` pre-installed, but that ``python`` environment should not be used,
or modified, as it's used to run system scripts, and changing it might result in
a bricked system.

Part of the solution to this problem is to use `virtual environments <https://docs.python.org/3/tutorial/venv.html>`_.

But also your system might ship an outdated version of ``python``, so to make
things easier `pyenv <https://github.com/pyenv/pyenv>`_ is recommended (if you
know Node.js you might be familiar with ``nvm``).

To install ``pyenv`` checkout this repo: `<https://github.com/pyenv/pyenv-installer>`_

Once ``pyenv`` is installed, run this series of commands to install an appropriate version::

    pyenv update
    pyenv install 3.*.*  # 3.8+, probably works on 3.7 but not tested

Then you can create a ``python`` virtual environment local to a folder, based
of a fresh install of a specific version::

    cd project/path
    pyenv local $version
    pyenv virtualenv $env_name


Install package
###############

With our ``python`` environment properly setup run::

    pip install git+git://github.com/guilledk/pytest-eosiocdt.git
