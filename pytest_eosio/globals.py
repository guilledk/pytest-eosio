#!/usr/bin/env python3

from contextlib import ExitStack


"""This globals are needed to keep some values in between pytest hook calls
"""


_EXITSTACK = None
_DOCKERCTL = None
_VTESTNET = None
_MOUNTS = None


def get_exit_stack() -> ExitStack:
    global _EXITSTACK
    if _EXITSTACK == None:
        _EXITSTACK = ExitStack()

    return _EXITSTACK


def set_dockerctl(dockerctl):
    global _DOCKERCTL
    _DOCKERCTL = dockerctl

def get_dockerctl():
    global _DOCKERCTL
    return _DOCKERCTL


def set_testnet(container):
    global _VTESTNET
    _VTESTNET = container

def get_testnet():
    global _VTESTNET
    return _VTESTNET


def set_mounts(mounts):
    global _MOUNTS
    _MOUNTS = mounts


def get_mounts():
    global _MOUNTS
    return _MOUNTS
