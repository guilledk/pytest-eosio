#!/usr/bin/env python3

from contextlib import ExitStack


"""This globals are needed to keep some values in between pytest hook calls
"""


_EXITSTACK = None

_SESSION_OBJ = None


def get_exit_stack() -> ExitStack:
    global _EXITSTACK
    if _EXITSTACK == None:
        _EXITSTACK = ExitStack()

    return _EXITSTACK


def set_session(session_obj):
    global _SESSION_OBJ
    _SESSION_OBJ = session_obj


def get_session():
    global _SESSION_OBJ
    return _SESSION_OBJ
    
