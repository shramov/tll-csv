#!/usr/bin/env python3
# vim: sts=4 sw=4 et

import pytest

import os
import pathlib
import tempfile

import tll.logger
tll.logger.init()

from tll.channel import Context

version = tuple([int(x) for x in pytest.__version__.split('.')[:2]])

if version < (3, 9):
    @pytest.fixture
    def tmp_path():
        with tempfile.TemporaryDirectory() as tmp:
            yield pathlib.Path(tmp)

@pytest.fixture
def context():
    ctx = Context()
    ctx.load(os.path.join(os.environ.get("BUILD_DIR", "target/debug"), "tll_csv"))
    return ctx
