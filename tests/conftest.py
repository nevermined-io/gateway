#  Copyright 2018 Ocean Protocol Foundation
#  SPDX-License-Identifier: Apache-2.0

import os
import pathlib
import json

import pytest
from contracts_lib_py.contract_handler import ContractHandler
from contracts_lib_py.utils import get_account
from contracts_lib_py.web3_provider import Web3Provider

from nevermind_gateway.run import app
from nevermind_gateway.util import get_config, get_keeper_path, init_account_envvars

app = app


def get_resource_path(dir_name, file_name):
    base = os.path.realpath(__file__).split(os.path.sep)[1:-1]
    if dir_name:
        return pathlib.Path(os.path.join(os.path.sep, *base, dir_name, file_name))
    else:
        return pathlib.Path(os.path.join(os.path.sep, *base, file_name))


@pytest.fixture
def client():
    client = app.test_client()
    yield client


@pytest.fixture(autouse=True)
def setup_all():
    config = get_config()
    Web3Provider.get_web3(config.keeper_url)
    ContractHandler.artifacts_path = os.path.expanduser('~/.nevermind/nevermind-contracts/artifacts')
    init_account_envvars()


def get_publisher_account():
    return get_account(0)


def get_consumer_account():
    return get_account(0)


def get_sample_ddo():
    path = get_resource_path('ddo', 'ddo_sa_sample.json')
    assert path.exists(), f"{path} does not exist!"
    with open(path, 'r') as file_handle:
        metadata = file_handle.read()
    return json.loads(metadata)
