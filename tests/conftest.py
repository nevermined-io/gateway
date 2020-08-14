import json
import os
import pathlib
from urllib.request import urlopen

import pytest
from contracts_lib_py.contract_handler import ContractHandler
from contracts_lib_py.utils import get_account
from contracts_lib_py.web3_provider import Web3Provider

from nevermined_gateway.run import app
from nevermined_gateway.util import get_config, init_account_envvars

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
    ContractHandler.artifacts_path = os.path.expanduser(
        '~/.nevermined/nevermined-contracts/artifacts')
    init_account_envvars()


def get_publisher_account():
    return get_account(0)


def get_consumer_account():
    os.environ['PARITY_ADDRESS1'] = '0x068ed00cf0441e4829d9784fcbe7b9e26d4bd8d0'
    os.environ['PARITY_PASSWORD1'] = 'secret'
    os.environ['PARITY_KEYFILE1'] = 'tests/resources/data/consumer_key_file.json'
    return get_account(1)


def get_sample_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/keyko-io/nevermined-docs/master/docs/architecture/specs'
        '/examples/access/v0.1/ddo1.json').read().decode(
        'utf-8'))


