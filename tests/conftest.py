import json
import os
import pathlib
from urllib.request import urlopen

import pytest
from contracts_lib_py.contract_handler import ContractHandler
from contracts_lib_py.utils import get_account
from contracts_lib_py.web3_provider import Web3Provider

from nevermined_gateway.util import get_config, init_account_envvars


def get_resource_path(dir_name, file_name):
    base = os.path.realpath(__file__).split(os.path.sep)[1:-1]
    if dir_name:
        return pathlib.Path(os.path.join(os.path.sep, *base, dir_name, file_name))
    else:
        return pathlib.Path(os.path.join(os.path.sep, *base, file_name))


@pytest.fixture(autouse=True)
def env_setup(monkeypatch):
    """Set test environment variables so that we can run the tests without having
    to set them.
    """
    provider_keyfile = pathlib.Path(__file__).parent / "resources/data/publisher_key_file.json"
    rsa_priv_keyfile = pathlib.Path(__file__).parent / "resources/data/rsa_priv_key.pem"
    rsa_pub_keyfile = pathlib.Path(__file__).parent / "resources/data/rsa_pub_key.pem"
    monkeypatch.setenv("PROVIDER_ADDRESS", "0x00bd138abd70e2f00903268f3db08f2d25677c9e")
    monkeypatch.setenv("PROVIDER_PASSWORD", "node0")
    monkeypatch.setenv("PROVIDER_KEYFILE", provider_keyfile.as_posix())
    monkeypatch.setenv("RSA_PRIVKEY_FILE", rsa_priv_keyfile.as_posix())
    monkeypatch.setenv("RSA_PUBKEY_FILE", rsa_pub_keyfile.as_posix())
    monkeypatch.setenv("ESTUARY_GATEWAY", "https://shuttle-4.estuary.tech")
    monkeypatch.setenv("IPFS_GATEWAY", "https://dweb.link/ipfs/:cid")


@pytest.fixture
def client():
    # This import is done here so that the `env_setup` fixture is called before we
    # initialize the flask app.
    from nevermined_gateway.run import app

    client = app.test_client()
    yield client


@pytest.fixture(autouse=True)
def setup_all():
    config = get_config()
    Web3Provider.get_web3(config.keeper_url)
    ContractHandler.artifacts_path = os.path.expanduser(
        '~/.nevermined/nevermined-contracts/artifacts')
    init_account_envvars()


@pytest.fixture
def provider_account():
    return get_account(0)


@pytest.fixture
def consumer_account():
    os.environ['PARITY_ADDRESS1'] = '0x068ed00cf0441e4829d9784fcbe7b9e26d4bd8d0'
    os.environ['PARITY_PASSWORD1'] = 'secret'
    os.environ['PARITY_KEYFILE1'] = 'tests/resources/data/consumer_key_file.json'
    return get_account(1)


@pytest.fixture
def publisher_account():
    os.environ['PARITY_ADDRESS2'] = '0xa99d43d86a0758d5632313b8fa3972b6088a21bb'
    os.environ['PARITY_PASSWORD2'] = 'secret'
    os.environ['PARITY_KEYFILE2'] = 'tests/resources/data/publisher2_key_file.json'
    return get_account(2)


def get_sample_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/docs/master/docs/architecture/specs'
        '/examples/access/v0.1/ddo1.json').read().decode(
        'utf-8'))


