import os
import tempfile
from unittest import mock

from contracts_lib_py.web3_provider import Web3Provider
import pytest

from nevermined_gateway.config import Config

INFURA_TOKEN = os.environ.get("INFURA_TOKEN")


@pytest.mark.parametrize("keeper_url,network_name", [
    [f"https://mainnet.infura.io/v3/{INFURA_TOKEN}", "mainnet"],
    [f"https://rinkeby.infura.io/v3/{INFURA_TOKEN}", "rinkeby"],
    ("http://localhost:8545", "spree"),
    ("https://matic-mumbai.chainstacklabs.com", "mumbai"),
    ("https://alfajores-forno.celo-testnet.org", "celo-alfajores"),
    ("https://baklava-forno.celo-testnet.org", "celo-baklava")
])
def test_artifact(keeper_url, network_name, monkeypatch):
    options = {
        "nevermined-contracts": {
            "keeper.url": keeper_url,
            "keeper.path": ""
        },
        "resources": {
            "gateway.url": "http://localhost:8030"
        }
    }
    config = Config(options_dict=options)
    config_file = tempfile.NamedTemporaryFile(mode='w', delete=False)
    config.write(config_file)
    config_file.flush()
    config_file_name = config_file.name
    config_file.close()

    with mock.patch.dict(os.environ, {'CONFIG_FILE': config_file_name}):

        from nevermined_gateway.run import app
        from nevermined_gateway.util import setup_keeper


        app.config['CONFIG_FILE'] = config_file_name
        Web3Provider._web3 = None
        setup_keeper(app.config['CONFIG_FILE'])
        client = app.test_client()

        response = client.get('/')
        assert response.json['network'] == network_name
        assert response.json['keeper-url'] == keeper_url