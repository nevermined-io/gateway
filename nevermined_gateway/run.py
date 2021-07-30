import configparser
import logging
import sys

from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.utils.crypto import get_ecdsa_public_key_from_file, get_content_keyfile_from_path
from flask import jsonify
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

from nevermined_gateway.config import Config
from nevermined_gateway.constants import BaseURLs, ConfigSections, Metadata
from nevermined_gateway.myapp import app
from nevermined_gateway.routes import services
from nevermined_gateway import version
from nevermined_gateway.util import keeper_instance, get_provider_account, get_provider_key_file, \
    get_provider_password, get_rsa_public_key_file

config = Config(filename=app.config['CONFIG_FILE'])
gateway_url = config.get(ConfigSections.RESOURCES, 'gateway.url')

requests_session = get_requests_session()
logger = logging.getLogger(__name__)

log = logging.getLogger('authlib')
log.addHandler(logging.StreamHandler(sys.stdout))
log.setLevel(logging.DEBUG)


def get_contracts():
    keeper = keeper_instance()

    return {name: contract.address for (name, contract) in keeper.contract_name_to_instance.items()}


def get_external_contracts():
    keeper = keeper_instance()
    return {name: contract.address for (name, contract) in keeper.external_contract_name_to_instance.items()}


@app.route("/")
def root_info():
    keeper = keeper_instance()
    info = {
        'software': Metadata.TITLE,
        'version': version.__version__,
        'keeper-url': config.keeper_url,
        'network': keeper.network_name,
        'contracts': get_contracts(),
        'external-contracts': get_external_contracts(),
        'keeper-version': keeper.did_registry.version,
        'provider-address': get_provider_account().address,
        'ecdsa-public-key': get_ecdsa_public_key_from_file(get_provider_key_file(), get_provider_password())
    }

    try:
        info['rsa-public-key'] = get_content_keyfile_from_path(get_rsa_public_key_file())
    except Exception as e:
        logger.warning(f'Unable to load RSA Public Key: {e}. ', exc_info=1)

    return jsonify(info)


@app.route("/spec")
def spec():
    swag = swagger(app, from_file_keyword='swagger_from_file')
    swag['info']['version'] = version.__version__
    swag['info']['title'] = Metadata.TITLE
    swag['info']['description'] = Metadata.DESCRIPTION
    return jsonify(swag)


# Call factory function to create our blueprint
swaggerui_blueprint = get_swaggerui_blueprint(
    BaseURLs.SWAGGER_URL,
    gateway_url + '/spec',
    config={  # Swagger UI config overrides
        'app_name': "Test application"
    },
    )

# Register blueprint at URL
app.register_blueprint(swaggerui_blueprint, url_prefix=BaseURLs.SWAGGER_URL)
app.register_blueprint(services, url_prefix=BaseURLs.ASSETS_URL)

if __name__ == '__main__':
    app.run(port=8030)
