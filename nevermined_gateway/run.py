import configparser
import logging

from common_utils_py.http_requests.requests_session import get_requests_session
from flask import jsonify
from flask_swagger import swagger
from flask_swagger_ui import get_swaggerui_blueprint

from nevermined_gateway.config import Config
from nevermined_gateway.constants import BaseURLs, ConfigSections, Metadata
from nevermined_gateway.myapp import app
from nevermined_gateway.routes import services
from nevermined_gateway.util import keeper_instance, get_provider_account, get_provider_key_file, get_provider_password, \
    get_ecdsa_public_key_from_file, get_content_keyfile_from_path, get_rsa_public_key_file

config = Config(filename=app.config['CONFIG_FILE'])
gateway_url = config.get(ConfigSections.RESOURCES, 'gateway.url')

requests_session = get_requests_session()
logger = logging.getLogger(__name__)

def get_version():
    conf = configparser.ConfigParser()
    conf.read('.bumpversion.cfg')
    return conf['bumpversion']['current_version']


@app.route("/")
def version():
    keeper = keeper_instance()
    info = dict()
    info['software'] = Metadata.TITLE
    info['version'] = get_version()
    info['keeper-url'] = config.keeper_url
    info['network'] = keeper.network_name
    info['contracts'] = dict()
    info['contracts'][
        'AccessSecretStoreCondition'] = keeper.access_secret_store_condition.address
    info['contracts']['AgreementStoreManager'] = keeper.agreement_manager.address
    info['contracts']['ConditionStoreManager'] = keeper.condition_manager.address
    info['contracts']['DIDRegistry'] = keeper.did_registry.address
    if keeper.network_name != 'production':
        info['contracts']['Dispenser'] = keeper.dispenser.address
    info['contracts'][
        'EscrowAccessSecretStoreTemplate'] = keeper.escrow_access_secretstore_template.address
    info['contracts']['EscrowReward'] = keeper.escrow_reward_condition.address
    info['contracts']['HashLockCondition'] = keeper.hash_lock_condition.address
    info['contracts']['LockRewardCondition'] = keeper.lock_reward_condition.address
    info['contracts']['SignCondition'] = keeper.sign_condition.address
    info['contracts']['OceanToken'] = keeper.token.address
    info['contracts']['TemplateStoreManager'] = keeper.template_manager.address
    info['keeper-version'] = keeper.token.version
    info['provider-address'] = get_provider_account().address

    info['ecdsa-public-key'] = get_ecdsa_public_key_from_file(get_provider_key_file(), get_provider_password())
    info['rsa-public-key'] = get_content_keyfile_from_path(get_rsa_public_key_file())

    return jsonify(info)


@app.route("/spec")
def spec():
    swag = swagger(app)
    swag['info']['version'] = get_version()
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
