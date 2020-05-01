import io
import json
import logging
import mimetypes
import os
import site
from datetime import datetime
from os import getenv

from common_utils_py.did import did_to_id
from contracts_lib_py import Keeper
from contracts_lib_py.contract_handler import ContractHandler
from contracts_lib_py.utils import add_ethereum_prefix_and_hash_msg, get_account
from contracts_lib_py.web3_provider import Web3Provider
from eth_utils import remove_0x_prefix
from flask import Response
from nevermined_gateway.config import Config
from osmosis_driver_interface.osmosis import Osmosis
from secret_store_client.client import Client as SecretStore

logger = logging.getLogger(__name__)


def setup_keeper(config_file=None):
    config = Config(filename=config_file) if config_file else get_config()
    keeper_url = config.keeper_url
    artifacts_path = get_keeper_path(config)

    ContractHandler.artifacts_path = artifacts_path
    Web3Provider.get_web3(keeper_url)
    init_account_envvars()

    account = get_account(0)
    if account is None:
        raise AssertionError(f'Nevermined Gateway cannot run without a valid '
                             f'ethereum account. Account address was not found in the environment'
                             f'variable `PROVIDER_ADDRESS`. Please set the following evnironment '
                             f'variables and try again: `PROVIDER_ADDRESS`, `PROVIDER_PASSWORD`, '
                             f'and `PROVIDER_KEYFILE`.')
    if not account.key_file and not (account.password and account.key_file):
        raise AssertionError(f'Nevermined Gateway cannot run without a valid '
                             f'ethereum account with either a password and '
                             f'keyfile/encrypted-key-string '
                             f'or private key. Current account has password {account.password}, '
                             f'keyfile {account.key_file}, encrypted-key {account._encrypted_key} '
                             f'and private-key {account._private_key}.')


def init_account_envvars():
    os.environ['PARITY_ADDRESS'] = os.getenv('PROVIDER_ADDRESS', '')
    os.environ['PARITY_PASSWORD'] = os.getenv('PROVIDER_PASSWORD', '')
    os.environ['PARITY_KEYFILE'] = os.getenv('PROVIDER_KEYFILE', '')


def get_provider_key_file():
    return os.getenv('PROVIDER_KEYFILE', '')


def get_provider_password():
    return os.getenv('PROVIDER_PASSWORD', '')


def get_config():
    config_file = os.getenv('CONFIG_FILE', 'config.ini')
    return Config(filename=config_file)


def do_secret_store_encrypt(did_id, document, provider_acc, config):
    secret_store = SecretStore(
        config.secret_store_url,
        config.parity_url,
        provider_acc.address,
        provider_acc.password
    )
    encrypted_document = secret_store.publish_document(did_id, document)
    return encrypted_document


def do_secret_store_decrypt(did_id, encrypted_document, provider_acc, config):
    secret_store = SecretStore(
        config.secret_store_url,
        config.parity_url,
        provider_acc.address,
        provider_acc.password
    )
    return secret_store.decrypt_document(
        did_id, encrypted_document
    )


def is_access_granted(agreement_id, did, consumer_address, keeper):
    agreement_consumer = keeper.escrow_access_secretstore_template.get_agreement_consumer(
        agreement_id)

    if agreement_consumer is None:
        return False

    if agreement_consumer != consumer_address:
        logger.warning(f'Invalid consumer address {consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement consumer is {agreement_consumer}')
        return False

    document_id = did_to_id(did)
    return keeper.access_secret_store_condition.check_permissions(
        document_id, consumer_address
    )


def was_compute_triggered(agreement_id, did, computer_consumer_address, keeper):
    agreement_consumer = keeper.escrow_compute_execution_template.get_agreement_consumer(
        agreement_id)
    if agreement_consumer is None:
        return False

    if agreement_consumer != computer_consumer_address:
        logger.warning(f'Invalid consumer address {computer_consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement consumer is {agreement_consumer}')
        return False

    document_id = did_to_id(did)
    return keeper.compute_execution_condition.was_compute_triggered(
        document_id, computer_consumer_address
    )


def is_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
    w3 = web3()
    parts = token.split('-')
    if len(parts) < 2:
        return '0x0'
    # :HACK: alert, this should be part of ocean-utils, ocean-keeper, or a stand-alone library
    sig, timestamp = parts
    auth_token_message = get_config().auth_token_message or "Nevermined Protocol Authentication"
    default_exp = 30 * 24 * 60 * 60
    expiration = int(get_config().auth_token_expiration or default_exp)
    if int(datetime.now().timestamp()) > (int(timestamp) + expiration):
        return '0x0'

    keeper = keeper_instance()
    message = f'{auth_token_message}\n{timestamp}'
    address = keeper.personal_ec_recover(message, sig)
    return w3.toChecksumAddress(address)


def generate_token(account):
    raw_msg = get_config().auth_token_message or "Nevermined Protocol Authentication"
    _time = int(datetime.now().timestamp())
    _message = f'{raw_msg}\n{_time}'
    prefixed_msg_hash = add_ethereum_prefix_and_hash_msg(_message)
    return f'{keeper_instance().sign_hash(prefixed_msg_hash, account)}-{_time}'


def verify_signature(keeper, signer_address, signature, original_msg):
    if is_token_valid(signature):
        address = check_auth_token(signature)
    else:
        address = keeper.personal_ec_recover(original_msg, signature)

    return address.lower() == signer_address.lower()


def get_provider_account():
    return get_account(0)


def get_env_property(env_variable, property_name):
    return getenv(
        env_variable,
        get_config().get('osmosis', property_name)
    )


def get_keeper_path(config):
    path = config.keeper_path
    if not os.path.exists(path):
        if os.getenv('VIRTUAL_ENV'):
            path = os.path.join(os.getenv('VIRTUAL_ENV'), 'artifacts')
        else:
            path = os.path.join(site.PREFIXES[0], 'artifacts')

    return path


def keeper_instance():
    # Init web3 before fetching keeper instance.
    web3()
    return Keeper.get_instance()


def web3():
    return Web3Provider.get_web3(get_config().keeper_url)


def get_metadata(ddo):
    try:
        for service in ddo['service']:
            if service['type'] == 'Metadata':
                return service['metadata']
    except Exception as e:
        logger.error("Error getting the metatada: %s" % e)


def build_download_response(request, requests_session, url, download_url, content_type):
    try:
        if request.range:
            headers = {"Range": request.headers.get('range')}
        else:
            filename = url.split("/")[-1]
            file_ext = os.path.splitext(filename)[1]
            if file_ext and not content_type:
                content_type = mimetypes.guess_type(filename)[0]
            elif not file_ext and content_type:
                # add an extension to filename based on the content_type
                extension = mimetypes.guess_extension(content_type)
                if extension:
                    filename = filename + extension

            headers = {
                "Content-Disposition": f'attachment;filename={filename}',
                "Access-Control-Expose-Headers": f'Content-Disposition'
            }

        response = requests_session.get(download_url, headers=headers, stream=True)
        return Response(
            io.BytesIO(response.content).read(),
            response.status_code,
            headers=headers,
            content_type=content_type
        )
    except Exception as e:
        logger.error(f'Error preparing file download response: {str(e)}')
        raise


def get_asset_url_at_index(url_index, asset, account):
    logger.debug(
        f'get_asset_url_at_index(): url_index={url_index}, did={asset.did}, provider='
        f'{account.address}')
    try:
        files_str = do_secret_store_decrypt(
            remove_0x_prefix(asset.asset_id),
            asset.encrypted_files,
            account,
            get_config()
        )
        logger.debug(f'Got decrypted files str {files_str}')
        files_list = json.loads(files_str)
        if not isinstance(files_list, list):
            raise TypeError(f'Expected a files list, got {type(files_list)}.')
        if url_index >= len(files_list):
            raise ValueError(f'url index "{url_index}"" is invalid.')

        file_meta_dict = files_list[url_index]
        if not file_meta_dict or not isinstance(file_meta_dict, dict):
            raise TypeError(f'Invalid file meta at index {url_index}, expected a dict, got a '
                            f'{type(file_meta_dict)}.')
        if 'url' not in file_meta_dict:
            raise ValueError(f'The "url" key is not found in the '
                             f'file dict {file_meta_dict} at index {url_index}.')

        return file_meta_dict['url']

    except Exception as e:
        logger.error(f'Error decrypting url at index {url_index} for asset {asset.did}: {str(e)}')
        raise


def get_download_url(url, config_file):
    try:
        logger.info('Connecting through Osmosis to generate the signed url.')
        osm = Osmosis(url, config_file)
        download_url = osm.data_plugin.generate_url(url)
        logger.debug(f'Osmosis generated the url: {download_url}')
        return download_url
    except Exception as e:
        logger.error(f'Error generating url (using Osmosis): {str(e)}')
        raise


def check_required_attributes(required_attributes, data, method):
    assert isinstance(data, dict), 'invalid payload format.'
    logger.info('got %s request: %s' % (method, data))
    if not data:
        logger.error('%s request failed: data is empty.' % method)
        return 'payload seems empty.', 400
    for attr in required_attributes:
        if attr not in data:
            logger.error('%s request failed: required attr %s missing.' % (method, attr))
            return '"%s" is required in the call to %s' % (attr, method), 400
    return None, None
