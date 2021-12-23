import io
import json
import logging
import mimetypes
import os
import tempfile
import uuid
from datetime import datetime
from distutils.util import strtobool
from os import getenv

from common_utils_py.did import did_to_id, convert_to_bytes
from common_utils_py.utils.crypto import ecdsa_decryption, rsa_decryption_aes
from contracts_lib_py import Keeper, keeper
from contracts_lib_py.contract_handler import ContractHandler
from contracts_lib_py.utils import add_ethereum_prefix_and_hash_msg, get_account
from contracts_lib_py.web3_provider import Web3Provider
from eth_utils import remove_0x_prefix
from flask import Response
from metadata_driver_interface.driver_interface import DriverInterface
from secret_store_client.client import Client as SecretStore
from nevermined_contracts import get_artifacts_path

from nevermined_gateway.config import Config
from nevermined_gateway.constants import ConditionState

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
                             f'variable `PROVIDER_ADDRESS`. Please set the following environment '
                             f'variables and try again: `PROVIDER_ADDRESS`, `PROVIDER_PASSWORD`, '
                             f', `PROVIDER_KEYFILE`, `RSA_KEYFILE` and `RSA_PASSWORD`.')
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
    os.environ['PSK-RSA_PRIVKEY_FILE'] = os.getenv('RSA_PRIVKEY_FILE', '')
    os.environ['PSK-RSA_PUBKEY_FILE'] = os.getenv('RSA_PUBKEY_FILE', '')


def get_provider_key_file():
    return os.getenv('PROVIDER_KEYFILE', '')


def get_provider_password():
    return os.getenv('PROVIDER_PASSWORD', '')


def get_rsa_private_key_file():
    return os.getenv('RSA_PRIVKEY_FILE', '')


def get_rsa_public_key_file():
    return os.getenv('RSA_PUBKEY_FILE', '')


def get_upload_enabled():
    return strtobool(os.getenv("UPLOAD_ENABLED", "true"))


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


def is_owner_granted(did, consumer_address, keeper):
    document_id = did_to_id(did)
    is_granted = keeper.access_condition.check_permissions(
        document_id, consumer_address
    )
    logger.info(is_granted)
    return is_granted


def is_access_granted(agreement_id, did, consumer_address, keeper):
    agreement_consumer = keeper.access_template.get_agreement_consumer(
        agreement_id)
    logger.info(agreement_consumer)

    if agreement_consumer is None:
        return False

    if agreement_consumer != consumer_address:
        logger.warning(f'Invalid consumer address {consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement consumer is {agreement_consumer}')
        return False

    document_id = did_to_id(did)

    is_granted = keeper.access_condition.check_permissions(
        document_id, consumer_address
    )
    logger.info(is_granted)
    return is_granted


def is_lock_payment_condition_fulfilled(lock_payment_condition_id, keeper):
    return keeper.condition_manager.get_condition_state(lock_payment_condition_id) == ConditionState.Fulfilled.value


def is_escrow_payment_condition_fulfilled(escrow_payment_condition_id, keeper):
    return keeper.condition_manager.get_condition_state(escrow_payment_condition_id) == ConditionState.Fulfilled


def is_nft_transfer_condition_fulfilled(nft_transfer_condition_id, keeper):
    return keeper.condition_manager.get_condition_state(nft_transfer_condition_id) == ConditionState.Fulfilled.value


def is_nft_transfer_approved(account_address, operator_address, keeper):
    return keeper.did_registry.is_nft_approved_for_all(account_address, operator_address)


def is_nft_access_condition_fulfilled(agreement_id, access_cond_id, consumer_address, keeper):
    agreement_consumer = keeper.nft_access_template.get_agreement_consumer(agreement_id)
    logger.debug(agreement_consumer)

    if agreement_consumer is None:
        return False

    if agreement_consumer != consumer_address:
        logger.warning(f'Invalid consumer address {consumer_address} and/or '
                       f'service agreement id {agreement_id}'
                       f', agreement consumer is {agreement_consumer}')
        return False

    is_granted = keeper.condition_manager.get_condition_state(access_cond_id) == ConditionState.Fulfilled.value
    logger.debug(is_granted)
    return is_granted


def was_compute_triggered(agreement_id, did, compute_consumer_address, keeper):
    agreement_consumer = keeper.escrow_compute_execution_template.get_agreement_consumer(
        agreement_id)
    if agreement_consumer is None:
        return False

    if agreement_consumer != compute_consumer_address:
        logger.warning(f'Invalid consumer address {compute_consumer_address} and/or '
                       f'service agreement id {agreement_id} (did {did})'
                       f', agreement consumer is {agreement_consumer}')
        return False

    document_id = did_to_id(did)
    return keeper.compute_execution_condition.was_compute_triggered(
        document_id, compute_consumer_address
    )


def is_token_valid(token):
    return isinstance(token, str) and token.startswith('0x') and len(token.split('-')) == 2


def check_auth_token(token):
    w3 = web3()
    parts = token.split('-')
    if len(parts) < 2:
        return '0x0'
    # :HACK: alert, this should be part of common-utils, common-contracts, or a stand-alone library
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

class BabyjubKey:
    def __init__(self, secret, public1, public2):
        self.secret = secret
        self.x = public1
        self.y = public2

def get_provider_babyjub_key():
    secret = os.getenv('PROVIDER_BABYJUB_SECRET', '')
    public1 = os.getenv('PROVIDER_BABYJUB_PUBLIC1', '')
    public2 = os.getenv('PROVIDER_BABYJUB_PUBLIC2', '')
    return BabyjubKey(secret, public1, public2)

def get_provider_public_key():
    public1 = os.getenv('PROVIDER_BABYJUB_PUBLIC1', '')
    public2 = os.getenv('PROVIDER_BABYJUB_PUBLIC2', '')
    return [public1, public2]

def get_buyer_public_key():
    public1 = os.getenv('BUYER_BABYJUB_PUBLIC1', '')
    public2 = os.getenv('BUYER_BABYJUB_PUBLIC2', '')
    return [public1, public2]

def get_buyer_secret_key():
    secret = os.getenv('BUYER_BABYJUB_SECRET', '')
    return secret

def get_env_property(env_variable, property_name):
    return getenv(
        env_variable,
        get_config().get('metadata-driver', property_name)
    )


def get_keeper_path(config):
    if config.keeper_path and config.keeper_path != '':
        return config.keeper_path

    return get_artifacts_path()


def keeper_instance():
    # Init web3 before fetching keeper instance.
    web3()
    external_contracts = get_config().external_contracts
    return Keeper.get_instance(external_contracts=external_contracts)


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


def get_asset_url_at_index(url_index, asset, account, auth_method='PSK-RSA'):
    logger.debug(
        f'get_asset_url_at_index(): url_index={url_index}, did={asset.did}, provider='
        f'{account.address}')
    try:
        if auth_method == 'SecretStore':
            files_str = do_secret_store_decrypt(
                remove_0x_prefix(asset.asset_id),
                asset.encrypted_files,
                account,
                get_config()
            )
        elif auth_method == 'PSK-RSA':
            files_str = rsa_decryption_aes(asset.encrypted_files, get_rsa_private_key_file())
        elif auth_method == 'PSK-ECDSA':
            files_str = ecdsa_decryption(asset.encrypted_files, get_provider_key_file(),
                                         get_provider_password())

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


def get_asset(request, requests_session, content_type, url, config_file):
    osm = DriverInterface(url, config_file)
    logger.info('Get Asset for url: ' + url)
    logger.info('URL Type: ' + osm.parse_url(url))
    if osm.parse_url(url) == 'filecoin':
        try:
            content_binary = get_content_binary(url, config_file)
            return Response(
                io.BytesIO(content_binary).read(),
                200,
                headers={},
                content_type=content_type
            )
        except Exception as e:
            logger.error('Unable to fetch Filecoin content ' + url)
            return None
    else:
        download_url = get_download_url(url, config_file)

        logger.debug(f'Done processing download request for asset')
        return build_download_response(request, requests_session, url, download_url, content_type)


def get_content_binary(url, config_file):
    try:
        logger.debug('Connecting through Metadata Driver Interface to generate the content binary.')
        osm = DriverInterface(url, config_file)
        content_binary = osm.data_plugin.download_bytes(url)
        logger.debug(f'Metadata Driver Interface downloaded the binary from the url: {url}')
        return content_binary
    except Exception as e:
        logger.error(f'Error fetching binary (using Metadata Driver Interface): {str(e)}')
        raise


def upload_content(content, file_name, protocol, config_file):
    try:
        logger.debug('Connecting through Metadata Driver Interface to upload file.')
        osm = DriverInterface(protocol, config_file)

        if protocol.startswith('cid'):
            cid = osm.data_plugin.upload_bytes(content, file_name)
            logger.debug(f'Metadata Driver Interface uploaded the file: {cid}')
            return 'cid://' + cid
        else:

            response = osm.data_plugin.upload_bytes(content, file_name)
            logger.debug(f'Metadata Driver Interface uploaded the file: {response}')
            return response

    except Exception as e:
        logger.error(f'Error uploading (using Metadata Driver Interface): {str(e)}')
        raise


def upload_filecoin_file(file, config_file):
    try:
        logger.debug('Connecting through Metadata Driver Interface to upload file.')
        osm = DriverInterface('cid://', config_file)
        response = osm.data_plugin.upload(file)
        logger.debug(f'Metadata Driver Interface uploaded the file: {response}')
        return response
    except Exception as e:
        logger.error(f'Error uploading (using Metadata Driver Interface): {str(e)}')
        raise


def get_download_url(url, config_file):
    try:
        logger.debug('Connecting through Metadata Driver Interface to generate the signed url.')
        osm = DriverInterface(url, config_file)
        download_url = osm.data_plugin.generate_url(url)
        logger.debug(f'Metadata Driver Interface generated the url: {download_url}')
        return download_url
    except Exception as e:
        logger.error(f'Error generating url (using Metadata Driver Interface): {str(e)}')
        raise


def check_required_attributes(required_attributes, data, method):
    assert isinstance(data, dict), 'invalid payload format.'
    logger.debug('got %s request: %s' % (method, data))
    if not data:
        logger.error('%s request failed: data is empty.' % method)
        return 'payload seems empty.', 400
    for attr in required_attributes:
        if attr not in data:
            logger.error('%s request failed: required attr %s missing.' % (method, attr))
            return '"%s" is required in the call to %s' % (attr, method), 400
    return None, None


def used_by(provenance_id, did, consumer_address, activity_id, signature, attributes,
            account, keeper):
    try:
        receipt = keeper.did_registry.used(
            convert_to_bytes(provenance_id),
            convert_to_bytes(did),
            convert_to_bytes(consumer_address),
            convert_to_bytes(Web3Provider.get_web3().keccak(text=activity_id)),
            signature, account, attributes)
        return bool(receipt and receipt.status == 1)
    except Exception as e:
        logging.debug(f'On-chain call error: {e}')
        return False


def generate_random_id():
    return uuid.uuid4().hex + uuid.uuid4().hex
