import json
import logging

from common_utils_py.did import id_to_did
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.http_requests.requests_session import get_requests_session
from ecies import decrypt
from eth_utils import remove_0x_prefix, to_hex, to_bytes, decode_hex
from flask import Blueprint, jsonify, request
from secret_store_client.client import RPCError

from nevermined_gateway.log import setup_logging
from nevermined_gateway.myapp import app
from nevermined_gateway.util import (build_download_response, check_required_attributes, do_secret_store_encrypt,
                                     get_asset_url_at_index, get_config, get_download_url, get_provider_account,
                                     is_access_granted, keeper_instance, setup_keeper, verify_signature,
                                     was_compute_triggered, get_provider_key_file, get_provider_password,
                                     get_keys_from_file, get_public_key_from_file, encryption)

setup_logging()
services = Blueprint('services', __name__)
setup_keeper(app.config['CONFIG_FILE'])
provider_acc = get_provider_account()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route("/encrypt", methods=['POST'])
def encrypt():
    """Call the execution of a workflow.
    swagger_from_file: docs/encrypt.yml
    """
    required_attributes = ['message']
    data = request.args

    # print('Received message: ')
    # print(data.get('message'))
    msg, status = check_required_attributes(required_attributes, data, 'encrypt')
    if msg:
        return msg, status

    message = data.get('message')

    # print('Message=' + message)
    # print('KeyFile=' + get_provider_key_file())
    # print('Password=' + get_provider_password())

    public_key_hex = get_public_key_from_file(get_provider_key_file(), get_provider_password())
    encrypted_message = encryption(public_key_hex, message.encode())
    hash = to_hex(encrypted_message)

    # print('PublicKey=' + public_key_hex)
    # print('HASH=')
    # print(hash)

    (_x, private_key_hex) = get_keys_from_file(get_provider_key_file(), get_provider_password())
    decrypted_message = decrypt(private_key_hex, decode_hex(hash))
    # print('decrypted_message=' + decrypted_message.decode())

    output = dict()
    output['public-key'] = public_key_hex
    output['hash'] = hash

    return jsonify(output)


@services.route('/publish', methods=['POST'])
def publish():
    """Encrypt document using the SecretStore and keyed by the given documentId.
    swagger_from_file: docs/publish.yml
    """
    required_attributes = [
        'documentId',
        'signature',
        'document',
        'publisherAddress'
    ]
    data = request.json
    if 'signedDocumentId' in data and 'signature' not in data:
        data['signature'] = data['signedDocumentId']

    msg, status = check_required_attributes(required_attributes, data, 'publish')
    if msg:
        return msg, status

    did = data.get('documentId')
    signature = data.get('signature')
    document = json.dumps(json.loads(data.get('document')), separators=(',', ':'))
    publisher_address = data.get('publisherAddress')

    try:
        if not verify_signature(keeper_instance(), publisher_address, signature, did):
            msg = f'Invalid signature {signature} for ' \
                  f'publisherAddress {publisher_address} and documentId {did}.'
            raise ValueError(msg)

        encrypted_document = do_secret_store_encrypt(
            remove_0x_prefix(did),
            document,
            provider_acc,
            get_config()
        )
        logger.info(f'encrypted urls {encrypted_document}, '
                    f'publisher {publisher_address}, '
                    f'documentId {did}')
        return encrypted_document, 201

    except (RPCError, Exception) as e:
        logger.error(
            f'SecretStore Error: {e}. \n'
            f'providerAddress={provider_acc.address}\n'
            f'Payload was: documentId={did}, '
            f'publisherAddress={publisher_address},'
            f'signature={signature}',
            exc_info=1
        )
        return f'Error: {str(e)}', 500


@services.route('/consume', methods=['GET'])
def consume():
    """Allows download of asset data file.
    swagger_from_file: docs/consume.yml
    """
    data = request.args
    required_attributes = [
        'serviceAgreementId',
        'consumerAddress'
    ]
    msg, status = check_required_attributes(required_attributes, data, 'consume')
    if msg:
        return msg, status

    if not (data.get('url') or (data.get('signature') and data.get('index'))):
        return f'Either `url` or `signature and index` are required in the call to "consume".', 400

    try:
        keeper = keeper_instance()
        agreement_id = data.get('serviceAgreementId')
        consumer_address = data.get('consumerAddress')
        asset_id = keeper.agreement_manager.get_agreement(agreement_id).did
        did = id_to_did(asset_id)

        if not is_access_granted(
                agreement_id,
                did,
                consumer_address,
                keeper):
            msg = ('Checking access permissions failed. Either consumer address does not have '
                   'permission to consume this asset or consumer address and/or service agreement '
                   'id is invalid.')
            logger.warning(msg)
            return msg, 401

        asset = DIDResolver(keeper.did_registry).resolve(did)
        content_type = None
        url = data.get('url')
        if not url:
            signature = data.get('signature')
            index = int(data.get('index'))
            if not verify_signature(keeper, consumer_address, signature, agreement_id):
                msg = f'Invalid signature {signature} for ' \
                      f'publisherAddress {consumer_address} and documentId {agreement_id}.'
                raise ValueError(msg)

            file_attributes = asset.metadata['main']['files'][index]
            content_type = file_attributes.get('contentType', None)
            url = get_asset_url_at_index(index, asset, provider_acc)

        download_url = get_download_url(url, app.config['CONFIG_FILE'])
        logger.info(f'Done processing consume request for asset {did}, agreementId {agreement_id},'
                    f' url {download_url}')
        return build_download_response(request, requests_session, url, download_url, content_type)
    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/exec', methods=['POST'])
def execute_compute_job():
    """Call the execution of a workflow.
    swagger_from_file: docs/execute_compute_job.yml
    """
    data = request.args
    required_attributes = [
        'serviceAgreementId',
        'consumerAddress',
        'signature',
        'workflowDID'
    ]
    msg, status = check_required_attributes(required_attributes, data, 'consume')
    if msg:
        return msg, status

    if not (data.get('signature')):
        return f'`signature is required in the call to "consume".', 400

    try:
        agreement_id = data.get('serviceAgreementId')
        consumer_address = data.get('consumerAddress')
        asset_id = keeper_instance().agreement_manager.get_agreement(agreement_id).did
        did = id_to_did(asset_id)
        if not was_compute_triggered(agreement_id, did, consumer_address, keeper_instance()):
            msg = (
                'Checking if the compute was triggered failed. Either consumer address does not '
                'have permission to executre this workflow or consumer address and/or service '
                'agreement id is invalid.')
            logger.warning(msg)
            return msg, 401

        workflow = DIDResolver(keeper_instance().did_registry).resolve(data.get('workflowDID'))
        body = {"serviceAgreementId": agreement_id, "workflow": workflow.as_dictionary()}

        response = requests_session.post(
            get_config().operator_service_url + '/api/v1/operator/init',
            data=json.dumps(body),
            headers={'content-type': 'application/json'})
        return jsonify({"workflowId": response.content.decode('utf-8')})
    except Exception as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500
