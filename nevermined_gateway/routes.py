import json
import logging

from common_utils_py.did import id_to_did, NEVERMINED_PREFIX
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.http_requests.requests_session import get_requests_session
from eth_utils import remove_0x_prefix
from flask import Blueprint, jsonify, request
from secret_store_client.client import RPCError

from nevermined_gateway import constants
from nevermined_gateway.log import setup_logging
from nevermined_gateway.myapp import app
from nevermined_gateway.util import (build_download_response, check_required_attributes, do_secret_store_encrypt,
                                     get_asset_url_at_index, get_config, get_download_url,
                                     get_provider_account,
                                     is_access_granted, keeper_instance, setup_keeper, verify_signature,
                                     was_compute_triggered, get_provider_key_file, get_provider_password,
                                     get_ecdsa_public_key_from_file, get_rsa_public_key_file,
                                     get_content_keyfile_from_path, rsa_encription_from_file,
                                     ecdsa_encription_from_file)

setup_logging()
services = Blueprint('services', __name__)
setup_keeper(app.config['CONFIG_FILE'])
provider_acc = get_provider_account()
requests_session = get_requests_session()

logger = logging.getLogger(__name__)


@services.route("/encrypt", methods=['POST'])
def encrypt_content():
    """Encrypt a Secret using the Secret Store, ECDSA or RSA methods

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        description: Asset urls encryption.
        schema:
          type: object
          required:
            - message
            - method
          properties:
            message:
              description: The message to encrypt
              type: string
              example: '{"url":"https://keyko.io/","index":0,"checksum":"efb21","contentLength":"45","contentType":"text/csv"}'
            method:
              description: The encryption method to use. Options (`SecretStore`, `PSK-ECDSA`, `PSK-RSA`)
              type: string
              example: 'PSK-RSA'
            did:
              description: Identifier of the asset.
              type: string
              example: 'did:nv:08a429b8529856d59867503f8056903a680935a76950bb9649785cc97869a43d'
    responses:
      200:
        description: document successfully encrypted.
      500:
        description: Error
    """

    required_attributes = ['message', 'method']
    data = request.json

    msg, status = check_required_attributes(required_attributes, data, 'encrypt')
    if msg:
        return msg, status

    try:
        message = data.get('message')
        method = data.get('method')

        if (method == 'SecretStore'):
            msg, status = check_required_attributes(['did'], data, 'encrypt')
            if msg:
                return msg, status

            did = data.get('did').replace(NEVERMINED_PREFIX, '')
            hash = do_secret_store_encrypt(
                remove_0x_prefix(did),
                message,
                provider_acc,
                get_config()
            )
            public_key = get_ecdsa_public_key_from_file(get_provider_key_file(), get_provider_password())

        elif (method == 'PSK-ECDSA'):
            hash, public_key = ecdsa_encription_from_file(message)

        elif (method == 'PSK-RSA'):
            hash, public_key = rsa_encription_from_file(message)
        else:
            return f'Unknown method: {method}\n' \
                   f'Options available are (`SecretStore`, `PSK-ECDSA`, `PSK-RSA`)', 500

        output = dict()
        output['public-key'] = public_key
        output['hash'] = hash
        output['method'] = method
        return jsonify(output)

    except Exception as e:
        logger.error(f'Error: {e}. ', exc_info=1)
        return f'Error: {str(e)}', 500


@services.route('/publish', methods=['POST'])
def publish():
    """Encrypt document using the SecretStore and keyed by the given documentId.

    This can be used by the publisher of an asset to encrypt the urls of the
    asset data files before publishing the asset ddo. The publisher to use this
    service is one that is using a front-end with a wallet app such as MetaMask.
    In such scenario the publisher is not able to encrypt the urls using the
    SecretStore interface and this service becomes necessary.

    tags:
      - services
    consumes:
      - application/json
    parameters:
      - in: body
        name: body
        required: true
        description: Asset urls encryption.
        schema:
          type: object
          required:
            - documentId
            - signature
            - document
            - publisherAddress:
          properties:
            documentId:
              description: Identifier of the asset to be registered in ocean.
              type: string
              example: 'did:nv:08a429b8529856d59867503f8056903a680935a76950bb9649785cc97869a43d'
            signature:
              description: Publisher signature of the documentId
              type: string
              example: ''
            document:
              description: document
              type: string
              example: '/some-url'
            publisherAddress:
              description: Publisher address.
              type: string
              example: '0x00a329c0648769A73afAc7F9381E08FB43dBEA72'
    responses:
      201:
        description: document successfully encrypted.
      500:
        description: Error

    return: the encrypted document (hex str)
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

        print('Document: ' + document)
        print('DID: ' + remove_0x_prefix(did))
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

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement.
        required: true
        type: string
      - name: url
        in: query
        description: This URL is only valid if Nevermined Gateway acts as a proxy.
                     Consumer can't download using the URL if it's not through Nevermined Gateway.
        required: true
        type: string
      - name: signature
        in: query
        description: Signature of the documentId to verify that the consumer has rights to download the asset.
      - name: index
        in: query
        description: Index of the file in the array of files.
    responses:
      200:
        description: Redirect to valid asset url.
      400:
        description: One of the required attributes is missing.
      401:
        description: Invalid asset data.
      500:
        description: Error
    """
    data = request.args
    required_attributes = [
        'serviceAgreementId',
        'consumerAddress',
        'signature',
        'index'
    ]
    msg, status = check_required_attributes(required_attributes, data, 'consume')
    if msg:
        return msg, status

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
        signature = data.get('signature')
        index = int(data.get('index'))

        if not verify_signature(keeper, consumer_address, signature, agreement_id):
            msg = f'Invalid signature {signature} for ' \
                  f'publisherAddress {consumer_address} and documentId {agreement_id}.'
            raise ValueError(msg)

        file_attributes = asset.metadata['main']['files'][index]
        content_type = file_attributes.get('contentType', None)

        try:
            auth_method = asset.authorization['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = ('The Authorization Method defined in the DDO is not part of the availble methods supported'
                   'by the Gateway: ' + auth_method)
            logger.warning(msg)
            return msg, 400

        url = get_asset_url_at_index(index, asset, provider_acc, auth_method)
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

    ---
    tags:
      - services
    consumes:
      - application/json
    parameters:
      - name: consumerAddress
        in: query
        description: The consumer address.
        required: true
        type: string
      - name: serviceAgreementId
        in: query
        description: The ID of the service agreement.
        required: true
        type: string
      - name: signature
        in: query
        description: Signature of the documentId to verify that the consumer has rights to download the asset.
        type: string
      - name: workflowDID
        in: query
        description: DID of the workflow that is going to start to be executed.
        type: string
    responses:
      200:
        description: Call to the operator-service was successful.
      400:
        description: One of the required attributes is missing.
      401:
        description: Invalid asset data.
      500:
        description: Error
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
