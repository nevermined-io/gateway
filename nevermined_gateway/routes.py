import json
import logging
from authlib.jose.errors import BadSignatureError

from common_utils_py.did import id_to_did, NEVERMINED_PREFIX
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.utils.crypto import (ecdsa_encryption_from_file,
                                          get_ecdsa_public_key_from_file,
                                          rsa_encryption_from_file)
from eth_utils import remove_0x_prefix
from flask import Blueprint, jsonify, request
from secret_store_client.client import RPCError
from authlib.integrations.flask_oauth2 import current_token

from nevermined_gateway import constants
from nevermined_gateway.identity.oauth2.authorization_server import create_authorization_server
from nevermined_gateway.identity.oauth2.resource_server import create_resource_server
from nevermined_gateway.log import setup_logging
from nevermined_gateway.myapp import app
from nevermined_gateway.util import (build_download_response, check_required_attributes,
                                     do_secret_store_encrypt, get_asset_url_at_index, get_config,
                                     get_download_url, get_provider_account, get_provider_key_file,
                                     get_provider_password, get_rsa_public_key_file,
                                     is_access_granted, keeper_instance,
                                     setup_keeper, used_by, verify_signature, was_compute_triggered)

setup_logging()
services = Blueprint('services', __name__)
setup_keeper(app.config['CONFIG_FILE'])
provider_acc = get_provider_account()
requests_session = get_requests_session()
authorization = create_authorization_server(app)
require_oauth = create_resource_server()

logger = logging.getLogger(__name__)


@services.route("/encrypt", methods=['POST'])
def encrypt_content():
    """Call the execution of a workflow.
    swagger_from_file: docs/encrypt.yml
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
            public_key = get_ecdsa_public_key_from_file(get_provider_key_file(),
                                                        get_provider_password())

        elif (method == 'PSK-ECDSA'):
            hash, public_key = ecdsa_encryption_from_file(message, get_provider_key_file(),
                                                          get_provider_password())

        elif (method == 'PSK-RSA'):
            hash, public_key = rsa_encryption_from_file(message, get_rsa_public_key_file())
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

        print('Document: ' + document)
        print('DID: ' + remove_0x_prefix(did))
        encrypted_document = do_secret_store_encrypt(
            remove_0x_prefix(did),
            document,
            provider_acc,
            get_config()
        )
        logger.debug(f'encrypted urls {encrypted_document}, '
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


@services.route('/download/<int:index>', methods=['GET'])
@require_oauth()
def download(index=0):
    """Allows to download an asset data file.
    swagger_from_file: docs/download.yml
    """

    consumer_address = current_token["client_id"]
    did = current_token["did"]

    logger.info('Parameters:\nIndex: %d\nConsumerAddress: %s\n'
                'DID: %s'
                % (index, consumer_address, did))

    try:
        keeper = keeper_instance()
        asset = DIDResolver(keeper.did_registry).resolve(did)

        file_attributes = asset.metadata['main']['files'][index]
        content_type = file_attributes.get('contentType', None)

        try:
            auth_method = asset.authorization.main['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = (
                    'The Authorization Method defined in the DDO is not part of the available '
                    'methods supported'
                    'by the Gateway: ' + auth_method)
            logger.warning(msg)
            return msg, 400

        url = get_asset_url_at_index(index, asset, provider_acc, auth_method)
        download_url = get_download_url(url, app.config['CONFIG_FILE'])

        logger.debug(f'Done processing download request for asset {did}')
        return build_download_response(request, requests_session, url, download_url, content_type)

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/access/<agreement_id>', methods=['GET'])
@services.route('/access/<agreement_id>/<int:index>', methods=['GET'])
@require_oauth()
def access(agreement_id, index=0):
    """Allows to get access to an asset data file.
    swagger_from_file: docs/access.yml
    """

    consumer_address = current_token["client_id"]
    did = current_token["did"]
    agreement_id = current_token["sub"]

    logger.info('Parameters:\nAgreementId: %s\nIndex: %d\nConsumerAddress: %s\n'
                'DID: %s\n'
                % (agreement_id, index, consumer_address, did))

    try:
        keeper = keeper_instance()
        asset = DIDResolver(keeper.did_registry).resolve(did)

        logger.debug('AgreementID :' + agreement_id)

        # TODO: Not sure what signature should be here
        signature = '0x00'
        used_by(agreement_id, did, consumer_address, 'access', signature, 'access', provider_acc,
                keeper)
        file_attributes = asset.metadata['main']['files'][index]
        content_type = file_attributes.get('contentType', None)

        try:
            auth_method = asset.authorization.main['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = (
                    'The Authorization Method defined in the DDO is not part of the available '
                    'methods supported'
                    'by the Gateway: ' + auth_method)
            logger.warning(msg)
            return msg, 400

        url = get_asset_url_at_index(index, asset, provider_acc, auth_method)
        download_url = get_download_url(url, app.config['CONFIG_FILE'])

        logger.debug(f'Done processing consume request for asset {did}, agreementId {agreement_id},'
                     f' url {download_url}')
        return build_download_response(request, requests_session, url, download_url, content_type)

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/execute/<agreement_id>', methods=['POST'])
@require_oauth()
def execute(agreement_id):
    """Call the execution of a workflow.
    swagger_from_file: docs/execute.yml
    """

    consumer_address = current_token["client_id"]
    workflow_did = current_token["did"]
    agreement_id = current_token["sub"]

    try:
        keeper = keeper_instance()
        asset_id = keeper_instance().agreement_manager.get_agreement(agreement_id).did
        did = id_to_did(asset_id)

        # TODO: Not sure what the signature should be
        signature = '0x00'
        used_by(agreement_id, did, consumer_address, 'compute', signature, 'compute', provider_acc,
                keeper)

        workflow = DIDResolver(keeper_instance().did_registry).resolve(workflow_did)
        body = {"serviceAgreementId": agreement_id, "workflow": workflow.as_dictionary()}

        response = requests_session.post(
            get_config().compute_api_url + '/api/v1/nevermined-compute-api/init',
            data=json.dumps(body),
            headers={'content-type': 'application/json'})
        if response.status_code != 200:
            msg = f'The compute API was not able to create the workflow. {response.content}'
            logger.warning(msg)
            return msg, 401
        return jsonify({"workflowId": response.content.decode('utf-8')})

    except Exception as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/compute/logs/<agreement_id>/<execution_id>', methods=['GET'])
@require_oauth()
def compute_logs(agreement_id, execution_id):
    """Allows to get access to an asset data file.
    swagger_from_file: docs/compute_logs.yml
    """

    consumer_address = current_token["client_id"]
    execution_id = current_token["execution_id"]
    agreement_id = current_token["sub"]

    logger.info(('Parameters:\n'
                 'ConsumerAddress: %s\n'
                 'AgreementId: %s\n'
                 'ExecutionId: %s\n'),
                consumer_address, agreement_id, execution_id)

    response = requests_session.get(
        get_config().compute_api_url + f'/api/v1/nevermined-compute-api/logs/{execution_id}',
        headers={'content-type': 'application/json'})

    if not response.ok:
        msg = f'The compute API was not able to return the logs. {response.content}'
        logger.warning(msg)
        return msg, response.status_code

    return jsonify(response.json()), 200


@services.route('/compute/status/<agreement_id>/<execution_id>', methods=['GET'])
@require_oauth()
def compute_status(agreement_id, execution_id):
    """Allows to get access to an asset data file.
    swagger_from_file: docs/compute_logs.yml
    """

    consumer_address = current_token["client_id"]
    execution_id = current_token["execution_id"]
    agreement_id = current_token["sub"]

    logger.info(('Parameters:\n'
                 'ConsumerAddress: %s\n'
                 'AgreementId: %s\n'
                 'ExecutionId: %s\n'),
                consumer_address, agreement_id, execution_id)

    response = requests_session.get(
        get_config().compute_api_url + f'/api/v1/nevermined-compute-api/status/{execution_id}',
        headers={'content-type': 'application/json'})

    if not response.ok:
        msg = f'The compute API was not able to return the logs. {response.content}'
        logger.warning(msg)
        return msg, response.status_code

    return response.content.decode('utf-8'), 200


##### DEPRECATED METHODS ######


@services.route('/consume', methods=['GET'])
def consume():
    """Allows download of asset data file.
    Method deprecated, it will be replaced by `/access` in further versions
    swagger_from_file: docs/consume.yml
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
            auth_method = asset.authorization.main['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = (
                    'The Authorization Method defined in the DDO is not part of the available '
                    'methods supported'
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
    Method deprecated, it will be replaced by `/execute` in further versions
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
            get_config().compute_api_url + '/api/v1/nevermined-compute-api/init',
            data=json.dumps(body),
            headers={'content-type': 'application/json'})
        return jsonify({"workflowId": response.content.decode('utf-8')})
    except Exception as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/oauth/token', methods=['POST'])
def issue_token():
    try:
        return authorization.create_token_response()
    except BadSignatureError as e:
        msg = f"Bad Signature: {str(e)}"
        logger.warning(msg)
        return msg, 401
