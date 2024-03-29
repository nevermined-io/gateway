import json
import logging

from authlib.integrations.flask_oauth2 import current_token
from authlib.jose.errors import BadSignatureError
from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import id_to_did, NEVERMINED_PREFIX
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.utils.crypto import (ecdsa_encryption_from_file,
                                          get_ecdsa_public_key_from_file,
                                          rsa_encryption_from_file)
from eth_utils import remove_0x_prefix
from flask import Blueprint, jsonify, request
from flask.wrappers import Response
from secret_store_client.client import RPCError
from web3 import Web3

from nevermined_gateway import constants
from nevermined_gateway.conditions import fulfill_access_proof_condition, fulfill_escrow_payment_condition, \
    fulfill_escrow_payment_condition_multi, fulfill_for_delegate_nft_transfer_condition, is_nft_holder, \
    fulfill_for_delegate_nft721_transfer_condition
from nevermined_gateway.config import upload_backends
from nevermined_gateway.identity.oauth2.authorization_server import create_authorization_server
from nevermined_gateway.identity.oauth2.resource_server import create_resource_server
from nevermined_gateway.log import setup_logging
from nevermined_gateway.myapp import app
from nevermined_gateway.snark_util import call_prover
from nevermined_gateway.util import (check_required_attributes,
                                     do_secret_store_encrypt, encrypt, generate_password, get_asset_url_at_index,
                                     get_config,
                                     get_provider_account, get_provider_babyjub_key, get_provider_key_file,
                                     get_provider_password, get_rsa_public_key_file,
                                     is_access_granted, is_access_proof_condition_fulfilled,
                                     is_escrow_payment_condition_fulfilled, is_nft_transfer_approved,
                                     is_nft_transfer_condition_fulfilled, keeper_instance,
                                     setup_keeper, used_by, verify_signature, was_compute_triggered,
                                     get_asset, generate_random_id, is_lock_payment_condition_fulfilled,
                                     get_upload_enabled, upload_content)

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
        encrypted_document, public_key = rsa_encryption_from_file(document, get_rsa_public_key_file())
        logger.debug(f'encrypted urls {encrypted_document}, '
                     f'publisher {publisher_address}, '
                     f'documentId {did}')
        return encrypted_document, 201

    except (RPCError, Exception) as e:
        logger.error(
            f'Encryption Error: {e}. \n'
            f'providerAddress={provider_acc.address}\n'
            f'Payload was: documentId={did}, '
            f'publisherAddress={publisher_address},'
            f'signature={signature}',
            exc_info=1
        )
        return f'Error: {str(e)}', 500


@services.route('/upload/<backend>', methods=['POST'])
def upload(backend=None):

    if not get_upload_enabled():
        return 'Upload not supported in this server', 501

    if not upload_backends.keys().__contains__(backend):
        return 'Backend not implemented', 501

    file_ = request.files.get('file')
    if file_ is None:
        return 'No file provided in request', 400

    data = request.form

    try:
        file_name = data.get('fileName', file_.filename)
        if data.get('encrypt') == 'true':
            password = generate_password()
            filedata = encrypt(password, file_)
            url = upload_content(filedata, file_name, upload_backends[backend], app.config['CONFIG_FILE'])
            return {'url': url, 'password': password}, 201
        fdata = file_.read()
        url = upload_content(fdata, file_name, upload_backends[backend], app.config['CONFIG_FILE'])
        return {'url': url }, 201
    except Exception as e:
        logger.error(f'Driver error when uploading file: {e}')
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
        return get_asset(request, requests_session, content_type, url, app.config['CONFIG_FILE'])

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
        used_by(generate_random_id(), did, consumer_address, 'access', '0x00', 'access', provider_acc,
                keeper)
        return get_asset(request, requests_session, content_type, url, app.config['CONFIG_FILE'])

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/access-proof/<agreement_id>', methods=['GET'])
@services.route('/access-proof/<agreement_id>/<int:index>', methods=['GET'])
@require_oauth()
def access_proof(agreement_id, index=0):
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
        used_by(generate_random_id(), did, consumer_address, 'access', '0x00', 'access proof', provider_acc,
                keeper)
        return Response(
            url,
            '200',
            content_type=content_type
        )

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/nft-access/<agreement_id>', methods=['GET'])
@services.route('/nft-access/<agreement_id>/<int:index>', methods=['GET'])
@require_oauth()
def nft_access(agreement_id, index=0):
    """Allows to get access to an asset data file holding a NFT.
    swagger_from_file: docs/nft_access.yml
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
        used_by(generate_random_id(), did, consumer_address, 'access', '0x00', 'nft access', provider_acc,
                keeper)
        return get_asset(request, requests_session, content_type, url, app.config['CONFIG_FILE'])

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/nft-access-proof/<agreement_id>', methods=['GET'])
@services.route('/nft-access-proof/<agreement_id>/<int:index>', methods=['GET'])
@require_oauth()
def nft_access_proof(agreement_id, index=0):
    """Allows to get access to an asset data file holding a NFT.
    swagger_from_file: docs/nft_access.yml
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
        used_by(generate_random_id(), did, consumer_address, 'access', '0x00', 'nft access prof', provider_acc,
                keeper)
        return Response(
            url,
            '200',
            content_type=content_type
        )

    except (ValueError, Exception) as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


@services.route('/nft-transfer', methods=['POST'])
def nft_transfer():
    """Allows the provider transfer and release the rewards.
    swagger_from_file: docs/nft_transfer.yml
    """
    required_attributes = ['agreementId', 'nftHolder', 'nftReceiver', 'nftAmount']
    data = request.json

    msg, status = check_required_attributes(required_attributes, data, 'nft-transfer')
    if msg:
        return msg, status

    agreement_id = data.get('agreementId')
    nft_holder_address = data.get('nftHolder')
    nft_receiver_address = data.get('nftReceiver')
    nft_amount = data.get('nftAmount')
    nft_type = str(data.get('nftType'))
    service_type = ServiceTypes.NFT_SALES
    is_1155 = True

    if nft_type == '721':
        service_type = ServiceTypes.NFT721_SALES
        is_1155 = False

    keeper = keeper_instance()
    agreement = keeper.agreement_manager.get_agreement(agreement_id)
    did = id_to_did(agreement.did)
    ddo = DIDResolver(keeper.did_registry).resolve(did)

    try:
        service_agreement = ServiceAgreement.from_ddo(service_type, ddo)
    except ValueError as e:
        logger.error('nft-sales service not found on ddo for %s', did)
        return str(e), 400

    (
        lock_payment_condition_id,
        nft_transfer_condition_id,
        escrow_payment_condition_id
    ) = agreement.condition_ids

    nft_transfer = service_agreement.get_nft_transfer_or_mint()
    nft_contract_address = service_agreement.get_nft_contract_address()
    if nft_transfer and not is_nft_holder(keeper, agreement.did, nft_amount, nft_holder_address, nft_contract_address):
        msg = f'Holder {nft_holder_address} does not have enough NFTs to transfer'
        logger.warning(msg)
        return msg, 406

    if not is_lock_payment_condition_fulfilled(lock_payment_condition_id, keeper):
        msg = f'lockPayment condition for agreement_id={agreement_id} is not fulfilled'
        logger.warning(msg)
        return msg, 402

    if nft_transfer and not is_nft_transfer_approved(nft_holder_address, get_provider_account().address, keeper):
        msg = f'Gateway ({get_provider_account().address}) is not approved to transfer nfts from {nft_holder_address}'
        logger.warning(msg)
        return msg, 405

    # fulfill transferNFT condition
    if not is_nft_transfer_condition_fulfilled(nft_transfer_condition_id, keeper):
        logger.debug('Fulfilling TransferNFT condition')
        if is_1155:
            result = fulfill_for_delegate_nft_transfer_condition(
                agreement_id,
                service_agreement,
                agreement.did,
                Web3.toChecksumAddress(nft_holder_address),
                Web3.toChecksumAddress(nft_receiver_address),
                nft_amount,
                lock_payment_condition_id,
                keeper
            )
        else:
            logger.debug('Fulfilling TransferNFT721 condition')
            result = fulfill_for_delegate_nft721_transfer_condition(
                agreement_id,
                service_agreement,
                agreement.did,
                Web3.toChecksumAddress(nft_holder_address),
                Web3.toChecksumAddress(nft_receiver_address),
                nft_amount,
                lock_payment_condition_id,
                keeper
            )
        if result is False:
            msg = f'There was an error fulfilling the Transfer NFT condition for agreement_id={agreement_id} Is 1155? {is_1155}'
            logger.error(msg)
            return msg, 500

    if not is_nft_transfer_condition_fulfilled(nft_transfer_condition_id, keeper):
        msg = f'The TransferNFT condition was not fulfilled for agreement_id={agreement_id}'
        logger.error(msg)
        return msg, 500

    # fulfill escrowPayment condition
    if not is_escrow_payment_condition_fulfilled(escrow_payment_condition_id, keeper):
        logger.debug('Fulfilling EscrowPayment condition')
        result = fulfill_escrow_payment_condition(
            keeper,
            agreement_id,
            [
                nft_transfer_condition_id,
                lock_payment_condition_id,
                escrow_payment_condition_id
            ],
            ddo,
            get_provider_account(),
            service_type=service_type
        )
        if result is False:
            msg = f'There was an error fulfilling the EscrowPayment condition for agreement_id={agreement_id}'
            logger.error(msg)
            return msg, 500

    return 'success', 200


@services.route('/nft-transfer-with-access', methods=['POST'])
def nft_transfer_proof():
    """Allows the provider transfer and release the rewards.
    swagger_from_file: docs/nft_transfer.yml
    """
    required_attributes = ['agreementId', 'nftHolder', 'nftReceiver', 'nftAmount', 'buyerPub']
    data = request.json

    msg, status = check_required_attributes(required_attributes, data, 'nft-transfer-with-access')
    if msg:
        return msg, status

    agreement_id = data.get('agreementId')
    nft_holder_address = data.get('nftHolder')
    nft_receiver_address = data.get('nftReceiver')
    nft_amount = data.get('nftAmount')
    consumer_pub = data.get('buyerPub')

    keeper = keeper_instance()
    agreement = keeper.agreement_manager.get_agreement(agreement_id)
    did = id_to_did(agreement.did)
    ddo = DIDResolver(keeper.did_registry).resolve(did)

    try:
        service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_SALES_WITH_ACCESS, ddo)
    except ValueError as e:
        logger.error('nft-sales-with-access service not found on ddo for %s', did)
        return str(e), 400

    (
        lock_payment_condition_id,
        nft_transfer_condition_id,
        escrow_payment_condition_id,
        access_condition_id
    ) = agreement.condition_ids

    nft_contract_address = service_agreement.get_nft_contract_address()

    if not is_nft_holder(keeper, agreement.did, nft_amount, nft_holder_address, nft_contract_address):
        msg = f'Holder {nft_holder_address} does not have enough NFTs to transfer'
        logger.warning(msg)
        return msg, 406

    if not is_lock_payment_condition_fulfilled(lock_payment_condition_id, keeper):
        msg = f'lockPayment condition for agreement_id={agreement_id} is not fulfilled'
        logger.warning(msg)
        return msg, 402

    if not is_nft_transfer_approved(nft_holder_address, get_provider_account().address, keeper):
        msg = f'Gateway ({get_provider_account().address}) is not approved to transfer nfts from {nft_holder_address}'
        logger.warning(msg)
        return msg, 405

    # fulfill transferNFT condition
    if not is_nft_transfer_condition_fulfilled(nft_transfer_condition_id, keeper):
        logger.debug('NFTTransfer condition not fulfilled')
        result = fulfill_for_delegate_nft_transfer_condition(
            agreement_id,
            service_agreement,
            agreement.did,
            Web3.toChecksumAddress(nft_holder_address),
            Web3.toChecksumAddress(nft_receiver_address),
            nft_amount,
            lock_payment_condition_id,
            keeper
        )
        if result is False:
            msg = f'There was an error fulfilling the NFTTransfer condition for agreement_id={agreement_id}'
            logger.error(msg)
            return msg, 500

    if not is_access_proof_condition_fulfilled(access_condition_id, keeper):
        logger.debug('AccessProof condition not fulfilled')
        provider_account = get_provider_account()
        agreement = keeper.agreement_manager.get_agreement(agreement_id)
        cond_ids = agreement.condition_ids
        asset = DIDResolver(keeper.did_registry).resolve(did)
        auth_method = asset.authorization.main['service']
        url = '0x' + get_asset_url_at_index(0, asset, provider_account, auth_method)
        provider_key = get_provider_babyjub_key()
        provider_pub = [provider_key.x, provider_key.y]
        proof = call_prover(consumer_pub, provider_key.secret, url)
        result = fulfill_access_proof_condition(
            keeper,
            agreement_id,
            access_condition_id,
            proof['hash'],
            consumer_pub,
            provider_pub,
            proof['cipher'],
            proof['proof'],
            provider_account
        )
        if result is False:
            msg = f'There was an error fulfilling the AccessProof condition for agreement_id={agreement_id}'
            logger.error(msg)
            return msg, 500

    # fulfill escrowPayment condition
    if not is_escrow_payment_condition_fulfilled(escrow_payment_condition_id, keeper):
        logger.debug('EscrowPayment condition not fulfilled')
        result = fulfill_escrow_payment_condition_multi(
            keeper,
            agreement_id,
            [
                nft_transfer_condition_id,
                lock_payment_condition_id,
                escrow_payment_condition_id,
                access_condition_id
            ],
            ddo,
            get_provider_account(),
            service_type=ServiceTypes.NFT_SALES_WITH_ACCESS
        )
        if result is False:
            msg = f'There was an error fulfilling the EscrowPayment condition for agreement_id={agreement_id}'
            logger.error(msg)
            return msg, 500

    return 'success', 200


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

        signature = '0x00'

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

        used_by(generate_random_id(), did, consumer_address, 'compute', signature, 'compute', provider_acc,
                keeper)
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
        return get_asset(request, requests_session, content_type, url, app.config['CONFIG_FILE'])
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
