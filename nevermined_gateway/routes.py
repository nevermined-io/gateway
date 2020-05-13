import json
import logging
import time

from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import id_to_did, NEVERMINED_PREFIX
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.utils.crypto import get_ecdsa_public_key_from_file, ecdsa_encryption_from_file, \
    rsa_encryption_from_file
from contracts_lib_py.web3_provider import Web3Provider
from eth_utils import remove_0x_prefix
from flask import Blueprint, jsonify, request
from secret_store_client.client import RPCError

from nevermined_gateway import constants
from nevermined_gateway.constants import ConditionState, ConfigSections
from nevermined_gateway.log import setup_logging
from nevermined_gateway.myapp import app
from nevermined_gateway.util import (build_download_response, check_required_attributes, do_secret_store_encrypt,
                                     get_asset_url_at_index, get_config, get_download_url,
                                     get_provider_account,
                                     is_access_granted, keeper_instance, setup_keeper, verify_signature,
                                     was_compute_triggered, get_provider_key_file, get_provider_password,
                                     get_rsa_public_key_file)

setup_logging()
services = Blueprint('services', __name__)
setup_keeper(app.config['CONFIG_FILE'])
provider_acc = get_provider_account()
requests_session = get_requests_session()

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
            public_key = get_ecdsa_public_key_from_file(get_provider_key_file(), get_provider_password())

        elif (method == 'PSK-ECDSA'):
            hash, public_key = ecdsa_encryption_from_file(message, get_provider_key_file(), get_provider_password())

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


@services.route('/access/<agreement_id>', methods=['GET'])
@services.route('/access/<agreement_id>/<int:index>', methods=['GET'])
def access(agreement_id, index=0):
    """Allows to get access to an asset data file.
    swagger_from_file: docs/access.yml
    """

    try:
        consumer_address = request.headers.get('X-Consumer-Address')
        did = request.headers.get('X-DID')
        signature = request.headers.get('X-Signature')

        if not consumer_address or not did or not signature:
            return 'Unable to get params from headers', 401
    except Exception:
        return 'Unable to retrieve required parameters', 401

    logger.info('Parameters:\nAgreementId: %s\nIndex: %d\nConsumerAddress: %s\n'
                'DID: %s\nSignature: %s'
                % (agreement_id, index, consumer_address, did, signature))

    try:
        keeper = keeper_instance()
        asset_id = did.replace(NEVERMINED_PREFIX, '')

        logger.debug('AgreementID :' + agreement_id)

        ## Access flow
        # 1. Verification of signature
        if not verify_signature(keeper, consumer_address, signature, agreement_id):
            msg = f'Invalid signature {signature} for ' \
                  f'publisherAddress {consumer_address} and documentId {agreement_id}.'
            raise ValueError(msg)

        asset = DIDResolver(keeper.did_registry).resolve(did)

        # 2. Verification that access is granted
        if not is_access_granted(
                agreement_id,
                did,
                consumer_address,
                keeper):
            # 3. If not granted, verification of agreement and conditions
            agreement = keeper.agreement_manager.get_agreement(agreement_id)
            cond_ids = agreement.condition_ids

            access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            lockreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
            escrowreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            logger.debug('AccessCondition: %d' % access_condition_status)
            logger.debug('LockRewardCondition: %d' % lockreward_condition_status)
            logger.debug('EscrowRewardCondition: %d' % escrowreward_condition_status)

            if lockreward_condition_status != ConditionState.Fulfilled.value:
                logger.debug('ServiceAgreement %s was not paid. Forbidden' % agreement_id)
                return 'ServiceAgreement %s was not paid, LockRewardCondition status is %d' \
                       % (agreement_id, lockreward_condition_status), 401

            if access_condition_status != ConditionState.Fulfilled.value:
                logger.debug('Fulfilling Access condition %s' % agreement_id)
                keeper.access_secret_store_condition.fulfill(
                    agreement_id, asset_id, consumer_address, provider_acc
                )

            if escrowreward_condition_status != ConditionState.Fulfilled.value:
                logger.debug('Fulfilling EscrowReward condition %s' % agreement_id)
                service_agreement = asset.get_service(ServiceTypes.ASSET_ACCESS)
                did_owner = keeper.agreement_manager.get_agreement_did_owner(agreement_id)
                access_id, lock_id = cond_ids[:2]
                keeper.escrow_reward_condition.fulfill(
                    agreement_id,
                    service_agreement.get_price(),
                    Web3Provider.get_web3().toChecksumAddress(did_owner),
                    consumer_address,
                    lock_id,
                    access_id,
                    provider_acc
                )

            iteration = 0
            access_granted = False
            while iteration < ConfigSections.PING_ITERATIONS:
                iteration = iteration + 1
                logger.debug('Checking if access was granted. Iteration %d' % iteration)
                if not is_access_granted(agreement_id, did, consumer_address, keeper):
                    time.sleep(ConfigSections.PING_SLEEP / 1000)
                else:
                    access_granted = True
                    break

            if not access_granted:
                msg = ('Checking access permissions failed. Either consumer address does not have '
                       'permission to consume this asset or consumer address and/or service agreement '
                       'id is invalid.')
                logger.warning(msg)
                return msg, 401

        file_attributes = asset.metadata['main']['files'][index]
        content_type = file_attributes.get('contentType', None)

        try:
            auth_method = asset.authorization['attributes']['main']['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = ('The Authorization Method defined in the DDO is not part of the available methods supported'
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
def execute(agreement_id):
    """Call the execution of a workflow.
    swagger_from_file: docs/execute.yml
    """

    try:
        consumer_address = request.headers.get('X-Consumer-Address')
        workflow_did = request.headers.get('X-Workflow-DID')
        signature = request.headers.get('X-Signature')

        if not consumer_address or not workflow_did or not signature:
            return 'Unable to get params from headers', 401
    except Exception:
        return 'Unable to retrieve required parameters', 401

    try:
        keeper = keeper_instance()

        asset_id = keeper_instance().agreement_manager.get_agreement(agreement_id).did
        did = id_to_did(asset_id)
        asset = DIDResolver(keeper.did_registry).resolve(did)

        if not was_compute_triggered(agreement_id, did, consumer_address, keeper_instance()):

            agreement = keeper.agreement_manager.get_agreement(agreement_id)
            cond_ids = agreement.condition_ids

            compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            lockreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
            escrowreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            logger.debug('ComputeExecutionCondition: %d' % compute_condition_status)
            logger.debug('LockRewardCondition: %d' % lockreward_condition_status)
            logger.debug('EscrowRewardCondition: %d' % escrowreward_condition_status)

            if lockreward_condition_status != ConditionState.Fulfilled.value:
                logger.debug('ServiceAgreement %s was not paid. Forbidden' % agreement_id)
                return 'ServiceAgreement %s was not paid, LockRewardCondition status is %d' \
                       % (agreement_id, lockreward_condition_status), 401

            if compute_condition_status != ConditionState.Fulfilled.value:
                logger.debug('Fulfilling Compute Execution condition %s' % agreement_id)
                keeper.access_secret_store_condition.fulfill(
                    agreement_id, asset_id, consumer_address, provider_acc
                )

            if escrowreward_condition_status != ConditionState.Fulfilled.value:
                logger.debug('Fulfilling EscrowReward condition %s' % agreement_id)
                service_agreement = asset.get_service(ServiceTypes.CLOUD_COMPUTE)
                did_owner = keeper.agreement_manager.get_agreement_did_owner(agreement_id)
                compute_id, lock_id = cond_ids[:2]
                keeper.escrow_reward_condition.fulfill(
                    agreement_id,
                    service_agreement.get_price(),
                    Web3Provider.get_web3().toChecksumAddress(did_owner),
                    consumer_address,
                    lock_id,
                    compute_id,
                    provider_acc
                )

            iteration = 0
            access_granted = False
            while iteration < ConfigSections.PING_ITERATIONS:
                iteration = iteration + 1
                logger.debug('Checking if compute was granted. Iteration %d' % iteration)
                if not is_access_granted(agreement_id, did, consumer_address, keeper):
                    time.sleep(ConfigSections.PING_SLEEP / 1000)
                else:
                    access_granted = True
                    break

            if not access_granted:
                msg = (
                    'Scheduling the compute execution failed. Either consumer address does not '
                    'have permission to execute this workflow or consumer address and/or service '
                    'agreement id is invalid.')
                logger.warning(msg)
                return msg, 401

        workflow = DIDResolver(keeper_instance().did_registry).resolve(workflow_did)
        body = {"serviceAgreementId": agreement_id, "workflow": workflow.as_dictionary()}

        response = requests_session.post(
            get_config().operator_service_url + '/api/v1/operator/init',
            data=json.dumps(body),
            headers={'content-type': 'application/json'})
        return jsonify({"workflowId": response.content.decode('utf-8')})

    except Exception as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500


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
            auth_method = asset.authorization['attributes']['main']['service']
        except Exception:
            auth_method = constants.ConfigSections.DEFAULT_DECRYPTION_METHOD

        if auth_method not in constants.ConfigSections.DECRYPTION_METHODS:
            msg = ('The Authorization Method defined in the DDO is not part of the available methods supported'
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
            get_config().operator_service_url + '/api/v1/operator/init',
            data=json.dumps(body),
            headers={'content-type': 'application/json'})
        return jsonify({"workflowId": response.content.decode('utf-8')})
    except Exception as e:
        logger.error(f'Error- {str(e)}', exc_info=1)
        return f'Error : {str(e)}', 500
