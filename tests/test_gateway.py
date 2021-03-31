import json
import mimetypes
import uuid
from unittest.mock import MagicMock, Mock

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.ddo.ddo import DDO
from common_utils_py.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from common_utils_py.did import DID, did_to_id, did_to_id_bytes
from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_access_grant_token, generate_download_grant_token
from contracts_lib_py.utils import add_ethereum_prefix_and_hash_msg
from eth_utils import add_0x_prefix
from metadata_driver_interface.driver_interface import DriverInterface
from werkzeug.utils import get_content_type

from nevermined_gateway import constants
from nevermined_gateway.constants import BaseURLs, ConditionState
from nevermined_gateway.util import (build_download_response, check_auth_token,
                                     generate_token, get_download_url, get_provider_account,
                                     is_token_valid, keeper_instance, verify_signature, web3, get_asset)
from .utils import get_registered_ddo, place_order, lock_payment

PURCHASE_ENDPOINT = BaseURLs.BASE_GATEWAY_URL + '/services/access/initialize'
SERVICE_ENDPOINT = BaseURLs.BASE_GATEWAY_URL + '/services/consume'


def dummy_callback(*_):
    pass


def grant_access(agreement_id, ddo, consumer_account, provider_account):
    keeper = keeper_instance()
    tx_hash = keeper.access_secret_store_condition.fulfill(
        agreement_id, ddo.asset_id, consumer_account.address, provider_account
    )
    keeper.access_secret_store_condition.get_tx_receipt(tx_hash)


def test_consume(client, provider_account, consumer_account):
    endpoint = BaseURLs.ASSETS_URL + '/consume'

    # for method in ['PSK-ECDSA']:
    for method in constants.ConfigSections.DECRYPTION_METHODS:
        print('Testing Consume with Authorization Method: ' + method)
        ddo = get_registered_ddo(provider_account, providers=[provider_account.address], auth_service=method)

        # initialize an agreement
        agreement_id = place_order(provider_account, ddo, consumer_account)
        payload = dict({
            'serviceAgreementId': agreement_id,
            'consumerAddress': consumer_account.address
        })

        print('Provider: ' + provider_account.address)
        print('Consumer: ' + consumer_account.address)

        keeper = keeper_instance()
        agr_id_hash = add_ethereum_prefix_and_hash_msg(agreement_id)
        signature = keeper.sign_hash(agr_id_hash, consumer_account)
        index = 0

        event = keeper.escrow_access_secretstore_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
        assert event, "Agreement event is not found, check the keeper node's logs"

        consumer_balance = keeper.token.get_token_balance(consumer_account.address)
        if consumer_balance < 50:
            keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

        sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
        lock_payment(agreement_id, ddo.did, sa, amounts, receivers, consumer_account)
        event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
        assert event, "Lock reward condition fulfilled event is not found, check the keeper " \
                      "node's logs"

        grant_access(agreement_id, ddo, consumer_account, provider_account)
        event = keeper.access_secret_store_condition.subscribe_condition_fulfilled(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
        assert event or keeper.access_secret_store_condition.check_permissions(
            ddo.asset_id, consumer_account.address
        ), f'Failed to get access permission: agreement_id={agreement_id}, ' \
           f'did={ddo.did}, consumer={consumer_account.address}'

        # Consume using url index and signature (let the gateway do the decryption)
        payload['signature'] = signature
        payload['index'] = index
        request_url = endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
        response = client.get(
            request_url
        )
        assert response.status == '200 OK'


def test_access(client, provider_account, consumer_account):

    for method in constants.ConfigSections.DECRYPTION_METHODS:
        ddo = get_registered_ddo(provider_account, providers=[provider_account.address], auth_service=method)

        # initialize an agreement
        agreement_id = place_order(provider_account, ddo, consumer_account)

        keeper = keeper_instance()
        index = 0

        event = keeper.escrow_access_secretstore_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
        assert event, "Agreement event is not found, check the keeper node's logs"

        consumer_balance = keeper.token.get_token_balance(consumer_account.address)
        if consumer_balance < 50:
            keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

        sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
        lock_payment(agreement_id, sa, consumer_account)
        event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
        assert event, "Lock reward condition fulfilled event is not found, check the keeper node's logs"

        # Consume using url index

        # generate the grant token
        grant_token = generate_access_grant_token(consumer_account, agreement_id, ddo.did)

        # request access token
        response = client.post("/api/v1/gateway/services/oauth/token", data={
            "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
            "assertion": grant_token
        })
        access_token = response.get_json()["access_token"]

        endpoint = BaseURLs.ASSETS_URL + '/access/%s/%d' % (agreement_id, index)
        response = client.get(
            endpoint,
            headers={"Authorization": f"Bearer {access_token}"}
        )

        agreement = keeper.agreement_manager.get_agreement(agreement_id)
        cond_ids = agreement.condition_ids
        assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
        assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
        assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value
        assert response.status == '200 OK'
        assert len(keeper.did_registry.get_provenance_method_events('USED', did_bytes=did_to_id_bytes(ddo.did))) == 1


def test_download(client, provider_account):

    ddo = get_registered_ddo(provider_account, providers=[provider_account.address])
    index = 0

    # generate the grant token
    grant_token = generate_download_grant_token(provider_account, ddo.did)

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]

    endpoint = BaseURLs.ASSETS_URL + '/download/%d' % (index)
    print(endpoint)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'



def test_empty_payload(client):
    consume = client.get(
        BaseURLs.ASSETS_URL + '/consume',
        data=None,
        content_type='application/json'
    )
    assert consume.status_code == 400

    publish = client.post(
        BaseURLs.ASSETS_URL + '/publish',
        data=None,
        content_type='application/json'
    )
    assert publish.status_code == 400


def test_publish(client):
    endpoint = BaseURLs.ASSETS_URL + '/publish'
    did = DID.did({"0": str(uuid.uuid4())})
    asset_id = did_to_id(did)
    account = get_provider_account()
    test_urls = [
        'url 00',
        'url 11',
        'url 22'
    ]
    keeper = keeper_instance()
    urls_json = json.dumps(test_urls)
    asset_id_hash = add_ethereum_prefix_and_hash_msg(asset_id)
    signature = keeper.sign_hash(asset_id_hash, account)
    address = web3().eth.account.recoverHash(asset_id_hash, signature=signature)
    assert address.lower() == account.address.lower()
    address = keeper.personal_ec_recover(asset_id, signature)
    assert address.lower() == account.address.lower()

    payload = {
        'documentId': asset_id,
        'signature': signature,
        'document': urls_json,
        'publisherAddress': account.address
    }
    post_response = client.post(
        endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    encrypted_url = post_response.data.decode('utf-8')
    assert encrypted_url.startswith('0x')

    # publish using auth token
    signature = generate_token(account)
    payload['signature'] = signature
    did = DID.did({"0": str(uuid.uuid4())})
    asset_id = did_to_id(did)
    payload['documentId'] = add_0x_prefix(asset_id)
    post_response = client.post(
        endpoint,
        data=json.dumps(payload),
        content_type='application/json'
    )
    encrypted_url = post_response.data.decode('utf-8')
    assert encrypted_url.startswith('0x')


def test_auth_token():
    token = "0x1d2741dee30e64989ef0203957c01b14f250f5d2f6ccb0" \
            "c88c9518816e4fcec16f84e545094eb3f377b7e214ded226" \
            "76fbde8ca2e41b4eb1b3565047ecd9acf300-1568372035"
    pub_address = "0x62C092047B01630FC7ABAf3Ab07f4b8aDa5EeB35"
    doc_id = "663516d306904651bbcf9fe45a00477c215c7303d8a24c5bad6005dd2f95e68e"
    assert is_token_valid(token), f'cannot recognize auth-token {token}'
    address = check_auth_token(token)
    assert address and address.lower() == pub_address.lower(), f'address mismatch, got {address}, ' \
                                                               f'' \
                                                               f'' \
                                                               f'' \
                                                               f'' \
                                                               f'' \
                                                               f'expected {pub_address}'
    good = verify_signature(keeper_instance(), pub_address, token, doc_id)
    assert good, f'invalid signature/auth-token {token}, {pub_address}, {doc_id}'


def test_execute_endpoint():
    pass


def test_encryption_content(client):
    content = [
        'https://github.com/nevermined-io/321321321321321321321321321321321',
        'https://github.com/nevermined-io/dsadsadsadsadasdasdasdasdasdasdasdas',
        'https://github.com/nevermined-io/321321321321321321321321321321321',
        'https://github.com/nevermined-io/dsadsadsadsadasdasdasdasdasdasdasdas',
        'https://github.com/nevermined-io/321321321321321321321321321321321',
        'https://github.com/nevermined-io/dsadsadsadsadasdasdasdasdasdasdasdas',
        'https://github.com/nevermined-io/321321321321321321321321321321321',
        'https://github.com/nevermined-io/dsadsadsadsadasdasdasdasdasdasdasdas',
        'https://github.com/nevermined-io/321321321321321321321321321321321',
        'https://github.com/nevermined-io/dsadsadsadsadasdasdasdasdasdasdasdas',
        'https://github.com/nevermined-io/h65h5h6hrh6rhrh6rhrhrhrh6rhr6hr66h'
    ]
    message = json.dumps(content)
    print(message)
    did = DID.did({"0": str(uuid.uuid4())})

    for method in constants.ConfigSections.DECRYPTION_METHODS:
        print('Testing encrypt: ' + method)

        payload = {
            'message': message,
            'method': method,
            'did': did
        }
        post_response = client.post(
            BaseURLs.ASSETS_URL + '/encrypt',
            data=json.dumps(payload),
            content_type='application/json'
        )

        assert post_response.status_code == 200
        result = json.loads(post_response.data.decode('utf-8'))
        assert len(result['hash']) > 1
        assert len(result['public-key']) > 1


def test_download_ipfs_file(client):
    cid = 'QmQfpdcMWnLTXKKW9GPV7NgtEugghgD6HgzSF6gSrp2mL9'
    url = f'ipfs://{cid}'
    download_url = get_download_url(url, None)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f'got ipfs download url: {download_url}')
    assert download_url and download_url.endswith(f'ipfs/{cid}')
    response = build_download_response(request, requests_session, download_url, download_url, None)
    assert response.data, f'got no data {response.data}'


def test_download_filecoin_file():
    cid = 'QmW68jbcqSRtqSQb6xkukQ6tfonZGhu1VrZv9zAicNmovs'
    url = f'cid://{cid}'
    download_url = get_download_url(url, None)
    requests_session = get_requests_session()

    request = Mock()
    request.range = None

    print(f'got filecoin download url: {download_url}')
    assert download_url and download_url == url
    response = get_asset(request, requests_session, '', url, None)
    assert response is None # In the local tests we are not using a real connection to a PowerGate node


def test_build_download_response():
    request = Mock()
    request.range = None

    class Dummy:
        pass

    response = Dummy()
    response.content = b'asdsadf'
    response.status_code = 200

    requests_session = Dummy()
    requests_session.get = MagicMock(return_value=response)

    filename = '<<filename>>.xml'
    content_type = mimetypes.guess_type(filename)[0]
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == content_type
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename}'

    filename = '<<filename>>'
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, None)
    assert response.headers["content-type"] == get_content_type(response.default_mimetype,
                                                                response.charset)
    assert response.headers.get_all('Content-Disposition')[0] == f'attachment;filename={filename}'

    filename = '<<filename>>'
    url = f'https://source-lllllll.cccc/{filename}'
    response = build_download_response(request, requests_session, url, url, content_type)
    assert response.headers["content-type"] == content_type
    assert response.headers.get_all('Content-Disposition')[
               0] == f'attachment;filename={filename + mimetypes.guess_extension(content_type)}'
