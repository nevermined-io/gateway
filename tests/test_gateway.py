import json
import mimetypes
import uuid
from unittest.mock import MagicMock, Mock

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_factory import ServiceDescriptor, ServiceFactory
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.ddo.ddo import DDO
from common_utils_py.ddo.metadata import MetadataMain
from common_utils_py.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from common_utils_py.did import DID, did_to_id, did_to_id_bytes
from common_utils_py.http_requests.requests_session import get_requests_session
from common_utils_py.metadata.metadata import Metadata
from common_utils_py.utils.utilities import checksum
from contracts_lib_py.utils import add_ethereum_prefix_and_hash_msg
from eth_utils import add_0x_prefix, remove_0x_prefix
from werkzeug.utils import get_content_type

from nevermined_gateway.constants import BaseURLs
from nevermined_gateway.util import (build_download_response, check_auth_token,
                                     do_secret_store_decrypt, do_secret_store_encrypt,
                                     generate_token, get_config, get_download_url,
                                     get_provider_account, is_token_valid, keeper_instance,
                                     verify_signature, web3)
from tests.conftest import get_consumer_account, get_publisher_account, get_sample_ddo

PURCHASE_ENDPOINT = BaseURLs.BASE_GATEWAY_URL + '/services/access/initialize'
SERVICE_ENDPOINT = BaseURLs.BASE_GATEWAY_URL + '/services/consume'


def dummy_callback(*_):
    pass


def get_registered_ddo(account, providers=None):
    keeper = keeper_instance()
    aqua = Metadata('http://localhost:5000')
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['url'] = "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    ddo = DDO()
    ddo_service_endpoint = aqua.get_service_endpoint()

    metadata_service_desc = ServiceDescriptor.metadata_service_descriptor(metadata,
                                                                          ddo_service_endpoint)

    access_service_attributes = {"main": {
        "name": "dataAssetAccessServiceAgreement",
        "creator": account.address,
        "price": metadata[MetadataMain.KEY]['price'],
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    service_descriptors = [ServiceDescriptor.authorization_service_descriptor(
        'http://localhost:12001')]
    service_descriptors += [ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )]

    service_descriptors = [metadata_service_desc] + service_descriptors

    services = ServiceFactory.build_services(service_descriptors)
    checksums = dict()
    for service in services:
        checksums[str(service.index)] = checksum(service.main)

    # Adding proof to the ddo.
    ddo.add_proof(checksums, account)

    did = ddo.assign_did(DID.did(ddo.proof['checksum']))

    access_service = ServiceFactory.complete_access_service(did,
                                                            'http://localhost:8030',
                                                            access_service_attributes,
                                                            keeper.escrow_access_secretstore_template.address,
                                                            keeper.escrow_reward_condition.address)
    for service in services:
        if service.type == 'access':
            ddo.add_service(access_service)
        else:
            ddo.add_service(service)

    ddo.proof['signatureValue'] = keeper.sign_hash(did_to_id_bytes(did), account)

    ddo.add_public_key(did, account.address)

    ddo.add_authentication(did, PUBLIC_KEY_TYPE_RSA)

    try:
        _oldddo = aqua.get_asset_ddo(ddo.did)
        if _oldddo:
            aqua.retire_asset_ddo(ddo.did)
    except ValueError:
        pass

    encrypted_files = do_secret_store_encrypt(
        remove_0x_prefix(ddo.asset_id),
        json.dumps(metadata['main']['files']),
        account,
        get_config()
    )
    _files = metadata['main']['files']
    # only assign if the encryption worked
    if encrypted_files:
        index = 0
        for file in metadata['main']['files']:
            file['index'] = index
            index = index + 1
            del file['url']
        metadata['encryptedFiles'] = encrypted_files

    keeper_instance().did_registry.register(
        ddo.asset_id,
        checksum=web3().toBytes(hexstr=ddo.asset_id),
        url=ddo_service_endpoint,
        account=account,
        providers=providers
    )
    aqua.publish_asset_ddo(ddo)
    return ddo


def place_order(publisher_account, ddo, consumer_account):
    keeper = keeper_instance()
    agreement_id = ServiceAgreement.create_new_agreement_id()
    agreement_template = keeper.escrow_access_secretstore_template
    publisher_address = publisher_account.address
    # balance = keeper.token.get_token_balance(consumer_account.address)/(2**18)
    # if balance < 20:
    #     keeper.dispenser.request_tokens(100, consumer_account)

    service_agreement = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    condition_ids = service_agreement.generate_agreement_condition_ids(
        agreement_id, ddo.asset_id, consumer_account.address, publisher_address, keeper)
    time_locks = service_agreement.conditions_timelocks
    time_outs = service_agreement.conditions_timeouts
    agreement_template.create_agreement(
        agreement_id,
        ddo.asset_id,
        condition_ids,

        time_locks,
        time_outs,
        consumer_account.address,
        consumer_account
    )

    return agreement_id


def lock_reward(agreement_id, service_agreement, consumer_account):
    keeper = keeper_instance()
    price = service_agreement.get_price()
    keeper.token.token_approve(keeper.lock_reward_condition.address, price, consumer_account)
    tx_hash = keeper.lock_reward_condition.fulfill(
        agreement_id, keeper.escrow_reward_condition.address, price, consumer_account)
    keeper.lock_reward_condition.get_tx_receipt(tx_hash)


def grant_access(agreement_id, ddo, consumer_account, publisher_account):
    keeper = keeper_instance()
    tx_hash = keeper.access_secret_store_condition.fulfill(
        agreement_id, ddo.asset_id, consumer_account.address, publisher_account
    )
    keeper.access_secret_store_condition.get_tx_receipt(tx_hash)


def test_consume(client):
    endpoint = BaseURLs.ASSETS_URL + '/consume'

    pub_acc = get_publisher_account()
    cons_acc = get_consumer_account()

    ddo = get_registered_ddo(pub_acc, providers=[pub_acc.address])

    # initialize an agreement
    agreement_id = place_order(pub_acc, ddo, cons_acc)
    payload = dict({
        'serviceAgreementId': agreement_id,
        'consumerAddress': cons_acc.address
    })

    keeper = keeper_instance()
    agr_id_hash = add_ethereum_prefix_and_hash_msg(agreement_id)
    signature = keeper.sign_hash(agr_id_hash, cons_acc)
    index = 0

    event = keeper.escrow_access_secretstore_template.subscribe_agreement_created(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(cons_acc.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50 - consumer_balance, cons_acc)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_reward(agreement_id, sa, cons_acc)
    event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper node's logs"

    grant_access(agreement_id, ddo, cons_acc, pub_acc)
    event = keeper.access_secret_store_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event or keeper.access_secret_store_condition.check_permissions(
        ddo.asset_id, cons_acc.address
    ), f'Failed to get access permission: agreement_id={agreement_id}, ' \
       f'did={ddo.did}, consumer={cons_acc.address}'

    # Consume using decrypted url
    files_list = json.loads(
        do_secret_store_decrypt(did_to_id(ddo.did), ddo.encrypted_files, pub_acc, get_config()))
    payload['url'] = files_list[index]['url']
    request_url = endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])

    response = client.get(
        request_url
    )
    assert response.status == '200 OK'

    # Consume using url index and signature (let the gateway do the decryption)
    payload.pop('url')
    payload['signature'] = signature
    payload['index'] = index
    request_url = endpoint + '?' + '&'.join([f'{k}={v}' for k, v in payload.items()])
    response = client.get(
        request_url
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
                                                               f'expected {pub_address}'
    good = verify_signature(keeper_instance(), pub_address, token, doc_id)
    assert good, f'invalid signature/auth-token {token}, {pub_address}, {doc_id}'


def test_exec_endpoint():
    pass


def test_encryption_ecdsa(client):
    payload = 'message=hola'

    post_response = client.post(
        BaseURLs.ASSETS_URL + '/encrypt-ecdsa?' + payload,
        data='',
        content_type='application/json'
    )
    assert post_response.status_code == 200

    result = json.loads(post_response.data.decode('utf-8'))
    print(result)
    assert len(result['hash']) > 1
    assert len(result['public-key']) > 1


def test_encryption_rsa(client):
    payload = 'message=hola'

    post_response = client.post(
        BaseURLs.ASSETS_URL + '/encrypt-rsa?' + payload,
        data='',
        content_type='application/json'
    )
    assert post_response.status_code == 200

    result = json.loads(post_response.data.decode('utf-8'))
    print(result)
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
