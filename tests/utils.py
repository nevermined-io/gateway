import json
import uuid
from urllib.request import urlopen

from common_utils_py.agreements.service_factory import ServiceDescriptor, ServiceFactory
from common_utils_py.agreements.service_types import ServiceAuthorizationTypes, ServiceTypes
from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.ddo.ddo import DDO
from common_utils_py.ddo.metadata import MetadataMain
from common_utils_py.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from common_utils_py.metadata.metadata import Metadata
from common_utils_py.utils.crypto import ecdsa_encryption_from_file, rsa_encryption_from_file
from common_utils_py.utils.utilities import checksum
from common_utils_py.did import DID, did_to_id_bytes
from eth_utils.hexadecimal import remove_0x_prefix

from nevermined_gateway.util import do_secret_store_encrypt, get_config, get_provider_key_file, get_provider_password, get_rsa_public_key_file, keeper_instance, web3


def get_sample_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/keyko-io/nevermined-docs/master/docs/architecture/specs'
        '/examples/access/v0.1/ddo1.json').read().decode(
        'utf-8'))


def get_registered_ddo(account, providers=None, auth_service='SecretStore'):
    keeper = keeper_instance()
    metadata_api = Metadata('http://localhost:5000')
    metadata = get_sample_ddo()['service'][0]['attributes']
    metadata['main']['files'][0][
        'url'] = "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos" \
                 "/CoverSongs/shs_dataset_test.txt"
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    ddo = DDO()
    ddo_service_endpoint = metadata_api.get_service_endpoint()

    metadata_service_desc = ServiceDescriptor.metadata_service_descriptor(metadata,
                                                                          ddo_service_endpoint)
    authorization_service_attributes = {"main": {
        "service": auth_service,
        "publicKey": "0xd7"
    }}

    access_service_attributes = {"main": {
        "name": "dataAssetAccessServiceAgreement",
        "creator": account.address,
        "price": metadata[MetadataMain.KEY]['price'],
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    service_descriptors = [ServiceDescriptor.authorization_service_descriptor(
        authorization_service_attributes,
        'http://localhost:12001'
    )]
    service_descriptors += [ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )]

    service_descriptors = [metadata_service_desc] + service_descriptors

    services = ServiceFactory.build_services(service_descriptors)
    checksums = dict()
    for service in services:
        try:
            checksums[str(service.index)] = checksum(service.main)
        except Exception as e:
            pass

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
        _oldddo = metadata_api.get_asset_ddo(ddo.did)
        if _oldddo:
            metadata_api.retire_asset_ddo(ddo.did)
    except ValueError:
        pass

    if auth_service == ServiceAuthorizationTypes.SECRET_STORE:
        encrypted_files = do_secret_store_encrypt(
            remove_0x_prefix(ddo.asset_id),
            json.dumps(metadata['main']['files']),
            account,
            get_config()
        )
    elif auth_service == ServiceAuthorizationTypes.PSK_RSA:
        encrypted_files, public_key = rsa_encryption_from_file(
            json.dumps(metadata['main']['files']), get_rsa_public_key_file())
    else:
        encrypted_files, public_key = ecdsa_encryption_from_file(
            json.dumps(metadata['main']['files']), get_provider_key_file(), get_provider_password())

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
    metadata_api.publish_asset_ddo(ddo)
    return ddo


def place_order(provider_account, ddo, consumer_account):
    keeper = keeper_instance()
    agreement_id = ServiceAgreement.create_new_agreement_id()
    agreement_template = keeper.escrow_access_secretstore_template
    publisher_address = provider_account.address
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