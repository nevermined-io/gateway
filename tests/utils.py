import json
from nevermined_gateway.snark_util import poseidon_hash
import uuid
from urllib.request import urlopen
from pathlib import Path
import time

from common_utils_py.agreements.service_factory import ServiceDescriptor, ServiceFactory
from common_utils_py.agreements.service_types import ServiceAuthorizationTypes, ServiceTypes
from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.ddo.ddo import DDO
from common_utils_py.ddo.metadata import MetadataMain
from common_utils_py.ddo.public_key_rsa import PUBLIC_KEY_TYPE_RSA
from common_utils_py.metadata.metadata import Metadata
from common_utils_py.utils.crypto import ecdsa_encryption_from_file, rsa_encryption_from_file
from common_utils_py.utils.utilities import checksum, to_checksum_addresses
from common_utils_py.did import DID, did_to_id_bytes
from eth_utils.hexadecimal import remove_0x_prefix
from metadata_driver_aws.data_plugin import Plugin
from metadata_driver_aws.config_parser import parse_config

from nevermined_gateway.util import do_secret_store_encrypt, get_config, get_provider_key_file, get_provider_password, get_rsa_public_key_file, keeper_instance, web3, get_provider_public_key


def get_sample_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/keyko-io/nevermined-docs/master/docs/architecture/specs'
        '/examples/access/v0.1/ddo1.json').read().decode(
        'utf-8'))


def get_sample_nft_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/keyko-io/nevermined-docs/master/docs/architecture/specs'
        '/examples/access/v0.1/ddo_nft.json').read().decode(
        'utf-8'))


def get_sample_algorithm_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/docs/master/docs/architecture/specs'
        '/examples/metadata/v0.1/ddo-example-algorithm.json').read().decode('utf-8')
    )


def get_sample_workflow_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/docs/master/docs/architecture/specs'
        '/examples/metadata/v0.1/ddo-example-workflow.json').read().decode('utf-8')
    )

def generate_new_id():
    """
    Generate a new id without prefix.

    :return: Id, str
    """
    return uuid.uuid4().hex + uuid.uuid4().hex


def get_file_url():
    return "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"

def get_key():
    return "4e657665726d696e65640a436f707972696768742032303230204b65796b6f20476d62482e0a0a546869732070726f6475637420696e636c75646573"


def write_s3():
    config_path = Path(__file__).parent / "resources/config.ini"
    config = parse_config(config_path.as_posix(), "metadata-driver")
    aws_plugin = Plugin(config)

    bucket_name = f"nevermined-gateway-{int(time.time())}"
    aws_plugin.create_directory(f"s3://{bucket_name}/test")

    test_file_path = (Path(__file__).parent / "resources/TEST.md").as_posix()
    s3_url = f"s3://{bucket_name}/test/TEST.md"
    aws_plugin.upload(test_file_path, s3_url)

    return s3_url


def get_registered_ddo(account, providers=None, auth_service='PSK-RSA', url=get_file_url()):
    ddo = get_sample_ddo()
    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0]['url'] = url
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    escrow_payment_condition = ddo['service'][1]['attributes']['serviceAgreementTemplate']['conditions'][2]
    _amounts = get_param_value_by_name(escrow_payment_condition['parameters'], '_amounts')
    _receivers = to_checksum_addresses(
        get_param_value_by_name(escrow_payment_condition['parameters'], '_receivers'))

    access_service_attributes = {"main": {
        "name": "dataAssetAccessServiceAgreement",
        "creator": account.address,
        "price": metadata[MetadataMain.KEY]['price'],
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated'],
        "_amounts": _amounts,
        "_receivers": _receivers
    }}

    access_service_descriptor = ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])

def get_proof_ddo(account, providers=None, auth_service='PSK-RSA', key=get_key()):
    ddo = get_sample_ddo()
    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0]['url'] = key
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    metadata['additionalInformation'] = {
        "providerKey": get_provider_public_key(),
        "poseidonHash": poseidon_hash(key)
    }

    escrow_payment_condition = ddo['service'][1]['attributes']['serviceAgreementTemplate']['conditions'][2]
    _amounts = get_param_value_by_name(escrow_payment_condition['parameters'], '_amounts')
    _receivers = to_checksum_addresses(
        get_param_value_by_name(escrow_payment_condition['parameters'], '_receivers'))
    access_service_attributes = {
        "main": {
            "name": "dataAssetAccessProofServiceAgreement",
            "creator": account.address,
            "price": metadata[MetadataMain.KEY]['price'],
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated'],
            "_amounts": _amounts,
            "_receivers": _receivers
        }
    }

    access_service_descriptor = ServiceDescriptor.access_proof_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])


def get_nft_ddo(account, providers=None, auth_service='PSK-RSA'):
    ddo = get_sample_nft_ddo()
    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0][
        'url'] = "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos" \
                 "/CoverSongs/shs_dataset_test.txt?" + str(uuid.uuid4())
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    escrow_payment_condition = ddo['service'][1]['attributes']['serviceAgreementTemplate']['conditions'][2]
    _number_nfts = 1
    _amounts = get_param_value_by_name(escrow_payment_condition['parameters'], '_amounts')
    _receivers = to_checksum_addresses(
        get_param_value_by_name(escrow_payment_condition['parameters'], '_receivers'))

    access_service_attributes = {"main": {
        "name": "nftAccessAgreement",
        "creator": account.address,
        "timeout": 3600,
        "price": metadata[MetadataMain.KEY]['price'],
        "_amounts": _amounts,
        "_receivers": _receivers,
        "_numberNfts": str(_number_nfts),
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    access_service_descriptor = ServiceDescriptor.nft_access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor], royalties= 0, cap=10, mint=10)


def get_param_value_by_name(parameters, name):
    """
    Return the value from the conditions parameters given the param name.

    :return: Object
    """
    for p in parameters:
        if p['name'] == name:
            return p['value']


def get_registered_compute_ddo(account, providers=None, auth_service='PSK-RSA'):
    ddo = get_sample_ddo()
    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0][
        'url'] = "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos" \
                 "/CoverSongs/shs_dataset_test.txt"
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    escrow_payment_condition = ddo['service'][1]['attributes']['serviceAgreementTemplate']['conditions'][2]
    _amounts = get_param_value_by_name(escrow_payment_condition['parameters'], '_amounts')
    _receivers = to_checksum_addresses(
        get_param_value_by_name(escrow_payment_condition['parameters'], '_receivers'))

    compute_service_attributes = {
        "main": {
            "name": "dataAssetComputeServiceAgreement",
            "creator": account.address,
            "dataPublished": metadata[MetadataMain.KEY]["dateCreated"],
            "price": metadata[MetadataMain.KEY]["price"],
            "timeout": 86400,
            "_amounts": _amounts,
            "_receivers": _receivers,
            "provider": {}
        }
    }

    compute_service_descriptor = ServiceDescriptor.compute_service_descriptor(
        compute_service_attributes,
        "http://localhost:8050"
    )

    return register_ddo(metadata, account, providers, auth_service, [compute_service_descriptor])


def get_registered_algorithm_ddo(account, providers=None, auth_service='PSK-RSA'):
    metadata = get_sample_algorithm_ddo()['service'][0]['attributes']
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    access_service_attributes = {"main": {
        "name": "dataAssetAccessServiceAgreement",
        "creator": account.address,
        "price": metadata[MetadataMain.KEY]['price'],
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    access_service_descriptor = ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])


def get_registered_workflow_ddo(account, compute_did, algorithm_did, providers=None, auth_service='PSK-RSA'):
    metadata = get_sample_workflow_ddo()['service'][0]['attributes']
    metadata['main']['workflow']['stages'][0]['input'][0]['id'] = compute_did
    metadata['main']['workflow']['stages'][0]['transformation']['id'] = algorithm_did
    metadata['main']['workflow']['checksum'] = str(uuid.uuid4())

    access_service_attributes = {"main": {
        "name": "dataAssetAccessServiceAgreement",
        "creator": account.address,
        "price": metadata[MetadataMain.KEY]['price'],
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    access_service_descriptor = ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])


def register_ddo(metadata, account, providers, auth_service, additional_service_descriptors, royalties=None, cap=None, mint=0):
    keeper = keeper_instance()
    metadata_api = Metadata('http://172.17.0.1:5000')

    ddo = DDO()
    ddo_service_endpoint = metadata_api.get_service_endpoint()

    metadata_service_desc = ServiceDescriptor.metadata_service_descriptor(metadata,
                                                                          ddo_service_endpoint)
    authorization_service_attributes = {"main": {
        "service": auth_service,
        "publicKey": "0xd7"
    }}

    service_descriptors = [ServiceDescriptor.authorization_service_descriptor(
        authorization_service_attributes,
        'http://localhost:12001'
    )]
    service_descriptors += [metadata_service_desc]
    service_descriptors += additional_service_descriptors

    services = ServiceFactory.build_services(service_descriptors)
    checksums = dict()
    for service in services:
        try:
            checksums[str(service.index)] = checksum(service.main)
        except Exception as e:
            pass

    # Adding proof to the ddo.
    ddo.add_proof(checksums, account)

    did_seed = checksum(ddo.proof['checksum'])
    asset_id = keeper.did_registry.hash_did(did_seed, account.address)
    ddo._did = DID.did(asset_id)
    did = ddo._did

    for service in services:
        if service.type == ServiceTypes.ASSET_ACCESS or service.type == ServiceTypes.NFT_ACCESS or service.type == ServiceTypes.ASSET_PROOF_ACCESS:
            access_service = ServiceFactory.complete_access_service(
                did,
                service.service_endpoint,
                service.attributes,
                keeper.access_template.address,
                keeper.escrow_payment_condition.address,
                service.type
            )
            ddo.add_service(access_service)
        elif service.type == ServiceTypes.CLOUD_COMPUTE:
            compute_service = ServiceFactory.complete_compute_service(
                did,
                service.service_endpoint,
                service.attributes,
                keeper.compute_execution_condition.address,
                keeper.escrow_payment_condition.address
            )
            ddo.add_service(compute_service)
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

    if 'files' in metadata['main']:
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

    if mint > 0 or royalties is not None or cap is not None:
        keeper.did_registry.register_mintable_did(
            did_seed,
            checksum=web3().toBytes(hexstr=ddo.asset_id),
            url=ddo_service_endpoint,
            cap=cap,
            royalties=royalties,
            account=account,
            providers=None
        )
        if mint > 0:
            keeper.did_registry.mint(ddo.asset_id, mint, account=account)
    else:
        keeper_instance().did_registry.register(
            did_seed,
            checksum=web3().toBytes(hexstr=ddo.asset_id),
            url=ddo_service_endpoint,
            account=account,
            providers=providers
        )
    metadata_api.publish_asset_ddo(ddo)
    return ddo


def place_order(provider_account, ddo, consumer_account, service_type=ServiceTypes.ASSET_ACCESS):
    keeper = keeper_instance()
    agreement_id = ServiceAgreement.create_new_agreement_id()

    if service_type == ServiceTypes.ASSET_ACCESS:
        agreement_template = keeper.access_template
    elif service_type == ServiceTypes.NFT_SALES:
        agreement_template = keeper.nft_sales_template
    elif service_type == ServiceTypes.CLOUD_COMPUTE:
        agreement_template = keeper.escrow_compute_execution_template
    else:
        raise NotImplementedError("The agreement template could not be created.")

    publisher_address = provider_account.address

    service_agreement = ServiceAgreement.from_ddo(service_type, ddo)
    condition_ids = service_agreement.generate_agreement_condition_ids(
        agreement_id, ddo.asset_id, consumer_account.address, keeper)
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


def lock_payment(agreement_id, did, service_agreement, amounts, receivers, consumer_account, token_address=None):
    keeper = keeper_instance()
    if token_address is None:
        token_address = keeper.token.address

    price = service_agreement.get_price()
    keeper.token.token_approve(keeper.lock_payment_condition.address, price, consumer_account)
    tx_hash = keeper.lock_payment_condition.fulfill(
        agreement_id, did, keeper.escrow_payment_condition.address, token_address, amounts, receivers, consumer_account)
    keeper.lock_payment_condition.get_tx_receipt(tx_hash)