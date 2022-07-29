import copy
import json

from contracts_lib_py.wallet import Wallet
from eth_utils import to_checksum_address

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

from nevermined_gateway.util import do_secret_store_encrypt, get_config, get_provider_key_file, get_provider_password, \
    get_rsa_public_key_file, keeper_instance, web3, get_provider_public_key, get_buyer_public_key
import ssl

ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

def get_sample_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/nvm-docs/main/docs/architecture/specs/examples/access/v0.1/ddo1.json',
        context=ssl_context).read().decode('utf-8'))


def get_sample_nft_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/nvm-docs/main/docs/architecture/specs/examples/access/v0.1/ddo_nft.json',
        context=ssl_context).read().decode('utf-8'))

def get_sample_nft721_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/nvm-docs/main/docs/architecture/specs/examples/nft/ddo_nft721.json',
        context=ssl_context).read().decode('utf-8'))

def get_sample_algorithm_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/nvm-docs/main/docs/architecture/specs/examples/metadata/v0.1/ddo-example-algorithm.json',
        context=ssl_context).read().decode('utf-8'))


def get_sample_workflow_ddo():
    return json.loads(urlopen(
        'https://raw.githubusercontent.com/nevermined-io/nvm-docs/main/docs/architecture/specs/examples/metadata/v0.1/ddo-example-workflow.json',
        context=ssl_context).read().decode('utf-8'))


def generate_new_id():
    """
    Generate a new id without prefix.

    :return: Id, str
    """
    return uuid.uuid4().hex + uuid.uuid4().hex


def get_file_url():
    return "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos/CoverSongs/shs_dataset_test.txt"


def get_key():
    return "23fefefefefefefefefeefefefefefefef2323abababababababab"


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
        "price": str(metadata[MetadataMain.KEY]['price']),
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
    hash = poseidon_hash(key)
    providerKey = get_provider_public_key()
    metadata['additionalInformation'] = {
        "providerKey": {
            "x": providerKey[0],
            "y": providerKey[1]
        },
        "poseidonHash": hash
    }

    escrow_payment_condition = ddo['service'][1]['attributes']['serviceAgreementTemplate']['conditions'][2]
    _amounts = get_param_value_by_name(escrow_payment_condition['parameters'], '_amounts')
    _receivers = to_checksum_addresses(
        get_param_value_by_name(escrow_payment_condition['parameters'], '_receivers'))
    access_service_attributes = {
        "main": {
            "name": "dataAssetAccessProofServiceAgreement",
            "creator": account.address,
            "price": str(metadata[MetadataMain.KEY]['price']),
            "timeout": 3600,
            "datePublished": metadata[MetadataMain.KEY]['dateCreated'],
            "_amounts": _amounts,
            "_tokenAddress": "",
            "_hash": hash,
            "_providerPub": providerKey,
            "_receivers": _receivers
        }
    }

    access_service_descriptor = ServiceDescriptor.access_proof_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])


def sign_and_send_tx(web3, construct_txn, account):
    signed_tx = Wallet(web3, account.key_file, account.password).sign_tx(construct_txn)
    tx_hash = web3.eth.send_raw_transaction(signed_tx)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    print(f'Tx successful with hash: { tx_receipt.transactionHash.hex() }')
    return tx_receipt


def deploy_contract(web3, abi_path, account):
    with open(abi_path, 'r') as abi_file:
        abi_dict = json.load(abi_file)

    wallet = Wallet(web3, account.key_file, account.password, address=account.address)

    _contract = web3.eth.contract(abi=abi_dict['abi'], bytecode=abi_dict['bytecode'])
    construct_txn = _contract.constructor('NFTSubscription', 'NVM').buildTransaction(
        {
            'from': account.address,
            'gasPrice': web3.eth.gas_price,
        }
    )
    signed_tx = wallet.sign_tx(construct_txn)
    tx_hash = web3.eth.send_raw_transaction(signed_tx)
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    print(f'Contract deployed at address: { tx_receipt.contractAddress }')
    time.sleep(10)

    initialize_txn = _contract.functions.initialize('NFTSubscription', 'NVM').buildTransaction(
        {
            'from': account.address,
            'to': tx_receipt.contractAddress,
            'gasPrice': web3.eth.gas_price,
        }
    )
    sign_and_send_tx(web3, initialize_txn, account)

    return tx_receipt.contractAddress


def grant_role_nft721(web3, abi_path, contract_address, transfer_nft_address, account):
    with open(abi_path, 'r') as abi_file:
        abi_dict = json.load(abi_file)

    _contract = web3.eth.contract(address=contract_address, abi=abi_dict['abi'])

    contract_owner = _contract.functions.owner().call()
    print('Current owner is {}'.format(contract_owner))

    print('Trying to add minter with address {}'.format(transfer_nft_address))
    construct_txn = _contract.functions.addMinter(transfer_nft_address).buildTransaction(
        {
            'from': account.address,
            'gasPrice': web3.eth.gas_price,
        }
    )
    sign_and_send_tx(web3, construct_txn, account)

    time.sleep(3)


def approve_all_nft721(web3, abi_path, contract_address, provider_address, account):
    with open(abi_path, 'r') as abi_file:
        abi_dict = json.load(abi_file)

    _contract = web3.eth.contract(address=contract_address, abi=abi_dict['abi'])

    contract_owner = _contract.functions.owner().call()
    print('Current owner is {}'.format(contract_owner))

    is_approved = _contract.functions.isApprovedForAll(contract_owner, provider_address).call()
    print('Is address {} approved? {}'.format(provider_address, is_approved))

    print('Trying to approve address {}'.format(provider_address))
    construct_txn = _contract.functions.setApprovalForAll(provider_address, True).buildTransaction(
        {
            'from': account.address,
            'gasPrice': web3.eth.gas_price,
        }
    )
    sign_and_send_tx(web3, construct_txn, account)
    time.sleep(3)

    is_approved = _contract.functions.isApprovedForAll(contract_owner, provider_address).call()
    print('Is address {} approved? {}'.format(provider_address, is_approved))


def get_nft_ddo(account, providers=None, auth_service='PSK-RSA', is_1155=True, nft_contract_address=None,
                access_service=True, sales_service=True):
    nft_type = None
    to_mint = 10
    if is_1155:
        ddo = get_sample_nft_ddo()
        if nft_contract_address is None:
            nft_contract_address = keeper_instance().did_registry.get_erc1155_address()
    else:
        nft_type = '721'
        to_mint = 0
        ddo = get_sample_nft721_ddo()
        if nft_contract_address is None:
            nft_contract_address = keeper_instance().did_registry.get_erc721_address()

    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0][
        'url'] = "https://raw.githubusercontent.com/tbertinmahieux/MSongsDB/master/Tasks_Demos" \
                 "/CoverSongs/shs_dataset_test.txt?" + str(uuid.uuid4())
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())
    metadata['main']['files'][0]['contentType'] = 'text/text'

    _number_nfts = 1
    _duration = 1000000  # Number of blocks of duration of the subscription
    _amounts = ['9']
    _receivers = to_checksum_addresses([account.address])

    _nftHolder = to_checksum_address(account.address)
    _total_price = str(sum(int(x) for x in _amounts))

    metadata['main']['price'] = _total_price
    access_service_attributes = {"main": {
        "name": "nftAccessAgreement",
        "creator": account.address,
        "timeout": 3600,
        "price": _total_price,
        "_amounts": _amounts,
        "_receivers": _receivers,
        "_numberNfts": str(_number_nfts),
        "_contractAddress": nft_contract_address,
        "_tokenAddress": "",
        "datePublished": metadata['main']['dateCreated']
    }}

    sales_service_attributes = copy.deepcopy(access_service_attributes)
    sales_service_attributes['main']['name'] = 'nftSalesAgreement'
    sales_service_attributes['main']['_nftHolder'] = _nftHolder
    sales_service_attributes['main']['_nftTransfer'] = 'false'
    sales_service_attributes['main']['_duration'] = str(_duration)

    list_services = []
    if sales_service:
        nft_sales_service_descriptor = ServiceDescriptor.nft_sales_service_descriptor(
            sales_service_attributes,
            'http://localhost:8030',
            is_1155
        )
        list_services.append(nft_sales_service_descriptor)
    if access_service:
        nft_access_service_descriptor = ServiceDescriptor.nft_access_service_descriptor(
            access_service_attributes,
            'http://localhost:8030',
            is_1155
        )
        list_services.append(nft_access_service_descriptor)

    return register_ddo(metadata, account, providers, auth_service,
                        list_services,
                        royalties=0, cap=10, mint=to_mint, nft_type=nft_type)


def get_nft_proof_ddo(account, providers=None, auth_service='PSK-RSA', key=get_key()):
    ddo = get_sample_nft_ddo()
    nft_contract_address = keeper_instance().did_registry.get_erc1155_address()
    metadata = ddo['service'][0]['attributes']
    metadata['main']['files'][0]['url'] = key
    metadata['main']['files'][0]['checksum'] = str(uuid.uuid4())

    _number_nfts = 1
    _amounts = ['9']
    _receivers = to_checksum_addresses([account.address])

    _nftHolder = to_checksum_address(account.address)
    _total_price = str(sum(int(x) for x in _amounts))

    metadata['main']['price'] = _total_price

    hash = poseidon_hash(key)
    providerKey = get_provider_public_key()
    metadata['additionalInformation'] = {
        "providerKey": {
            "x": providerKey[0],
            "y": providerKey[1]
        },
        "poseidonHash": hash
    }

    access_service_attributes = {"main": {
        "name": "nftAccessAgreement",
        "creator": account.address,
        "timeout": 3600,
        "price": _total_price,
        "_amounts": _amounts,
        "_receivers": _receivers,
        "_contractAddress": nft_contract_address,
        "_hash": hash,
        "_providerPub": providerKey,
        "_numberNfts": str(_number_nfts),
        "_tokenAddress": "",
        "datePublished": metadata['main']['dateCreated']
    }}

    sales_service_attributes = copy.deepcopy(access_service_attributes)
    sales_service_attributes['main']['name'] = 'nftSalesWithAccessAgreement'
    sales_service_attributes['main']['_nftHolder'] = _nftHolder

    nft_sales_service_descriptor = ServiceDescriptor.nft_sales_with_access_service_descriptor(
        sales_service_attributes,
        'http://localhost:8030'
    )
    access_service_descriptor = ServiceDescriptor.nft_access_proof_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [nft_sales_service_descriptor, access_service_descriptor], royalties= 0, cap=100, mint=10)


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
            "price": str(metadata[MetadataMain.KEY]["price"]),
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
        "price": str(metadata[MetadataMain.KEY]['price']),
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
        "price": str(metadata[MetadataMain.KEY]['price']),
        "timeout": 3600,
        "datePublished": metadata[MetadataMain.KEY]['dateCreated']
    }}

    access_service_descriptor = ServiceDescriptor.access_service_descriptor(
        access_service_attributes,
        'http://localhost:8030'
    )

    return register_ddo(metadata, account, providers, auth_service, [access_service_descriptor])


def register_ddo(metadata, account, providers, auth_service, additional_service_descriptors, royalties=None, cap=None,
                 mint=0, nft_type=None):
    keeper = keeper_instance()
    metadata_api = Metadata('http://172.17.0.1:3100', account)

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
        if service.type == ServiceTypes.ASSET_ACCESS or service.type == ServiceTypes.NFT_ACCESS or service.type == ServiceTypes.NFT721_ACCESS or service.type == ServiceTypes.ASSET_ACCESS_PROOF or service.type == ServiceTypes.NFT_ACCESS_PROOF:
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
        elif service.type == ServiceTypes.NFT_SALES or service.type == ServiceTypes.NFT721_SALES or service.type == ServiceTypes.NFT_SALES_WITH_ACCESS:
            nft_sales_service = ServiceFactory.complete_nft_sales_service(
                did,
                service.service_endpoint,
                service.attributes,
                keeper.nft_sales_template.address,
                keeper.escrow_payment_condition.address,
                service.type
            )
            ddo.add_service(nft_sales_service)
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

    ddo_with_did = DDO(did, json_text=ddo.as_text().replace('/{did}', '/' + did))
    ddo_service_endpoint = ddo_service_endpoint.replace('/{did}', '/' + did)

    if mint > 0 or royalties is not None or cap is not None or nft_type is not None:
        if nft_type == '721':
            keeper.did_registry.register_mintable_did721(
                did_seed,
                checksum=web3().toBytes(hexstr=ddo.asset_id),
                url=ddo_service_endpoint,
                royalties=royalties,
                account=account,
                providers=providers
            )
            if mint > 0:
                keeper.did_registry.mint721(ddo.asset_id, account.address, account=account)
        else:
            keeper.did_registry.register_mintable_did(
                did_seed,
                checksum=web3().toBytes(hexstr=ddo.asset_id),
                url=ddo_service_endpoint,
                cap=cap,
                royalties=royalties,
                account=account,
                providers=providers
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
    metadata_api.publish_asset_ddo(ddo_with_did)
    return ddo_with_did


def place_order(provider_account, ddo, consumer_account, service_type=ServiceTypes.ASSET_ACCESS):
    keeper = keeper_instance()
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    if service_type == ServiceTypes.ASSET_ACCESS:
        agreement_template = keeper.access_template
    elif service_type == ServiceTypes.ASSET_ACCESS_PROOF:
        agreement_template = keeper.access_proof_template
    elif service_type == ServiceTypes.NFT_SALES or service_type == ServiceTypes.NFT721_SALES:
        agreement_template = keeper.nft_sales_template
    elif service_type == ServiceTypes.CLOUD_COMPUTE:
        agreement_template = keeper.escrow_compute_execution_template
    else:
        raise NotImplementedError("The agreement template could not be created.")

    publisher_address = provider_account.address

    service_agreement = ServiceAgreement.from_ddo(service_type, ddo)

    if service_type == ServiceTypes.ASSET_ACCESS_PROOF:
      consumer_pub = get_buyer_public_key()
      (agreement_id, id1, id2, id3) = service_agreement.generate_agreement_condition_ids(
          agreement_id_seed, ddo.asset_id, consumer_account.address, keeper, init_agreement_address=consumer_account.address, babyjub_pk=consumer_pub)
    else:
      (agreement_id, id1, id2, id3) = service_agreement.generate_agreement_condition_ids(
          agreement_id_seed, ddo.asset_id, consumer_account.address, keeper, init_agreement_address=consumer_account.address)

    time_locks = service_agreement.conditions_timelocks
    time_outs = service_agreement.conditions_timeouts
    agreement_template.create_agreement(
        agreement_id[0],
        ddo.asset_id,
        [id1[0], id2[0], id3[0]],
        time_locks,
        time_outs,
        consumer_account.address,
        consumer_account
    )

    return agreement_id[1]


def lock_payment(agreement_id, did, service_agreement, amounts, receivers, consumer_account, token_address=None):
    keeper = keeper_instance()
    if token_address is None:
        token_address = keeper.token.address

    print('TOKEN ADDRESS = ' + token_address)
    price = service_agreement.get_price()
    keeper.token.token_approve(keeper.lock_payment_condition.address, price, consumer_account)
    tx_hash = keeper.lock_payment_condition.fulfill(
        agreement_id, did, keeper.escrow_payment_condition.address, token_address, amounts, receivers, consumer_account)
    keeper.lock_payment_condition.get_tx_receipt(tx_hash)
