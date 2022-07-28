import json
import time

import web3
from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import did_to_id_bytes
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_access_grant_token, \
    generate_access_proof_grant_token
from eth_utils import to_checksum_address

from conditions import is_nft721_holder
from nevermined_gateway.constants import BaseURLs, ConditionState
from nevermined_gateway.util import get_buyer_public_key, get_buyer_secret_key, get_provider_account, keeper_instance
from .utils import get_nft_ddo, lock_payment, get_nft_proof_ddo, deploy_contract, grant_role_nft721, approve_all_nft721


def test_nft_access(client, provider_account, consumer_account, publisher_account):
    keeper = keeper_instance()
    ddo = get_nft_ddo(provider_account, providers=[provider_account.address])
    asset_id = ddo.asset_id
    nft_amounts = 1

    keeper.nft_upgradeable.transfer_nft(asset_id, consumer_account.address, nft_amounts, provider_account)

    assert keeper.nft_upgradeable.balance(consumer_account.address, asset_id) >= nft_amounts

    nft_access_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_ACCESS, ddo)
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    (agreement_id, nft_access_cond_id, nft_holder_cond_id) = nft_access_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed, asset_id, consumer_account.address, keeper, consumer_account.address, consumer_account.address)

    print('NFT_ACCESS_DID: ' + asset_id)

    keeper.nft_access_template.create_agreement(
        agreement_id[0],
        asset_id,
        [nft_holder_cond_id[0], nft_access_cond_id[0]],
        nft_access_service_agreement.conditions_timelocks,
        nft_access_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )
    event = keeper.nft_access_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    # generate the grant token
    grant_token = generate_access_grant_token(consumer_account, agreement_id[1], ddo.did, uri="/nft-access")

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]
    index = 0
    endpoint = BaseURLs.ASSETS_URL + '/nft-access/%s/%d' % (agreement_id, index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'
    assert len(keeper.did_registry.get_provenance_method_events('USED', did_bytes=did_to_id_bytes(ddo.did))) >= 1


def test_nft_access_no_agreement(client, provider_account, consumer_account):
    ddo = get_nft_ddo(provider_account, providers=[provider_account.address])
    nft_amounts = 1

    keeper = keeper_instance()
    keeper.nft_upgradeable.transfer_nft(ddo.asset_id, consumer_account.address, nft_amounts, provider_account)

    no_agreement_id = '0x'
    # generate the grant token
    grant_token = generate_access_grant_token(consumer_account, no_agreement_id, ddo.did, uri="/nft-access")

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]
    index = 0
    endpoint = BaseURLs.ASSETS_URL + '/nft-access/%s/%d' % (no_agreement_id, index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'
    assert len(keeper.did_registry.get_provenance_method_events('USED', did_bytes=did_to_id_bytes(ddo.did))) >= 1


def test_nft_access_no_balance(client, provider_account, consumer_account):
    ddo = get_nft_ddo(provider_account, providers=[provider_account.address])

    no_agreement_id = '0x'
    # generate the grant token
    grant_token = generate_access_grant_token(consumer_account, no_agreement_id, ddo.did, uri="/nft-access")

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    assert response.status_code == 400

    index = 0
    access_token = '123'
    endpoint = BaseURLs.ASSETS_URL + '/nft-access/%s/%d' % (no_agreement_id, index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status != '200 OK'


def test_nft_transfer(client, provider_account, consumer_account, publisher_account):
    print('PROVIDER_ACCOUNT= ' + provider_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(provider_account.address)))
    print('PUBLISHER_ACCOUNT= ' + publisher_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(publisher_account.address)))
    print('CONSUMER_ACCOUNT= ' + consumer_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(consumer_account.address)))

    keeper = keeper_instance()
    ddo = get_nft_ddo(publisher_account, providers=[provider_account.address])
    asset_id = ddo.asset_id

    nft_amounts = 1
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    print('NFT_SALES_DID: ' + asset_id)

    nft_sales_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_SALES, ddo)
    (
        agreement_id,
        transfer_nft_condition_id,
        lock_payment_condition_id,
        escrow_payment_condition_id
    ) = nft_sales_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed,
        asset_id,
        consumer_account.address,
        keeper,
        init_agreement_address=consumer_account.address
    )

    keeper.nft_sales_template.create_agreement(
        agreement_id[0],
        asset_id,
        [lock_payment_condition_id[0], transfer_nft_condition_id[0], escrow_payment_condition_id[0]],
        nft_sales_service_agreement.conditions_timelocks,
        nft_sales_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )
    event = keeper.nft_sales_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    cond_ids = [lock_payment_condition_id[1], transfer_nft_condition_id[1], escrow_payment_condition_id[1]]

    keeper.token.token_approve(
        keeper.lock_payment_condition.address,
        nft_sales_service_agreement.get_price(),
        consumer_account
    )

    keeper.dispenser.request_tokens(50, consumer_account)

    lock_payment(
        agreement_id[1],
        ddo.asset_id,
        nft_sales_service_agreement,
        nft_sales_service_agreement.get_amounts_int(),
        nft_sales_service_agreement.get_receivers(),
        consumer_account
    )
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    keeper.nft_upgradeable.set_approval_for_all(
        get_provider_account().address,
        True,
        publisher_account
    )

    time.sleep(10)

    is_approved = keeper.nft_upgradeable.is_approved_for_all(
        publisher_account.address,
        provider_account.address
    )
    assert is_approved is True

    response = client.post(
        BaseURLs.ASSETS_URL + '/nft-transfer',
        json={
            'agreementId': agreement_id[1],
            'nftHolder': publisher_account.address,
            'nftReceiver': consumer_account.address,
            'nftAmount': nft_amounts
        }
    )
    print('GATEWAY TRANSFER STATUS CODE ' + str(response.status_code))
    assert response.status_code == 200

    # Fulfill escrow_payment_condition
    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value


def test_nft721_transfer(client, provider_account, consumer_account, publisher_account):
    print('PROVIDER_ACCOUNT= ' + provider_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(provider_account.address)))
    print('PUBLISHER_ACCOUNT= ' + publisher_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(publisher_account.address)))
    print('CONSUMER_ACCOUNT= ' + consumer_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(consumer_account.address)))

    abi_path = 'tests/resources/NFT721SubscriptionUpgradeable.json'
    keeper = keeper_instance()

    # Deploy NFT721 Contract (Subscription)
    nft_address = to_checksum_address(deploy_contract(web3.Web3(), abi_path, publisher_account))
    # Grant role to TransferNFT721Condition
    grant_role_nft721(web3.Web3(), abi_path, nft_address, keeper.transfer_nft721_condition.address, publisher_account)
    approve_all_nft721(web3.Web3(), abi_path, nft_address, provider_account.address, publisher_account)

    ddo = get_nft_ddo(publisher_account, providers=[provider_account.address], is_1155=False,
                      nft_contract_address=nft_address)
    asset_id = ddo.asset_id

    nft_amounts = 1
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    print('NFT721_SALES_DID: ' + asset_id)

    publisher_balance = keeper.nft721_upgradeable.balance(publisher_account.address)
    print('NFT721 Publisher Balance: {}'.format(publisher_balance))
    try:
        owner_of = keeper.nft721_upgradeable.owner(asset_id)
        print('NFT721 Owner of: {}'.format(owner_of))
    except:
        print('NFT not minted yet!')

    provider_balance = keeper.nft721_upgradeable.balance(provider_account.address)
    print('NFT721 Provider Balance: {}'.format(provider_balance))

    nft_sales_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT721_SALES, ddo)
    (
        agreement_id,
        transfer_nft_condition_id,
        lock_payment_condition_id,
        escrow_payment_condition_id
    ) = nft_sales_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed,
        asset_id,
        consumer_account.address,
        keeper,
        init_agreement_address=consumer_account.address
    )

    keeper.nft721_sales_template.create_agreement(
        agreement_id[0],
        asset_id,
        [lock_payment_condition_id[0], transfer_nft_condition_id[0], escrow_payment_condition_id[0]],
        nft_sales_service_agreement.conditions_timelocks,
        nft_sales_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )

    event = keeper.nft721_sales_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    print(json.dumps([lock_payment_condition_id, transfer_nft_condition_id, escrow_payment_condition_id]))

    cond_ids = [lock_payment_condition_id[1], transfer_nft_condition_id[1], escrow_payment_condition_id[1]]

    print('Agreement ID: {}'.format(agreement_id))

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Unfulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Unfulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Unfulfilled.value

    keeper.token.token_approve(
        keeper.lock_payment_condition.address,
        nft_sales_service_agreement.get_price(),
        consumer_account
    )

    keeper.dispenser.request_tokens(50, consumer_account)

    lock_payment(
        agreement_id[1],
        ddo.asset_id,
        nft_sales_service_agreement,
        nft_sales_service_agreement.get_amounts_int(),
        nft_sales_service_agreement.get_receivers(),
        consumer_account
    )
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    ### TRANSFER NFT ###################################

    # transfer_nft = nft_sales_service_agreement.get_nft_transfer_or_mint()
    # duration = nft_sales_service_agreement.get_duration()

    # fulfill_tx = keeper.transfer_nft721_condition.fulfill_for_delegate(
    #     agreement_id[1],
    #     asset_id,
    #     publisher_account.address,
    #     consumer_account.address,
    #     nft_amounts,
    #     cond_ids[0],
    #     transfer_nft,
    #     nft_address,
    #     duration,
    #     provider_account
    # )
    # worked = keeper.transfer_nft721_condition.is_tx_successful(fulfill_tx, get_revert_message=True)
    # assert worked
    ###################################

    # if not worked:  # Let's try via Gateway
    response = client.post(
        BaseURLs.ASSETS_URL + '/nft-transfer',
        json={
            'agreementId': agreement_id[1],
            'nftHolder': publisher_account.address,
            'nftReceiver': consumer_account.address,
            'nftAmount': nft_amounts,
            'nftType': '721'
        }
    )
    print('GATEWAY TRANSFER STATUS CODE ' + str(response.status_code))
    assert response.status_code == 200

    event = keeper.transfer_nft721_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "TransferNFT721Condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value

    assert is_nft721_holder(keeper, consumer_account.address, nft_address)


def test_e2e_nft_subscription(client, provider_account, consumer_account, publisher_account):
    print('PROVIDER_ACCOUNT= ' + provider_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(provider_account.address)))
    print('PUBLISHER_ACCOUNT= ' + publisher_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(publisher_account.address)))
    print('CONSUMER_ACCOUNT= ' + consumer_account.address + ' is CHECKSUM=' + str(
        web3.Web3.isChecksumAddress(consumer_account.address)))

    abi_path = 'tests/resources/NFT721SubscriptionUpgradeable.json'
    keeper = keeper_instance()

    # Deploy NFT721 Contract (Subscription)
    nft_address = to_checksum_address(deploy_contract(web3.Web3(), abi_path, publisher_account))
    # Grant role to TransferNFT721Condition
    grant_role_nft721(web3.Web3(), abi_path, nft_address, keeper.transfer_nft721_condition.address, publisher_account)
    approve_all_nft721(web3.Web3(), abi_path, nft_address, provider_account.address, publisher_account)

    ddo_subscription = get_nft_ddo(publisher_account, providers=[provider_account.address], is_1155=False,
                                   nft_contract_address=nft_address, access_service=False, sales_service=True)

    nft_amounts = 1
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    print('SUBSCRIPTION DID: ' + ddo_subscription.asset_id)

    ## The Consumer buys the subscription
    nft_sales_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT721_SALES, ddo_subscription)
    (
        agreement_id,
        transfer_nft_condition_id,
        lock_payment_condition_id,
        escrow_payment_condition_id
    ) = nft_sales_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed,
        ddo_subscription.asset_id,
        consumer_account.address,
        keeper,
        init_agreement_address=consumer_account.address
    )

    keeper.nft721_sales_template.create_agreement(
        agreement_id[0],
        ddo_subscription.asset_id,
        [lock_payment_condition_id[0], transfer_nft_condition_id[0], escrow_payment_condition_id[0]],
        nft_sales_service_agreement.conditions_timelocks,
        nft_sales_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )

    event = keeper.nft721_sales_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    cond_ids = [lock_payment_condition_id[1], transfer_nft_condition_id[1], escrow_payment_condition_id[1]]

    print('Agreement ID for the Subscription Purchase: {}'.format(agreement_id))

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Unfulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Unfulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Unfulfilled.value

    keeper.token.token_approve(
        keeper.lock_payment_condition.address,
        nft_sales_service_agreement.get_price(),
        consumer_account
    )

    keeper.dispenser.request_tokens(50, consumer_account)

    lock_payment(
        agreement_id[1],
        ddo_subscription.asset_id,
        nft_sales_service_agreement,
        nft_sales_service_agreement.get_amounts_int(),
        nft_sales_service_agreement.get_receivers(),
        consumer_account
    )
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    response = client.post(
        BaseURLs.ASSETS_URL + '/nft-transfer',
        json={
            'agreementId': agreement_id[1],
            'nftHolder': publisher_account.address,
            'nftReceiver': consumer_account.address,
            'nftAmount': nft_amounts,
            'nftType': '721'
        }
    )
    assert response.status_code == 200

    event = keeper.transfer_nft721_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "TransferNFT721Condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value

    assert is_nft721_holder(keeper, consumer_account.address, nft_address)

    ## Now we publish the report associated to the ERC-721 Subscription contract
    ddo_report = get_nft_ddo(publisher_account, providers=[provider_account.address], is_1155=False,
                             nft_contract_address=nft_address, access_service=True, sales_service=False)

    print('REPORT DID: ' + ddo_report.asset_id)

    no_agreement_id = '0x'
    # generate the grant token
    grant_token = generate_access_grant_token(consumer_account, no_agreement_id, ddo_report.did, uri="/nft-access")

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]
    index = 0
    endpoint = BaseURLs.ASSETS_URL + '/nft-access/%s/%d' % (no_agreement_id, index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'
    assert len(keeper.did_registry.get_provenance_method_events('USED', did_bytes=did_to_id_bytes(ddo_report.did))) >= 1




def test_nft_transfer_proof(client, provider_account, consumer_account, publisher_account):
    print('PROVIDER_ACCOUNT= ' + provider_account.address)
    print('PUBLISHER_ACCOUNT= ' + publisher_account.address)
    print('CONSUMER_ACCOUNT= ' + consumer_account.address)

    keeper = keeper_instance()
    ddo = get_nft_proof_ddo(publisher_account, providers=[provider_account.address])
    asset_id = ddo.asset_id
    nft_amounts = 1
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    print('NFT_SALES_DID: ' + asset_id)

    nft_sales_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_SALES_WITH_ACCESS, ddo)
    (
        agreement_id,
        transfer_nft_condition_id,
        lock_payment_condition_id,
        escrow_payment_condition_id,
        access_condition_id
    ) = nft_sales_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed,
        asset_id,
        consumer_account.address,
        keeper,
        init_agreement_address=consumer_account.address,
        babyjub_pk=get_buyer_public_key()
    )

    keeper.nft_sales_with_access_template.create_agreement(
        agreement_id[0],
        asset_id,
        [lock_payment_condition_id[0], transfer_nft_condition_id[0], escrow_payment_condition_id[0], access_condition_id[0]],
        nft_sales_service_agreement.conditions_timelocks,
        nft_sales_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )
    event = keeper.nft_sales_with_access_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    cond_ids = [lock_payment_condition_id[1], transfer_nft_condition_id[1], escrow_payment_condition_id[1], access_condition_id[1]]

    keeper.token.token_approve(
        keeper.lock_payment_condition.address,
        nft_sales_service_agreement.get_price(),
        consumer_account
    )

    keeper.dispenser.request_tokens(50, consumer_account)

    lock_payment(
        agreement_id[1],
        ddo.asset_id,
        nft_sales_service_agreement,
        nft_sales_service_agreement.get_amounts_int(),
        nft_sales_service_agreement.get_receivers(),
        consumer_account
    )
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper " \
                  "node's logs"

    keeper.nft_upgradeable.set_approval_for_all(
        get_provider_account().address,
        True,
        publisher_account
    )

    time.sleep(10)

    is_approved = keeper.nft_upgradeable.is_approved_for_all(
        publisher_account.address,
        provider_account.address
    )
    assert is_approved is True

    response = client.post(
        BaseURLs.ASSETS_URL + '/nft-transfer-with-access',
        json={
            'agreementId': agreement_id[1],
            'nftHolder': publisher_account.address,
            'nftReceiver': consumer_account.address,
            'buyerPub': get_buyer_public_key(),
            'nftAmount': nft_amounts
        }
    )
    assert response.status_code == 200

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[3]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value


def test_nft_access_proof(client, provider_account, consumer_account, publisher_account):
    keeper = keeper_instance()
    ddo = get_nft_proof_ddo(provider_account, providers=[provider_account.address])
    asset_id = ddo.asset_id
    nft_amounts = 1

    keeper.nft_upgradeable.transfer_nft(asset_id, consumer_account.address, nft_amounts, provider_account)

    assert keeper.nft_upgradeable.balance(consumer_account.address, asset_id) >= nft_amounts

    nft_access_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_ACCESS_PROOF, ddo)
    agreement_id_seed = ServiceAgreement.create_new_agreement_id()

    (agreement_id, nft_access_cond_id, nft_holder_cond_id) = nft_access_service_agreement.generate_agreement_condition_ids(
        agreement_id_seed,
        asset_id,
        consumer_account.address,
        keeper,
        init_agreement_address=consumer_account.address,
        babyjub_pk=get_buyer_public_key()
    )

    print('NFT_ACCESS_DID: ' + asset_id)

    keeper.nft_access_proof_template.create_agreement(
        agreement_id[0],
        asset_id,
        [nft_holder_cond_id[0], nft_access_cond_id[0]],
        nft_access_service_agreement.conditions_timelocks,
        nft_access_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )
    event = keeper.nft_access_proof_template.subscribe_agreement_created(
        agreement_id[1], 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    # generate the grant token
    grant_token = generate_access_proof_grant_token(consumer_account, agreement_id[1], ddo.did, get_buyer_secret_key(), "/nft-access-proof")

    # request access token
    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": grant_token
    })
    access_token = response.get_json()["access_token"]
    index = 0
    endpoint = BaseURLs.ASSETS_URL + '/nft-access-proof/%s/%d' % (agreement_id, index)
    response = client.get(
        endpoint,
        headers={"Authorization": f"Bearer {access_token}"}
    )

    assert response.status == '200 OK'
    assert len(keeper.did_registry.get_provenance_method_events('USED', did_bytes=did_to_id_bytes(ddo.did))) >= 1

