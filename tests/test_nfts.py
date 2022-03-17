import time
from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import did_to_id_bytes
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_access_grant_token, generate_access_proof_grant_token

from nevermined_gateway.constants import BaseURLs, ConditionState
from nevermined_gateway.util import get_buyer_public_key, get_buyer_secret_key, get_provider_account, keeper_instance, init_account_envvars
from .utils import get_nft_ddo, lock_payment, get_nft_proof_ddo


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
    print('PROVIDER_ACCOUNT= ' + provider_account.address)
    print('PUBLISHER_ACCOUNT= ' + publisher_account.address)
    print('CONSUMER_ACCOUNT= ' + consumer_account.address)

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
        consumer_account.address,
        consumer_account.address
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
    assert response.status_code == 200

    assert keeper.condition_manager.get_condition_state(cond_ids[0]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[1]) == ConditionState.Fulfilled.value
    assert keeper.condition_manager.get_condition_state(cond_ids[2]) == ConditionState.Fulfilled.value

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
        get_buyer_public_key(),
        keeper,
        consumer_account.address,
        consumer_account.address
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
        agreement_id_seed, asset_id, get_buyer_public_key(), keeper, consumer_account.address, consumer_account.address)

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

