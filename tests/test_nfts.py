from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import did_to_id_bytes
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant, generate_access_grant_token

from nevermined_gateway.constants import BaseURLs
from nevermined_gateway.util import (keeper_instance)
from .utils import get_nft_ddo


def test_nft_access(client, provider_account, consumer_account):
    keeper = keeper_instance()
    ddo = get_nft_ddo(provider_account, providers=[provider_account.address])
    asset_id = ddo.asset_id
    nft_amounts = 1

    keeper.did_registry.transfer_nft(asset_id, consumer_account.address, nft_amounts, provider_account)

    assert keeper.did_registry.balance(consumer_account.address, asset_id) >= nft_amounts

    nft_access_service_agreement = ServiceAgreement.from_ddo(ServiceTypes.NFT_ACCESS, ddo)
    agreement_id = ServiceAgreement.create_new_agreement_id()

    (nft_access_cond_id, nft_holder_cond_id) = nft_access_service_agreement.generate_agreement_condition_ids(
        agreement_id, asset_id, consumer_account.address, keeper)

    keeper.nft_access_template.create_agreement(
        agreement_id,
        asset_id,
        [nft_holder_cond_id, nft_access_cond_id],
        nft_access_service_agreement.conditions_timelocks,
        nft_access_service_agreement.conditions_timeouts,
        consumer_account.address,
        consumer_account
    )
    event = keeper.nft_access_template.subscribe_agreement_created(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Agreement event is not found, check the keeper node's logs"

    # generate the grant token
    grant_token = generate_access_grant_token(consumer_account, agreement_id, ddo.did, uri="/nft-access")

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
    keeper.did_registry.transfer_nft(ddo.asset_id, consumer_account.address, nft_amounts, provider_account)

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
