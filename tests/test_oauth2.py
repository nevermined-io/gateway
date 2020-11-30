import os

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from nevermined_gateway.constants import BaseURLs
from nevermined_gateway.identity.jwk_utils import account_to_jwk
from nevermined_gateway.identity.oauth2.token import NeverminedJWTBearerGrant
from nevermined_gateway.util import keeper_instance

from tests.utils import get_registered_ddo, lock_reward, place_order

# In Production JWT should only be used with https
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"


def test_access_endpoint(client, provider_account, consumer_account):
    # order access
    keeper = keeper_instance()
    ddo = get_registered_ddo(provider_account, providers=[provider_account.address])
    agreement_id = place_order(provider_account, ddo, consumer_account)

    event = keeper.escrow_access_secretstore_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(consumer_account.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_reward(agreement_id, sa, consumer_account)
    event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper node's logs"
    
    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        audience=BaseURLs.ASSETS_URL + "/access",
        subject=agreement_id,
        claims={
            "did": ddo.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    assert response.status_code == 200

    # use jwt access token to access the asset
    access_token = response.get_json()["access_token"]
    response = client.get(f"/api/v1/gateway/services/access/{agreement_id}", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 200


def test_access_endpoint_bad_signature(client, provider_account, consumer_account):
    # The provider_account will place the order and consumer_account
    # will try to request access to it
    
    # order access
    keeper = keeper_instance()
    ddo = get_registered_ddo(provider_account, providers=[provider_account.address])
    agreement_id = place_order(provider_account, ddo, provider_account)

    event = keeper.escrow_access_secretstore_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(consumer_account.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_reward(agreement_id, sa, consumer_account)
    event = keeper.lock_reward_condition.subscribe_condition_fulfilled(
        agreement_id, 15, None, (), wait=True, from_block=0
    )
    assert event, "Lock reward condition fulfilled event is not found, check the keeper node's logs"
    
    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        audience=BaseURLs.ASSETS_URL + '/access',
        subject=agreement_id,
        claims={
            "did": ddo.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_client"


def test_download_endpoint(client, provider_account):
    ddo = get_registered_ddo(provider_account, providers=[provider_account.address])

    # create jwt bearer grant
    jwk = account_to_jwk(provider_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=provider_account.address,
        audience=BaseURLs.ASSETS_URL + '/download',
        claims={
            "did": ddo.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    assert response.status_code == 200
