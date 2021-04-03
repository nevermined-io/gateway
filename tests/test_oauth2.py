import os
import time

import pytest

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.utils.utilities import to_checksum_addresses

from nevermined_gateway.constants import BaseURLs
from common_utils_py.oauth2.jwk_utils import account_to_jwk
from nevermined_gateway.identity.oauth2.token import NeverminedJWTBearerGrant
from nevermined_gateway.util import keeper_instance

from tests.utils import get_registered_algorithm_ddo, get_registered_compute_ddo, get_registered_ddo, get_registered_workflow_ddo, lock_payment, place_order

# In Production JWT should only be used with https
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

amounts = [10, 2]
receivers = to_checksum_addresses(
    ['0x00Bd138aBD70e2F00903268F3Db08f2D25677C9e', '0x068ed00cf0441e4829d9784fcbe7b9e26d4bd8d0'])

def test_access_endpoint(client, provider_account, consumer_account):
    # order access
    keeper = keeper_instance()
    ddo = get_registered_ddo(provider_account, providers=[provider_account.address])
    agreement_id = place_order(provider_account, ddo, consumer_account)

    event = keeper.access_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(consumer_account.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_payment(agreement_id, ddo.asset_id, sa, amounts, receivers, consumer_account)
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
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

    event = keeper.access_template.subscribe_agreement_created(
            agreement_id, 15, None, (), wait=True, from_block=0
        )
    assert event, "Agreement event is not found, check the keeper node's logs"

    consumer_balance = keeper.token.get_token_balance(consumer_account.address)
    if consumer_balance < 50:
        keeper.dispenser.request_tokens(50 - consumer_balance, consumer_account)

    sa = ServiceAgreement.from_ddo(ServiceTypes.ASSET_ACCESS, ddo)
    lock_payment(agreement_id, ddo.asset_id, sa, amounts, receivers, consumer_account)

    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
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


def test_execute_endpoint(client, provider_account, consumer_account):
    ddo_compute = get_registered_compute_ddo(provider_account, providers=[provider_account.address])
    ddo_algorithm = get_registered_algorithm_ddo(consumer_account, providers=[provider_account.address])
    ddo_workflow = get_registered_workflow_ddo(consumer_account, ddo_compute.did,
        ddo_algorithm.did, providers=[provider_account.address])

    # initialize agreement
    agreement_id = place_order(provider_account, ddo_compute, consumer_account, service_type=ServiceTypes.CLOUD_COMPUTE)
    sa = ServiceAgreement.from_ddo(ServiceTypes.CLOUD_COMPUTE, ddo_compute)
    lock_payment(agreement_id, ddo_compute.asset_id, sa, amounts, receivers, consumer_account)

    keeper = keeper_instance()
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id, 60, None, (), wait=True
    )
    assert event is not None, "Reward condition is not found"

    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        subject=agreement_id,
        audience=BaseURLs.ASSETS_URL + '/execute',
        claims={
            "did": ddo_workflow.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    assert response.status_code == 200

    # use jwt access token to execute the compute
    access_token = response.get_json()["access_token"]
    response = client.post(f"/api/v1/gateway/services/execute/{agreement_id}", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 200


@pytest.mark.xfail(reason="Check https://github.com/nevermined-io/compute-api/issues/33")
def test_compute_status_endpoint(client, provider_account, consumer_account):
    ddo_compute = get_registered_compute_ddo(provider_account, providers=[provider_account.address])
    ddo_algorithm = get_registered_algorithm_ddo(consumer_account, providers=[provider_account.address])
    ddo_workflow = get_registered_workflow_ddo(consumer_account, ddo_compute.did,
        ddo_algorithm.did, providers=[provider_account.address])

    # initialize agreement
    agreement_id = place_order(provider_account, ddo_compute, consumer_account, service_type=ServiceTypes.CLOUD_COMPUTE)
    sa = ServiceAgreement.from_ddo(ServiceTypes.CLOUD_COMPUTE, ddo_compute)
    lock_payment(agreement_id, ddo_compute.asset_id, sa, amounts, receivers, consumer_account)

    keeper = keeper_instance()
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id, 60, None, (), wait=True
    )
    assert event is not None, "Reward condition is not found"

    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        subject=agreement_id,
        audience=BaseURLs.ASSETS_URL + '/execute',
        claims={
            "did": ddo_workflow.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    # use jwt access token to execute the compute
    access_token = response.get_json()["access_token"]
    response = client.post(f"/api/v1/gateway/services/execute/{agreement_id}", headers={
        "Authorization": f"Bearer {access_token}"
    })
    execution_id = response.get_json()["workflowId"]

    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        subject=agreement_id,
        audience=BaseURLs.ASSETS_URL + '/compute',
        claims={
            "execution_id": execution_id
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    # use jwt access token to execute the compute
    access_token = response.get_json()["access_token"]

    response = client.get(
        f"/api/v1/gateway/services/compute/status/{agreement_id}/{execution_id}", headers={
            "Authorization": f"Bearer {access_token}"
        })
    assert response.status_code == 200


@pytest.mark.xfail(reason="See https://github.com/nevermined-io/compute-api/issues/33")
def test_compute_logs_endpoint(client, provider_account, consumer_account):
    ddo_compute = get_registered_compute_ddo(provider_account, providers=[provider_account.address])
    ddo_algorithm = get_registered_algorithm_ddo(consumer_account, providers=[provider_account.address])
    ddo_workflow = get_registered_workflow_ddo(consumer_account, ddo_compute.did,
        ddo_algorithm.did, providers=[provider_account.address])

    # initialize agreement
    agreement_id = place_order(provider_account, ddo_compute, consumer_account, service_type=ServiceTypes.CLOUD_COMPUTE)
    sa = ServiceAgreement.from_ddo(ServiceTypes.CLOUD_COMPUTE, ddo_compute)
    lock_payment(agreement_id, ddo_compute.asset_id, sa, amounts, receivers, consumer_account)

    keeper = keeper_instance()
    event = keeper.lock_payment_condition.subscribe_condition_fulfilled(
        agreement_id, 60, None, (), wait=True
    )
    assert event is not None, "Reward condition is not found"

    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        subject=agreement_id,
        audience=BaseURLs.ASSETS_URL + '/execute',
        claims={
            "did": ddo_workflow.did
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    # use jwt access token to execute the compute
    access_token = response.get_json()["access_token"]
    response = client.post(f"/api/v1/gateway/services/execute/{agreement_id}", headers={
        "Authorization": f"Bearer {access_token}"
    })
    execution_id = response.get_json()["workflowId"]

    # create jwt bearer grant
    jwk = account_to_jwk(consumer_account)
    assertion = NeverminedJWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        subject=agreement_id,
        audience=BaseURLs.ASSETS_URL + '/compute',
        claims={
            "execution_id": execution_id
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": NeverminedJWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
    })
    # use jwt access token to execute the compute
    access_token = response.get_json()["access_token"]

    # wait a few seconds for the pod to start
    time.sleep(5)
    response = client.get(
        f"/api/v1/gateway/services/compute/logs/{agreement_id}/{execution_id}", headers={
            "Authorization": f"Bearer {access_token}"
        })
    assert response.status_code == 200