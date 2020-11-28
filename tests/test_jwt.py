from nevermined_gateway.identity.jwk_utils import account_to_jwk
import os
import base64

from authlib.jose.rfc7517.jwk import JsonWebKey
from authlib.oauth2.rfc7523 import JWTBearerGrant
from authlib.jose import jwt

# In Production JWT should only be used with https
os.environ["AUTHLIB_INSECURE_TRANSPORT"] = "true"

def test_fetch_token(client, consumer_account):
    jwk = account_to_jwk(consumer_account)

    assertion = JWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        audience="foo",
        subject="john",
        claims={
            "did": "asdasdasd"
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": JWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
        })

    assert response.status_code == 200
    assert "access_token" in response.get_json()

def test_wrong_iss(client, consumer_account):
    jwk = account_to_jwk(consumer_account)
    
    assertion = JWTBearerGrant.sign(
        jwk,
        issuer="john",
        audience="foo",
        subject="john",
        claims={
            "did": "asdasdasd"
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": JWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
        })

    # issuer needs to be a valid ethereum address
    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_client"


def test_missing_claim(client, consumer_account):
    jwk = account_to_jwk(consumer_account)

    assertion = JWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        audience="foo",
        subject="john",
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": JWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
        })

    assert response.status_code == 400
    assert response.get_json()["error"] == "invalid_grant"
    assert response.get_json()["error_description"] == 'Missing "did" claim'


def test_access_protected_resource(client, consumer_account):
    jwk = account_to_jwk(consumer_account)

    # request a token
    assertion = JWTBearerGrant.sign(
        jwk,
        issuer=consumer_account.address,
        audience="foo",
        subject="john",
        claims={
            "did": "asdasdasd"
        },
        header={
            "alg": "ES256K"
        })

    response = client.post("/api/v1/gateway/services/oauth/token", data={
        "grant_type": JWTBearerGrant.GRANT_TYPE,
        "assertion": assertion
        })
    token = response.get_json()["access_token"]

    # test accessing a protected resource
    response = client.get("/api/v1/gateway/services/test", headers={
        "Authorization": f"Bearer {token}"
    })
    assert response.status_code == 200


def test_access_wrong_iss(client, consumer_account, provider_account):
    provider_jwk = account_to_jwk(provider_account)
    header = {
        "typ": "at+JWT",
        "alg": "ES256K",
    }
    claims = {
        "iss": consumer_account.address,
        "client_id": consumer_account.address,
        "sub": "adsadasd",
        "did": "asdsadad",
        "aud": "asdsadsad",
        # "scope": "scope if there are multiple"
    }
    access_token = jwt.encode(header, claims, provider_jwk).decode()

     # test accessing a protected resource
    response = client.get("/api/v1/gateway/services/test", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_claim"
    

def test_access_wrong_signature(client, consumer_account, provider_account):
    consumer_jwk = account_to_jwk(consumer_account)
    header = {
        "typ": "at+JWT",
        "alg": "ES256K",
    }
    claims = {
        "iss": provider_account.address,
        "client_id": consumer_account.address,
        "sub": "adsadasd",
        "did": "asdsadad",
        "aud": "asdsadsad",
        # "scope": "scope if there are multiple"
    }
    access_token = jwt.encode(header, claims, consumer_jwk).decode()

     # test accessing a protected resource
    response = client.get("/api/v1/gateway/services/test", headers={
        "Authorization": f"Bearer {access_token}"
    })
    assert response.status_code == 401
    assert response.get_json()["error"] == "invalid_token"