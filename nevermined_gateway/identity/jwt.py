import base64
import hashlib
from inspect import signature
import os

from authlib.jose.rfc7519.claims import JWTClaims
from authlib.oauth2.rfc6749.resource_protector import TokenValidator
from nevermined_gateway.util import get_provider_account
from nevermined_gateway.identity.jwk_utils import account_to_jwk, jwk_to_eth_address, recover_public_keys_from_assertion
from authlib.common.encoding import to_bytes
from authlib.integrations.flask_client.oauth_registry import OAuth
from authlib.integrations.flask_oauth2.authorization_server import AuthorizationServer
from authlib.integrations.flask_oauth2.resource_protector import ResourceProtector
from authlib.integrations.requests_client import oauth2_session
from authlib.integrations.requests_client.oauth2_session import OAuth2Session
from authlib.jose import jwk
from authlib.jose.errors import BadSignatureError, DecodeError, InvalidClaimError
from authlib.jose.rfc7517.jwk import JsonWebKey
from authlib.oauth2.rfc7523 import JWTBearerGrant
from authlib.oauth2.rfc6750 import BearerTokenValidator
from authlib.oauth2.rfc6750 import InvalidTokenError
from authlib.oauth2.rfc6749 import TokenMixin
from authlib.jose import jwt
from authlib.jose.util import extract_segment
from authlib.jose.rfc7518.jws_algs import ECAlgorithm
from authlib.oauth2.rfc6749.models import ClientMixin
from authlib.oauth2.rfc6749.errors import InvalidClientError
import ecdsa
from web3 import Web3

from nevermined_gateway.myapp import app

provider_account = get_provider_account()
provider_jwk = account_to_jwk(provider_account)


class NeverminedOauthClient(ClientMixin):
    def __init__(self, claims):
        self.address = claims["iss"]
        self.resource = claims["aud"]
        self.service_agreement_id = claims["sub"]
        self.did = claims["did"]

    def check_grant_type(self, grant_type):
        return grant_type == JWTBearerGrant.GRANT_TYPE


class NevermineJWTBearerGrant(JWTBearerGrant):

    def create_claims_options(self):
        """Create a claims_options to verify JWT payload claims.
        """
        # https://tools.ietf.org/html/rfc7523#section-3
        claims = {}
        public_claims = {
            'iss': {'essential': True},
            'sub': {'essential': True},
            # need to specify what are the available auds
            'aud': {'essential': True},
            'exp': {'essential': True},
            'sub': {'essential': True},
        }
        claims.update(public_claims)
        
        # private claims are non registered names and may lead to collisions
        private_claims = {
            'did': {'essential': True}
        }
        claims.update(private_claims)

        return claims

    def authenticate_user(self, client, claims):
        return None
    
    def resolve_public_key(self, headers, payload):
        assertion = to_bytes(self.request.data["assertion"])

        # with ecdsa this will produce two public keys that can possibly verify the signature.
        # we will keep both so that later we can authenticate the client.
        # and we can return any of them
        self.possible_public_keys = recover_public_keys_from_assertion(assertion)

        return self.possible_public_keys[0]

    def authenticate_client(self, claims):
        possible_eth_addresses = [jwk_to_eth_address(jwk) for jwk in self.possible_public_keys]

        try:
            received_address = Web3.toChecksumAddress(claims["iss"])
        except ValueError:
            raise InvalidClientError(f"iss: {claims['iss']} needs to be a valid ethereum address")
        
        if received_address in possible_eth_addresses:
            return NeverminedOauthClient(claims)

        raise InvalidClientError(f"iss: {claims['iss']} does not match with the public key used to sign the JwTBearerGrant")
            

class NeverminedJWTTokenValidator(TokenValidator):
    def authenticate_token(self, token_string):
        claims_options = {
            "iss": {
                "essential": True,
                "value": provider_account.address
            }
        }

        try:
            claims = jwt.decode(token_string, provider_jwk, claims_options=claims_options)
        except BadSignatureError as e:
            raise InvalidTokenError(description=e.description)
        return claims

    def validate_token(self, token, scopes):
        """Validates the JWT claims.

        We are subclassing TokenValidator because the ResourceServer api expects
        a non-jwt bearer token
        """
        try:
            token.validate()
        except InvalidClaimError as e:
            error = InvalidTokenError(description=e.description)
            error.error = InvalidClaimError.error
            raise error

def save_token(_token_data, _request):
    """This is a required method of the authorization server but in our case
    we are not storing the tokens."""
    pass

def genereate_access_token(client, grant_type, user, scope):
    """Generate an access token give a JWT Bearer Grant Token.

    OAuth2 has no requirements about what the access token should be.
    Since we want the access token to be a JWT we are going to return a
    JWT Access Token as described in https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10
    """
    header = {
        "typ": "at+JWT",
        "alg": "ES256K",
    }
    claims = {
        "iss": provider_account.address,
        "client_id": client.address,
        "sub": client.service_agreement_id,
        "did": client.did,
        "aud": client.resource,
        # "scope": "scope if there are multiple"
    }
    
    
    return jwt.encode(header, claims, provider_jwk).decode()


app.config["OAUTH2_ACCESS_TOKEN_GENERATOR"] = genereate_access_token

authorization = AuthorizationServer(app, save_token=save_token)
authorization.register_grant(NevermineJWTBearerGrant)

require_oauth = ResourceProtector()
require_oauth.register_token_validator(NeverminedJWTTokenValidator())