import logging

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.metadata.metadata import Metadata

from nevermined_gateway.compute_validations import is_allowed_read_compute
import time

from authlib.common.encoding import to_bytes
from authlib.jose import jwt
from authlib.jose.errors import BadSignatureError, InvalidClaimError
from authlib.oauth2.rfc6749.errors import InvalidClientError
from authlib.oauth2.rfc6749.models import ClientMixin
from authlib.oauth2.rfc6749.resource_protector import TokenValidator
from authlib.oauth2.rfc6750 import InvalidTokenError
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.did import NEVERMINED_PREFIX, id_to_did
from common_utils_py.did_resolver.did_resolver import DIDResolver
from common_utils_py.oauth2.token import NeverminedJWTBearerGrant as _NeverminedJWTBearerGrant
from common_utils_py.oauth2.jwk_utils import account_to_jwk
from nevermined_gateway.conditions import (fulfill_access_condition, fulfill_access_proof_condition, fulfill_compute_condition,
                                           fulfill_escrow_payment_condition, fulfill_nft_holder_and_access_condition, is_nft721_holder,
                                           is_nft_holder)
from nevermined_gateway.constants import (BaseURLs, ConditionState,
                                          ConfigSections)
from nevermined_gateway.identity.jwk_utils import jwk_to_eth_address, recover_public_keys_from_assertion, \
    recover_public_keys_from_eth_assertion
from nevermined_gateway.util import (get_config, get_provider_account, get_provider_babyjub_key, is_access_granted, is_owner_granted,
                                     keeper_instance, was_compute_triggered, is_nft_access_condition_fulfilled,
                                     get_asset_url_at_index)
from web3 import Web3
from nevermined_gateway.snark_util import call_prover
from common_utils_py.utils import keytransfer

logger = logging.getLogger(__name__)

class NeverminedOauthClient(ClientMixin):
    def __init__(self, claims):
        self.address = claims["iss"]
        self.resource = claims["aud"]
        self.service_agreement_id = claims.get("sub")
        self.did = claims.get("did")
        self.execution_id = claims.get("execution_id")

    def check_grant_type(self, grant_type):
        return grant_type == NeverminedJWTBearerGrant.GRANT_TYPE


class NeverminedJWTBearerGrant(_NeverminedJWTBearerGrant):

    def __init__(self, request, server):
        super().__init__(request, server)
        self.provider_account = get_provider_account()
        self.provider_key = get_provider_babyjub_key()
        self.config = get_config()

    def authenticate_user(self, client, claims):
        return None

    def resolve_public_key(self, headers, payload):
        assertion = to_bytes(self.request.data["assertion"])

        # with ecdsa this will produce two public keys that can possibly verify the signature.
        # we will keep both so that later we can authenticate the client.
        # and we can return any of them
        possible_public_keys = recover_public_keys_from_assertion(assertion)

        # if signing with ethereum this recovery becomes the de-facto signature verification
        # since we check if any of these keys match the issuer of the token.
        #
        # signing with ethereum differs from ES256K
        #   - it adds a prefix to the message to sign
        #   - it uses keccak_256 hash function instead of sha256
        #
        # we then return a public key that verifies the message so that
        # authlib doesn't complain with a bad signature
        eths = payload.get("eths")
        if eths == "personal":
            possible_eths_keys = recover_public_keys_from_eth_assertion(assertion)
            self.possible_public_keys = possible_eths_keys
        else:
            self.possible_public_keys = possible_public_keys

        return possible_public_keys[0]

    def check_ddo(self, did, agreement_id, asset_id, consumer_address, keeper, cond_ids, service_type):
        metadata_api = Metadata(self.config.metadata_url)
        ddo = metadata_api.get_asset_ddo(did)
        aservice = ddo.get_service(service_type)
        (id1, id2, id3) = aservice.generate_agreement_condition_ids(agreement_id, asset_id, consumer_address, keeper)
        ids = [id1, id2, id3]
        if ids != cond_ids:
            raise InvalidClientError(f"ServiceAgreement {agreement_id} doesn't match ddo")

    def authenticate_client(self, claims):
        logger.info('Auth client')
        possible_eth_addresses = [jwk_to_eth_address(jwk) for jwk in self.possible_public_keys]

        try:
            received_address = Web3.toChecksumAddress(claims["iss"])
        except ValueError:
            raise InvalidClientError(f"iss: {claims['iss']} needs to be a valid ethereum address")

        if not received_address in possible_eth_addresses:
            raise InvalidClientError(
                f"iss: {claims['iss']} does not match with the public key used to sign the JwTBearerGrant")

        if claims["aud"] == BaseURLs.ASSETS_URL + "/access":
            # check if client has access
            self.validate_access(claims["sub"], claims["did"], claims["iss"])
        elif claims["aud"] == BaseURLs.ASSETS_URL + "/nft-access":
            self.validate_nft_access(claims["sub"], claims["did"], claims["iss"])
        elif claims["aud"] == BaseURLs.ASSETS_URL + "/access-proof":
            self.validate_access_proof(claims["sub"], claims["did"], claims["iss"], claims["buyer"], claims["babysig"])
        elif claims["aud"] == BaseURLs.ASSETS_URL + "/download":
            self.validate_owner(claims["did"], claims["iss"])
        elif claims["aud"] == BaseURLs.ASSETS_URL + "/compute":
            self.validate_compute(claims["sub"], claims["execution_id"], claims["iss"])
        elif claims["aud"] == BaseURLs.ASSETS_URL + "/execute":
            self.validate_execute(claims["sub"], claims["did"], claims["iss"])

        return NeverminedOauthClient(claims)

    def validate_access(self, agreement_id, did, consumer_address):
        keeper = keeper_instance()

        if not is_access_granted(
                agreement_id,
                did,
                consumer_address,
                keeper):
            # 3. If not granted, verification of agreement and conditions
            agreement = keeper.agreement_manager.get_agreement(agreement_id)
            cond_ids = agreement.condition_ids
            asset = DIDResolver(keeper.did_registry).resolve(did)
            asset_id = f'0x{did.replace(NEVERMINED_PREFIX, "")}'
            self.check_ddo(did, agreement_id, asset_id, consumer_address, keeper, cond_ids, ServiceTypes.ASSET_ACCESS)

            access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            lock_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
            escrow_condition_status = keeper.condition_manager.get_condition_state(
                cond_ids[2])

            logger.debug('AccessCondition: %d' % access_condition_status)
            logger.debug('LockPaymentCondition: %d' % lock_condition_status)
            logger.debug('EscrowPaymentCondition: %d' % escrow_condition_status)

            if lock_condition_status != ConditionState.Fulfilled.value:
                logger.debug('ServiceAgreement %s was not paid. Forbidden' % agreement_id)
                raise InvalidClientError(
                    f"ServiceAgreement {agreement_id} was not paid, LockPaymentCondition status is {lock_condition_status}")

            fulfilled = fulfill_access_condition(keeper, agreement_id, cond_ids, asset_id, consumer_address,
                                                 self.provider_account)
            if not fulfilled:
                raise InvalidClientError('Server error fulfilling access condition')

            fulfill_escrow_payment_condition(keeper, agreement_id, cond_ids, asset,
                                             self.provider_account)

            iteration = 0
            access_granted = False
            while iteration < ConfigSections.PING_ITERATIONS:
                iteration = iteration + 1
                logger.debug('Checking if access was granted. Iteration %d' % iteration)
                if not is_access_granted(agreement_id, did, consumer_address, keeper):
                    time.sleep(ConfigSections.PING_SLEEP / 1000)
                else:
                    access_granted = True
                    break

            if not access_granted:
                msg = ('Checking access permissions failed. Either consumer address does not have '
                       'permission to consume this asset or consumer address and/or service '
                       'agreement '
                       'id is invalid.')
                logger.warning(msg)
                raise InvalidClientError(msg)

    def validate_access_proof(self, agreement_id, did, eth_address, consumer_address, jubjub_sig):
        consumer_pub = ['0x'+consumer_address[0:64], '0x'+consumer_address[64:128]]
        provider_pub = [self.provider_key.x, self.provider_key.y]

        if not keytransfer.verify([int(consumer_pub[0],16), int(consumer_pub[1],16)], int(eth_address,16), jubjub_sig):
            raise InvalidClientError(
                    f"ServiceAgreement {agreement_id}: babyjubjub signature doesn't match")

        keeper = keeper_instance()

        agreement = keeper.agreement_manager.get_agreement(agreement_id)
        cond_ids = agreement.condition_ids
        asset = DIDResolver(keeper.did_registry).resolve(did)
        asset_id = did.replace(NEVERMINED_PREFIX, "")
        self.check_ddo(did, agreement_id, asset_id, consumer_pub, keeper, cond_ids, ServiceTypes.ASSET_ACCESS_PROOF)

        access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
        lock_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
        escrow_condition_status = keeper.condition_manager.get_condition_state(
                cond_ids[2])

        logger.info('AccessProofCondition: %d' % access_condition_status)
        logger.info('LockPaymentCondition: %d' % lock_condition_status)
        logger.info('EscrowPaymentCondition: %d' % escrow_condition_status)

        if lock_condition_status != ConditionState.Fulfilled.value:
            logger.debug('ServiceAgreement %s was not paid. Forbidden' % agreement_id)
            raise InvalidClientError(
                    f"ServiceAgreement {agreement_id} was not paid, LockPaymentCondition status is {lock_condition_status}")

        if escrow_condition_status != ConditionState.Fulfilled.value:
            # compute the proof
            auth_method = asset.authorization.main['service']
            url = '0x' + get_asset_url_at_index(0, asset, self.provider_account, auth_method)
            res = call_prover(consumer_pub, self.provider_key.secret, url)
            # check that the condition ID is correct
            cond_id = keeper.access_proof_condition.generate_id(
                agreement_id,
                ['bytes32', 'bytes32', 'bytes32', 'bytes32', 'bytes32'],
                [res['hash'], consumer_pub[0], consumer_pub[1], provider_pub[0], provider_pub[1]]
            )
            if cond_ids[0] != cond_id.hex():
                raise InvalidClientError(
                        f"ServiceAgreement {agreement_id}: public key doesn't match {consumer_address}")

            fulfill_access_proof_condition(keeper, agreement_id, cond_ids, res['hash'], consumer_pub, provider_pub, res['cipher'], res['proof'], 
                                     self.provider_account)
            fulfill_escrow_payment_condition(keeper, agreement_id, cond_ids, asset,
                                             self.provider_account, ServiceTypes.ASSET_ACCESS_PROOF)

    def validate_nft_access(self, agreement_id, did, consumer_address):
        keeper = keeper_instance()

        asset = DIDResolver(keeper.did_registry).resolve(did)

        # check which nft access service type is on the ddo
        service_type = ServiceTypes.NFT_ACCESS
        if asset.get_service(ServiceTypes.NFT721_ACCESS) is not None:
            service_type = ServiceTypes.NFT721_ACCESS

        sa = ServiceAgreement.from_ddo(service_type, asset)
        return self._validate_nft_access(agreement_id, did, consumer_address, sa, service_type)


    def _validate_nft_access(self, agreement_id, did, consumer_address, service_agreement, service_type):
        keeper = keeper_instance()

        asset = DIDResolver(keeper.did_registry).resolve(did)
        asset_id = asset.asset_id
        sa_name = service_agreement.main['name']
        erc721_address = service_agreement.get_param_value_by_name('_contractAddress')

        access_granted = False

        if agreement_id is None or agreement_id == '0x':
            if sa_name == 'nftAccessAgreement':
                access_granted = is_nft_holder(keeper, asset_id, service_agreement.get_number_nfts(), consumer_address)
            elif sa_name == 'nft721AccessAgreement':
                access_granted = is_nft721_holder(keeper, asset_id, consumer_address, erc721_address)
        else:
            agreement = keeper.agreement_manager.get_agreement(agreement_id)
            cond_ids = agreement.condition_ids
            access_cond_id = cond_ids[1]
            metadata_api = Metadata(self.config.metadata_url)
            ddo = metadata_api.get_asset_ddo(did)

            nft_access_service_agreement = ServiceAgreement.from_ddo(service_type, ddo)

            (nft_access_cond_id, nft_holder_cond_id) = nft_access_service_agreement.generate_agreement_condition_ids(agreement_id, asset_id, consumer_address, keeper)
            if [nft_holder_cond_id, nft_access_cond_id] != cond_ids:
                raise InvalidClientError(f"ServiceAgreement {agreement_id} doesn't match ddo")                

            if not is_nft_access_condition_fulfilled(
                    agreement_id,
                    access_cond_id,
                    consumer_address,
                    keeper):
                # If not granted, verification of agreement and conditions and fulfill
                # access_granted = is_nft_holder(keeper, asset_id, sa.get_number_nfts(), consumer_address)
                access_granted = fulfill_nft_holder_and_access_condition(
                    keeper,
                    agreement_id,
                    cond_ids,
                    asset_id,
                    service_agreement.get_number_nfts(),
                    consumer_address,
                    self.provider_account
                )
        if not access_granted:
            msg = ('Checking access permissions failed. Either consumer address does not have '
                   'permission to consume this NFT or consumer address and/or service '
                   'agreement '
                   'id is invalid.')
            logger.warning(msg)
            raise InvalidClientError(msg)

    def validate_owner(self, did, consumer_address):
        keeper = keeper_instance()

        if not is_owner_granted(
                did,
                consumer_address,
                keeper):
            msg = ('Checking access permissions failed. Consumer address does not have '
                   'permission to download this asset or consumer address and/or did '
                   'is invalid.')
            logger.warning(msg)
            raise InvalidClientError(msg)

    def validate_execute(self, agreement_id, workflow_did, consumer_address):
        keeper = keeper_instance()

        asset_id = keeper.agreement_manager.get_agreement(agreement_id).did
        did = id_to_did(asset_id)
        asset = DIDResolver(keeper.did_registry).resolve(did)

        if not was_compute_triggered(agreement_id, did, consumer_address, keeper):

            agreement = keeper.agreement_manager.get_agreement(agreement_id)
            cond_ids = agreement.condition_ids
            self.check_ddo(did, agreement_id, asset_id, consumer_address, keeper, cond_ids, ServiceTypes.CLOUD_COMPUTE)

            compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            lock_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
            escrow_condition_status = keeper.condition_manager.get_condition_state(
                cond_ids[2])
            logger.debug('ComputeExecutionCondition: %d' % compute_condition_status)
            logger.debug('LockPaymentCondition: %d' % lock_condition_status)
            logger.debug('EscrowPaymentCondition: %d' % escrow_condition_status)

            if lock_condition_status != ConditionState.Fulfilled.value:
                logger.debug('ServiceAgreement %s was not paid. Forbidden' % agreement_id)
                raise InvalidClaimError(
                    f"ServiceAgreement {agreement_id} was not paid, LockPaymentCondition status is {lock_condition_status}")

            fulfill_compute_condition(keeper, agreement_id, cond_ids, asset_id, consumer_address,
                                      self.provider_account)
            fulfill_escrow_payment_condition(keeper, agreement_id, cond_ids, asset,
                                             self.provider_account,
                                             ServiceTypes.CLOUD_COMPUTE)

            iteration = 0
            access_granted = False
            while iteration < ConfigSections.PING_ITERATIONS:
                iteration = iteration + 1
                logger.debug('Checking if compute was granted. Iteration %d' % iteration)
                if not was_compute_triggered(agreement_id, did, consumer_address, keeper):
                    time.sleep(ConfigSections.PING_SLEEP / 1000)
                else:
                    access_granted = True
                    break

            if not access_granted:
                msg = (
                    'Scheduling the compute execution failed. Either consumer address does not '
                    'have permission to execute this workflow or consumer address and/or service '
                    'agreement id is invalid.')
                logger.warning(msg)
                raise InvalidClientError(msg)

    def validate_compute(self, agreement_id, execution_id, consumer_address):
        message, is_allowed = is_allowed_read_compute(agreement_id, execution_id, consumer_address,
                                                      None, has_bearer_token=True)

        if not is_allowed:
            raise InvalidClientError(message)


class NeverminedJWTTokenValidator(TokenValidator):
    def __init__(self, realm=None, **extra_attributes):
        super().__init__(realm, **extra_attributes)
        self.provider_account = get_provider_account()
        self.provider_jwk = account_to_jwk(self.provider_account)

    def authenticate_token(self, token_string):
        claims_options = {
            "iss": {
                "essential": True,
                "value": self.provider_account.address
            }
        }

        try:
            claims = jwt.decode(token_string, self.provider_jwk, claims_options=claims_options)
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


def genereate_access_token(client, grant_type, user, scope):
    """Generate an access token give a JWT Bearer Grant Token.

    OAuth2 has no requirements about what the access token should be.
    Since we want the access token to be a JWT we are going to return a
    JWT Access Token as described in https://tools.ietf.org/html/draft-ietf-oauth-access-token-jwt-10
    """
    provider_account = get_provider_account()
    provider_jwk = account_to_jwk(provider_account)

    header = {
        "typ": "at+JWT",
        "alg": "ES256K",
    }
    claims = {
        "iss": provider_account.address,
        "client_id": client.address,
        "aud": client.resource,
    }

    if client.service_agreement_id is not None:
        claims.update({"sub": client.service_agreement_id})
    if client.did is not None:
        claims.update({"did": client.did})
    if client.execution_id is not None:
        claims.update({"execution_id": client.execution_id})

    return jwt.encode(header, claims, provider_jwk).decode()
