import logging

from common_utils_py.did import id_to_did

from nevermined_gateway.util import keeper_instance, verify_signature, was_compute_triggered

logger = logging.getLogger(__name__)


def is_allowed_read_compute(agreement_id, execution_id, consumer_address, signature, has_bearer_token=False):
    keeper = keeper_instance()

    ## Access check
    if not has_bearer_token:
        if not verify_signature(keeper, consumer_address, signature, execution_id):
            msg = (f'Invalid signature {signature} for '
                f'consumerAddress {consumer_address} and executionId {execution_id}.')
            logger.error(msg)
            return msg, False

    asset_id = keeper.agreement_manager.get_agreement(agreement_id).did
    did = id_to_did(asset_id)

    if not was_compute_triggered(agreement_id, did, consumer_address, keeper):
        msg = (
            'Getting access failed. Either consumer address does not '
            'have permission to execute this agreement or consumer address and/or service '
            'agreement id is invalid.')
        logger.warning(msg)
        return msg, False

    return 'OK', True
