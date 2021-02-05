import logging

from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.utils.utilities import to_checksum_addresses
from contracts_lib_py.web3_provider import Web3Provider
from eth_utils import add_0x_prefix

from nevermined_gateway.constants import ConditionState
from nevermined_gateway.log import setup_logging

setup_logging()
logger = logging.getLogger(__name__)


def fulfill_access_condition(keeper, agreement_id, cond_ids, asset_id, consumer_address, provider_acc):
    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])

    recheck_condition = False
    if access_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling Access condition')
        try:
            keeper.access_secret_store_condition.fulfill(
                agreement_id, asset_id, consumer_address, provider_acc
            )
        except Exception:
            recheck_condition = True

    if recheck_condition:
        access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
        if access_condition_status != ConditionState.Fulfilled.value:
            logger.error('Error in access condition fulfill')
            return False
        else:
            logger.info('The access condition was already fulfilled')

    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
    return access_condition_status == ConditionState.Fulfilled.value


def fulfill_compute_condition(keeper, agreement_id, cond_ids, asset_id, consumer_address, provider_acc):
    compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])

    recheck_condition = False
    if compute_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling Compute condition')
        try:
            keeper.compute_execution_condition.fulfill(
                agreement_id, asset_id, consumer_address, provider_acc
            )
        except Exception:
            recheck_condition = True

    if recheck_condition:
        compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
        if compute_condition_status != ConditionState.Fulfilled.value:
            logger.error('Error in compute condition fulfill')
            return False
        else:
            logger.info('The compute condition was already fulfilled')

    compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
    return compute_condition_status == ConditionState.Fulfilled.value


def fulfill_escrow_reward_condition(keeper, agreement_id, cond_ids, asset, consumer_address, provider_acc,
                                    service_type=ServiceTypes.ASSET_ACCESS):
    escrowreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])

    if escrowreward_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling EscrowReward condition %s' % agreement_id)
        service_agreement = asset.get_service(service_type)
        did_owner = keeper.agreement_manager.get_agreement_did_owner(agreement_id)
        access_id, lock_id = cond_ids[:2]

        amounts = list(map(int, service_agreement.get_param_value_by_name('_amounts')))
        receivers = to_checksum_addresses(service_agreement.get_param_value_by_name('_receivers'))

        recheck_condition = False
        try:
            keeper.escrow_reward_condition.fulfill(
                add_0x_prefix(agreement_id),
                amounts,
                receivers,
                did_owner,
                lock_id,
                access_id,
                provider_acc
            )
        except Exception:
            recheck_condition = True

        if recheck_condition:
            escrowreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            if escrowreward_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in escrowReward fulfill')
                return False
            else:
                logger.info('The escrowReward condition was already fulfilled')

    escrowreward_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
    return escrowreward_condition_status == ConditionState.Fulfilled.value
