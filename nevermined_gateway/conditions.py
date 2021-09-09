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
            keeper.access_condition.fulfill(
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

def fulfill_access_proof_condition(keeper, agreement_id, cond_ids, asset_hash, consumer_address, provider_address, cipher, proof, provider_acc):
    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])

    recheck_condition = True
    if access_condition_status != ConditionState.Fulfilled.value:
        logger.info('Fulfilling Access proof condition')
        try:
            res = keeper.access_proof_condition.fulfill(
                agreement_id, asset_hash, consumer_address, provider_address, cipher, proof, provider_acc
            )
            print(res)
        except Exception as e:
            print(e)
            recheck_condition = True

    if recheck_condition:
        access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
        if access_condition_status != ConditionState.Fulfilled.value:
            logger.error('Error in access proof condition fulfill')
            return False
        else:
            logger.info('The access proof condition was already fulfilled')

    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
    return access_condition_status == ConditionState.Fulfilled.value


def is_nft_holder(keeper, asset_id, number_nfts, consumer_address):
    try:
        return keeper.did_registry.balance(consumer_address, asset_id) >= number_nfts
    except Exception:
        return False


def is_nft721_holder(keeper, asset_id, consumer_address, contract_address):
    # we need to change the address of the erc721 contract
    keeper.nft721.contract = Web3Provider.get_web3().eth.contract(
        address=contract_address, abi=keeper.nft721.contract.abi)
    return keeper.nft721.contract.caller.ownerOf(int(asset_id, 16)) == consumer_address


def fulfill_nft_holder_and_access_condition(keeper, agreement_id, cond_ids, asset_id, number_nfts, consumer_address, provider_acc):
    nft_holder_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])

    if nft_holder_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling NFT Holder condition')
        try:
            keeper.nft_holder_condition.fulfill(
                agreement_id, asset_id, consumer_address, number_nfts, provider_acc
            )
        except Exception:
            return False

    if access_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling NFT Access condition')
        try:
            keeper.nft_access_condition.fulfill(
                agreement_id, asset_id, consumer_address, provider_acc
            )
        except Exception:
            return False

    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[1])
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


def fulfill_escrow_payment_condition(keeper, agreement_id, cond_ids, asset, provider_acc,
                                     service_type=ServiceTypes.ASSET_ACCESS):
    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])

    if escrow_condition_status != ConditionState.Fulfilled.value:
        logger.info('Fulfilling EscrowPayment condition %s' % agreement_id)
        service_agreement = asset.get_service(service_type)
        print(service_agreement)
        # did_owner = keeper.agreement_manager.get_agreement_did_owner(agreement_id)
        access_id, lock_id = cond_ids[:2]

        amounts = list(map(int, service_agreement.get_param_value_by_name('_amounts')))
        receivers = to_checksum_addresses(service_agreement.get_param_value_by_name('_receivers'))
        token_address = service_agreement.get_param_value_by_name('_tokenAddress')
        if token_address is None or len(token_address) == 0:
            token_address = keeper.token.address

        recheck_condition = False
        try:
            keeper.escrow_payment_condition.fulfill(
                add_0x_prefix(agreement_id),
                asset.asset_id,
                amounts,
                receivers,
                keeper.escrow_payment_condition.address,
                token_address,
                lock_id,
                access_id,
                provider_acc
            )
        except Exception:
            recheck_condition = True

        if recheck_condition:
            escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            if escrow_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in escrowReward fulfill')
                return False
            else:
                logger.info('The escrowReward condition was already fulfilled')

    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
    return escrow_condition_status == ConditionState.Fulfilled.value
