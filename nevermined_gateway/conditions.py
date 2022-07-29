import logging

from common_utils_py.agreements.service_agreement import ServiceAgreement
from common_utils_py.agreements.service_types import ServiceTypes
from common_utils_py.utils.utilities import to_checksum_addresses
from contracts_lib_py.web3_provider import Web3Provider
from eth_utils import add_0x_prefix
from web3 import Web3

from nevermined_gateway.constants import ConditionState
from nevermined_gateway.log import setup_logging
from nevermined_gateway.util import get_provider_account

setup_logging()
logger = logging.getLogger(__name__)


def fulfill_access_condition(keeper, agreement_id, cond_ids, asset_id, consumer_address, provider_acc):
    access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])

    recheck_condition = False
    tx_hash = None
    if access_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling Access condition')
        try:
            tx_hash = keeper.access_condition.fulfill(
                agreement_id, asset_id, consumer_address, provider_acc
            )
        except Exception:
            access_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            if access_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in access condition fulfill')
            else:
                logger.info('The access condition was already fulfilled')

        if tx_hash and not keeper.access_condition.is_tx_successful(tx_hash):
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


def fulfill_access_proof_condition(keeper, agreement_id, cond_id, asset_hash, consumer_address, provider_address,
                                   cipher, proof, provider_acc):
    access_condition_status = keeper.condition_manager.get_condition_state(cond_id)

    if access_condition_status != ConditionState.Fulfilled.value:
        logger.info('Fulfilling Access proof condition')
        try:
            keeper.access_proof_condition.fulfill(
                agreement_id, asset_hash, consumer_address, provider_address, cipher, proof, provider_acc
            )
        except Exception:
            access_condition_status = keeper.condition_manager.get_condition_state(cond_id)
            if access_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in access proof condition fulfill')
            else:
                logger.info('The access proof condition was already fulfilled')

    access_condition_status = keeper.condition_manager.get_condition_state(cond_id)
    return access_condition_status == ConditionState.Fulfilled.value


def is_nft_holder(keeper, asset_id, number_nfts, consumer_address, contract_address=None):
    try:
        contracts_address = contract_address or keeper.nft_upgradeable.contract.address
        _contract = Web3Provider.get_web3().eth.contract(
            address=contract_address, abi=keeper.nft_upgradeable.contract.abi)
        return _contract.functions.balanceOf(Web3.toChecksumAddress(consumer_address), int(asset_id, 16)).call() >= number_nfts
    except Exception as e:
        logger.error(e)
        return False


def is_nft721_holder(keeper, consumer_address, contract_address=None):
    if contract_address is None:
        contract_address = keeper.nft721.contract.address
    _contract = Web3Provider.get_web3().eth.contract(
        address=contract_address, abi=keeper.nft721.contract.abi)
    return _contract.functions.balanceOf(consumer_address).call() > 0


def is_nft721_owner(keeper, asset_id, consumer_address, contract_address):
    keeper.nft721.contract = Web3Provider.get_web3().eth.contract(
        address=contract_address, abi=keeper.nft721.contract.abi)
    return keeper.nft721.contract.caller.ownerOf(int(asset_id, 16)) == consumer_address


def fulfill_nft_holder_and_access_condition(keeper, agreement_id, cond_ids, asset_id, number_nfts, consumer_address,
                                            provider_acc):
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

    if compute_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling Compute condition')
        try:
            keeper.compute_execution_condition.fulfill(
                agreement_id, asset_id, consumer_address, provider_acc
            )
        except Exception:
            compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
            if compute_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in compute condition fulfill')
            else:
                logger.info('The compute condition was already fulfilled')

    compute_condition_status = keeper.condition_manager.get_condition_state(cond_ids[0])
    return compute_condition_status == ConditionState.Fulfilled.value


def fulfill_escrow_payment_condition(keeper, agreement_id, cond_ids, asset, provider_acc,
                                     service_type=ServiceTypes.ASSET_ACCESS):
    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])

    if escrow_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling EscrowPayment condition %s' % agreement_id)
        service_agreement = ServiceAgreement.from_ddo(service_type, asset)

        access_id, lock_id = cond_ids[:2]

        amounts = service_agreement.get_amounts_int()
        receivers = service_agreement.get_receivers()
        token_address = service_agreement.get_param_value_by_name('_tokenAddress')
        agreement = keeper.agreement_manager.get_agreement(agreement_id)
        return_address = agreement.owner
        if token_address is None or len(token_address) == 0:
            token_address = keeper.token.address

        print('Fulfilling EscrowPayment:'
              'agrId: ', agreement_id,
              'asset_id', asset.asset_id,
              'amounts', amounts,
              'receivers', receivers,
              'return_address', return_address,
              'escrow_payment_condition', keeper.escrow_payment_condition.address,
              'token_address', token_address,
              'lock_id', lock_id,
              'access_id', access_id,
              'provider_acc', provider_acc
              )
        try:
            keeper.escrow_payment_condition.fulfill(
                add_0x_prefix(agreement_id),
                asset.asset_id,
                amounts,
                receivers,
                return_address,
                keeper.escrow_payment_condition.address,
                token_address,
                lock_id,
                access_id,
                provider_acc
            )
        except Exception:
            escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            if escrow_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in escrowReward fulfill')
            else:
                logger.info('The escrowReward condition was already fulfilled')

    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
    return escrow_condition_status == ConditionState.Fulfilled.value


def fulfill_escrow_payment_condition_multi(keeper, agreement_id, cond_ids, asset, provider_acc,
                                           service_type=ServiceTypes.ASSET_ACCESS):
    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])

    if escrow_condition_status != ConditionState.Fulfilled.value:
        logger.debug('Fulfilling EscrowPayment condition %s' % agreement_id)
        service_agreement = ServiceAgreement.from_ddo(service_type, asset)

        access_id = cond_ids[3]
        transfer_id = cond_ids[0]
        lock_id = cond_ids[1]

        amounts = service_agreement.get_amounts_int()
        receivers = to_checksum_addresses(service_agreement.get_receivers())
        token_address = service_agreement.get_param_value_by_name('_tokenAddress')
        agreement = keeper.agreement_manager.get_agreement(agreement_id)
        return_address = agreement.owner
        if token_address is None or len(token_address) == 0:
            token_address = keeper.token.address

        try:
            tx_hash = keeper.escrow_payment_condition.fulfill_multi(
                add_0x_prefix(agreement_id),
                asset.asset_id,
                amounts,
                receivers,
                return_address,
                keeper.escrow_payment_condition.address,
                token_address,
                lock_id,
                [transfer_id, access_id],
                provider_acc
            )
        except Exception:
            escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
            keeper.escrow_payment_condition.is_tx_successful(tx_hash, get_revert_message=True)
            if escrow_condition_status != ConditionState.Fulfilled.value:
                logger.error('Error in escrowReward fulfill (multi)')
            else:
                logger.info('The escrowReward condition was already fulfilled')

    escrow_condition_status = keeper.condition_manager.get_condition_state(cond_ids[2])
    return escrow_condition_status == ConditionState.Fulfilled.value


def fulfill_for_delegate_nft_transfer_condition(agreement_id, service_agreement, did, nft_holder_address,
                                                nft_receiver_address, nft_amount, lock_payment_condition_id, keeper):
    logger.debug('Fulfilling NFTTransfer condition')
    transfer_nft = service_agreement.get_nft_transfer_or_mint()

    tx_hash = keeper.transfer_nft_condition.fulfill_for_delegate(
        agreement_id,
        did,
        nft_holder_address,
        nft_receiver_address,
        nft_amount,
        lock_payment_condition_id,
        transfer_nft,
        get_provider_account()
    )

    return keeper.transfer_nft_condition.is_tx_successful(tx_hash)


def fulfill_for_delegate_nft721_transfer_condition(agreement_id, service_agreement, did, nft_holder_address,
                                                   nft_receiver_address, nft_amount, lock_payment_condition_id, keeper):
    logger.debug('Fulfilling NFT721Transfer condition')
    nft_contract_address = service_agreement.get_nft_contract_address()
    transfer_nft = service_agreement.get_nft_transfer_or_mint()
    duration = service_agreement.get_duration()

    tx_hash = keeper.transfer_nft721_condition.fulfill_for_delegate(
        agreement_id,
        did,
        nft_holder_address,
        nft_receiver_address,
        nft_amount,
        lock_payment_condition_id,
        transfer_nft,
        nft_contract_address,
        duration,
        get_provider_account()
    )

    return keeper.transfer_nft_condition.is_tx_successful(tx_hash, get_revert_message=True)
