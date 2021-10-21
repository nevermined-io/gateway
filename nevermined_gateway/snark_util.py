from common_utils_py.utils.keytransfer import make_prover, prove_transfer, hash_key
from web3 import Web3

prover = make_prover("/usr/local/share/keytransfer/keytransfer.zkey", "/usr/local/share/keytransfer/keytransfer.dat")

def call_prover(consumer_pub, provider_secret, asset_plain):
    c = Web3.keccak(text=provider_secret)
    provider_key=c.hex()[0:60]
    res = prove_transfer(prover, [int(consumer_pub[0], 16), int(consumer_pub[1], 16)], int(provider_key, 16), bytes.fromhex(asset_plain[2:]))
    return res

def poseidon_hash(asset_plain):
    res = hash_key(bytes.fromhex(asset_plain))
    return res

