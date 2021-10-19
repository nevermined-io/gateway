from subprocess import check_output
import json
from common_utils_py.utils.keytransfer import make_prover, prove, prove_transfer, hash_key
from web3 import Web3

prover = make_prover("/usr/local/share/keytransfer/keytransfer.zkey", "/usr/local/share/keytransfer/keytransfer.dat")

def call_prover(consumer_pub, provider_secret, asset_plain):
#    print(asset_plain)
    c = Web3.keccak(text=provider_secret)
    #print('keccak::::::::::::::::::::::::::::')
    provider_key=c.hex()[0:60]
    #print(provider_key)
    res = prove_transfer(prover, [int(consumer_pub[0], 16), int(consumer_pub[1], 16)], int(provider_key, 16), bytes.fromhex(asset_plain[2:]))
    #output = json.loads(check_output(['node', 'dist/prove.js', provider_secret, asset_plain, consumer_pub[0], consumer_pub[1]], cwd='snark-tools'))
#    return json.loads(output)
    #print(output)
    #print(res)
    # res['proof'] = output['proof']
    return res

def poseidon_hash(asset_plain):
    res = hash_key(bytes.fromhex(asset_plain))
#    output = check_output(['node', 'dist/hash.js', '0x'+asset_plain], cwd='snark-tools')
#    ret = output.strip().decode()
#    print('poseidon hash ' + asset_plain)
#    print(res)
#    print(ret)
    return res

