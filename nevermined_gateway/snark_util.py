from subprocess import check_output
import json

def call_prover(consumer_pub, provider_secret, asset_plain):
    output = check_output(['node', 'dist/prove.js', provider_secret, asset_plain, consumer_pub[0], consumer_pub[1]], cwd='snark-tools')
    return json.loads(output)

def poseidon_hash(asset_plain):
    output = check_output(['node', 'dist/hash.js', '0x'+asset_plain], cwd='snark-tools')
    return output.strip().decode()

