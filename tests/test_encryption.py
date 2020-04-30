from contracts_lib_py.utils import get_keys_from_file, decryption, encryption
from ecies import encrypt, decrypt
from ecies.utils import generate_eth_key

from nevermined_gateway.util import (check_auth_token,
                                     is_token_valid, keeper_instance,
                                     verify_signature)
from tests.conftest import get_provider_key_file, get_provider_password


def test_encryption_decryption():
    eth_k = generate_eth_key()
    private_key_hex = eth_k.to_hex()  # hex string
    public_key_hex = eth_k.public_key.to_hex()  # hex string
    data = b'hi there'
    result = decrypt(private_key_hex, encrypt(public_key_hex, data))
    assert result == data


def test_encryption_decryption_with_credentials():
    keyfile_path = get_provider_key_file()
    keyfile_password = get_provider_password()

    print('KeyFile Path = ' + keyfile_path)

    (public_key_hex, private_key_hex) = get_keys_from_file(keyfile_path, keyfile_password)

    data = b'hi there'
    assert data == decryption(private_key_hex, encryption(public_key_hex, data))
    assert b'it should fail' != decryption(private_key_hex, encryption(public_key_hex, b'kdas'))


def test_auth_token():
    token = "0x1d2741dee30e64989ef0203957c01b14f250f5d2f6ccb0" \
            "c88c9518816e4fcec16f84e545094eb3f377b7e214ded226" \
            "76fbde8ca2e41b4eb1b3565047ecd9acf300-1568372035"
    pub_address = "0x62C092047B01630FC7ABAf3Ab07f4b8aDa5EeB35"
    doc_id = "663516d306904651bbcf9fe45a00477c215c7303d8a24c5bad6005dd2f95e68e"
    assert is_token_valid(token), f'cannot recognize auth-token {token}'
    address = check_auth_token(token)
    assert address and address.lower() == pub_address.lower(), f'address mismatch, got {address}, ' \
                                                               f'' \
                                                               f'' \
                                                               f'' \
                                                               f'expected {pub_address}'
    good = verify_signature(keeper_instance(), pub_address, token, doc_id)
    assert good, f'invalid signature/auth-token {token}, {pub_address}, {doc_id}'

