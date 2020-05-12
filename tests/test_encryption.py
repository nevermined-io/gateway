from nevermined_gateway.util import (check_auth_token,
                                     is_token_valid, keeper_instance,
                                     verify_signature)


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

