"""Helper functions to convert between eth keys and JWK

This only works for EC curve secp256k1.
"""

import base64
import hashlib
from authlib.jose.errors import DecodeError
from authlib.jose.util import extract_segment
from cryptography.hazmat.primitives import serialization
import ecdsa
import sha3

from authlib.jose import JsonWebKey
from eth_keys import keys


def recover_public_keys_from_signature(signing_input, signature, hashfunc=hashlib.sha256):
    # use ecdsa library to recover public keys
    possible_keys =  ecdsa.VerifyingKey.from_public_key_recovery(
        signature, signing_input, ecdsa.SECP256k1, hashfunc=hashfunc
    )

    # convert to JWK
    jwks = []
    for public_key in possible_keys:
        public_key_bytes = public_key.to_string()
        jwk = public_key_bytes_to_jwk(public_key_bytes)
        jwks.append(jwk)

    return jwks


def recover_public_keys_from_assertion(assertion):
    signature_input, signature = split_assertion(assertion)
    return recover_public_keys_from_signature(signature_input, signature)


def recover_public_keys_from_eth_assertion(assertion):
    signature_input, signature = split_assertion(assertion)
    eth_signature_input = ('\u0019Ethereum Signed Message:\n' + str(len(signature_input)) + signature_input.decode()).encode()
    return recover_public_keys_from_signature(eth_signature_input, signature, hashfunc=sha3.keccak_256)


def split_assertion(assertion):
    signature_input, signature_segment = assertion.rsplit(b".", 1)
    signature = extract_segment(signature_segment, DecodeError, "signature")
    return signature_input, signature


def public_key_bytes_to_jwk(public_key_bytes):
    jwk_json = {
        "kty": "EC",
        "crv": "secp256k1",
        "x": base64.urlsafe_b64encode(public_key_bytes[:32]),
        "y": base64.urlsafe_b64encode(public_key_bytes[32:])
    }

    return JsonWebKey.import_key(jwk_json)


def public_key_bytes_to_eth_address(public_key_bytes):
    eth_checksum_address = keys.PublicKey(public_key_bytes).to_checksum_address()
    return eth_checksum_address


def jwk_to_eth_address(jwk):
    public_key = jwk.get_public_key()
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)

    # X962 format prepends the 0x04 byte to signal that this uncompressed
    return public_key_bytes_to_eth_address(public_key_bytes[1:])