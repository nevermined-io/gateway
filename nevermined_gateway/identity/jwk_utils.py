"""Helper functions to convert between eth keys and JWK

This only works for EC curve secp256k1.
"""

import base64
import hashlib
from authlib.jose.errors import DecodeError
from authlib.jose.util import extract_segment
from cryptography.hazmat.primitives import serialization
import ecdsa
from web3 import Web3

from authlib.jose import JsonWebKey
from eth_keys import keys


def recover_public_keys_from_signature(signing_input, signature):
    # use ecdsa library to recover public keys
    possible_keys =  ecdsa.VerifyingKey.from_public_key_recovery(
        signature, signing_input, ecdsa.SECP256k1, hashfunc=hashlib.sha256
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


def private_key_bytes_to_jwk(private_key_bytes):
    private_key = ecdsa.SigningKey.from_string(private_key_bytes, curve=ecdsa.SECP256k1)
    public_key_bytes = private_key.get_verifying_key().to_string()

    jwk_json = {
        "kty": "EC",
        "crv": "secp256k1",
        "d": base64.urlsafe_b64encode(private_key_bytes),
        "x": base64.urlsafe_b64encode(public_key_bytes[:32]),
        "y": base64.urlsafe_b64encode(public_key_bytes[32:])
    }

    return jwk_json


def key_file_to_jwk(key_file_path, password):
    with open(key_file_path) as f:
        encrypted_key = f.read()
    
    private_key = Web3().eth.account.decrypt(encrypted_key, password)
    private_key_bytes = bytes.fromhex(private_key.hex()[2:])
    
    return private_key_bytes_to_jwk(private_key_bytes)


def account_to_jwk(account):
    return key_file_to_jwk(account.key_file, account.password)


def public_key_bytes_to_eth_address(public_key_bytes):
    eth_checksum_address = keys.PublicKey(public_key_bytes).to_checksum_address()
    return eth_checksum_address


def jwk_to_eth_address(jwk):
    public_key = jwk.get_public_key()
    public_key_bytes = public_key.public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    
    # X962 format prepends the 0x04 byte to signal that this uncompressed
    return public_key_bytes_to_eth_address(public_key_bytes[1:])