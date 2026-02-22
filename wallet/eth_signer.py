from __future__ import annotations

from Crypto.Hash import keccak
from eth_keys import keys


def k256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def eip712_typed_hash(rho: bytes, user_op_hash: bytes, chain_id: int, wallet_address: bytes) -> bytes:
    domain = k256(b'BiometricWallet' + b'1' + chain_id.to_bytes(32, 'big') + wallet_address)
    struct_hash = k256(rho + user_op_hash)
    return k256(b'\x19\x01' + domain + struct_hash)


def sign_hash(k_scalar: int, digest: bytes) -> bytes:
    priv = keys.PrivateKey(k_scalar.to_bytes(32, 'big'))
    return priv.sign_msg_hash(digest).to_bytes()


def recover_signer(digest: bytes, signature: bytes) -> bytes:
    sig = keys.Signature(signature_bytes=signature)
    return sig.recover_public_key_from_msg_hash(digest).to_canonical_address()
