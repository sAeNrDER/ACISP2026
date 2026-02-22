from __future__ import annotations

import secrets
from dataclasses import dataclass

from eth_keys import keys
from py_ecc.secp256k1.secp256k1 import G, N, add, multiply

from wallet.bekd_crypto import lagrange_coefficients_at_zero


@dataclass
class CANodeShare:
    index: int
    share: int


@dataclass
class DKGResult:
    master_secret: int
    public_key: tuple[int, int]
    shares: list[CANodeShare]


def run_simulated_dkg(n: int = 3) -> DKGResult:
    secret = secrets.randbelow(N - 1) + 1
    # (t=1,n=3): linear polynomial
    a1 = secrets.randbelow(N - 1) + 1
    shares = []
    for i in range(1, n + 1):
        s = (secret + a1 * i) % N
        shares.append(CANodeShare(i, s))
    return DKGResult(master_secret=secret, public_key=multiply(G, secret), shares=shares)


def aggregate_helpers(partials: dict[int, tuple[int, int]]) -> tuple[int, int]:
    coeffs = lagrange_coefficients_at_zero(partials.keys(), N)
    out = None
    for idx, point in partials.items():
        weighted = multiply(point, coeffs[idx])
        out = weighted if out is None else add(out, weighted)
    return out


def sign_message_with_master(master_secret: int, msg_scalar: int) -> bytes:
    priv = keys.PrivateKey(master_secret.to_bytes(32, "big"))
    sig = priv.sign_msg_hash(msg_scalar.to_bytes(32, "big"))
    return sig.to_bytes()


def verify_signature(public_key: tuple[int, int], msg_scalar: int, signature: bytes) -> bool:
    pk = keys.PublicKey(public_key[0].to_bytes(32, "big") + public_key[1].to_bytes(32, "big"))
    sig = keys.Signature(signature_bytes=signature)
    return pk.verify_msg_hash(msg_scalar.to_bytes(32, "big"), sig)
