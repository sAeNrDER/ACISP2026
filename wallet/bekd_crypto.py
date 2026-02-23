from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from Crypto.Hash import keccak
from py_ecc.secp256k1.secp256k1 import G, N, add, multiply


def _k256(data: bytes) -> bytes:
    h = keccak.new(digest_bits=256)
    h.update(data)
    return h.digest()


def _scalar(data: bytes) -> int:
    return int.from_bytes(data, "big") % N


def serialize_int(x: int) -> bytes:
    return int(x).to_bytes(32, "big", signed=False)


def serialize_point(p: tuple[int, int] | None) -> bytes:
    if p is None:
        return b"\x00" * 64
    return serialize_int(p[0]) + serialize_int(p[1])


def H0(Wi: float, c: bytes) -> int:
    return _scalar(_k256(b"\x00" + repr(float(Wi)).encode() + c))


def H1(M: tuple[int, int], Mwi: tuple[int, int]) -> int:
    return _scalar(_k256(b"\x01" + serialize_point(M) + serialize_point(Mwi)))


def H2(R0: tuple[int, int], R1: tuple[int, int], hA: int) -> int:
    return _scalar(_k256(b"\x02" + serialize_point(R0) + serialize_point(R1) + serialize_int(hA)))


def H3(blob: bytes) -> int:
    return _scalar(_k256(b"\x03" + blob))


def Htag(index: int, rho: bytes, Zi: int, lambda_bytes: int = 32) -> bytes:
    return _k256(b"\x04" + serialize_int(index) + rho + serialize_int(Zi))[:lambda_bytes]


def token_id(R0: tuple[int, int]) -> bytes:
    return _k256(serialize_point(R0))


def lagrange_coefficients_at_zero(indices: Iterable[int], mod: int = N) -> dict[int, int]:
    idx = list(indices)
    coeffs: dict[int, int] = {}
    for i in idx:
        num, den = 1, 1
        for j in idx:
            if i == j:
                continue
            num = (num * (-j % mod)) % mod
            den = (den * (i - j)) % mod
        coeffs[i] = (num * pow(den, -1, mod)) % mod
    return coeffs


def shamir_poly(secret: int, degree: int, rand_scalar) -> list[int]:
    return [secret] + [rand_scalar() for _ in range(degree)]


def poly_eval(coeffs: list[int], x: int, mod: int = N) -> int:
    acc, xn = 0, 1
    for c in coeffs:
        acc = (acc + c * xn) % mod
        xn = (xn * x) % mod
    return acc


def interpolate_zero(points: list[tuple[int, int]], mod: int = N) -> int:
    coeffs = lagrange_coefficients_at_zero([i for i, _ in points], mod)
    return sum((y * coeffs[i]) % mod for i, y in points) % mod


def point_mul(s: int, p: tuple[int, int] = G) -> tuple[int, int]:
    return multiply(p, s % N)


def point_add(a: tuple[int, int], b: tuple[int, int]) -> tuple[int, int]:
    return add(a, b)


@dataclass
class Envelope:
    R0: tuple[int, int]
    R1: tuple[int, int]
    M: tuple[int, int]
    rho: bytes


def build_envelope(pk_ca: tuple[int, int], k: int, r: int) -> Envelope:
    R0 = point_mul(r)
    M = point_mul(r, pk_ca)
    K = point_mul(k)
    R1 = point_add(M, K)
    return Envelope(R0=R0, R1=R1, M=M, rho=token_id(R0))
