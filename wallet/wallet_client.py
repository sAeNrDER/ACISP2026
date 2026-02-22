from __future__ import annotations

import argparse
import secrets
from dataclasses import dataclass

from py_ecc.secp256k1.secp256k1 import G, N, add, eq, multiply, neg

from ca_consortium.threshold_crypto import run_simulated_dkg, sign_message_with_master, verify_signature
from wallet.bekd_crypto import (
    H0,
    H1,
    H2,
    H3,
    Htag,
    build_envelope,
    interpolate_zero,
    point_mul,
    poly_eval,
    shamir_poly,
)
from wallet.biometric_sim import generate_biometric, generate_noisy_biometric
from wallet.eth_signer import eip712_typed_hash, recover_signer, sign_hash
from wallet.token_storage import load_token, save_token


@dataclass
class ProtocolParams:
    d: int = 128
    tbio: int = 4
    t: int = 1
    n: int = 3
    lambda_bytes: int = 32


class MockSpentSet:
    def __init__(self):
        self.used = set()

    def mark_used(self, rho: bytes):
        if rho in self.used:
            raise ValueError('Token already spent')
        self.used.add(rho)


class BEKDWallet:
    def __init__(self, params: ProtocolParams | None = None):
        self.params = params or ProtocolParams()
        self.dkg = run_simulated_dkg(self.params.n)
        self.spent_set = MockSpentSet()
        self._ca_local_used: set[bytes] = set()

    def enroll(self, biometric=None) -> dict:
        W = biometric if biometric is not None else generate_biometric(self.params.d, seed=7)
        k = secrets.randbelow(N - 1) + 1
        c = secrets.token_bytes(32)
        w = [H0(float(W[i]), c) for i in range(self.params.d)]
        r = secrets.randbelow(N - 1) + 1
        env = build_envelope(self.dkg.public_key, k, r)
        coeffs = shamir_poly(k, self.params.tbio - 1, lambda: secrets.randbelow(N - 1) + 1)

        A, tags = [], []
        for i in range(1, self.params.d + 1):
            Zi = H1(env.M, point_mul(w[i - 1], env.M))
            Ai = (poly_eval(coeffs, i) + Zi) % N
            A.append(Ai)
            tags.append(Htag(i, env.rho, Zi, self.params.lambda_bytes).hex())

        hA = H3(b''.join(x.to_bytes(32, 'big') for x in A) + b''.join(bytes.fromhex(t) for t in tags))
        m = H2(env.R0, env.R1, hA)
        sigma = sign_message_with_master(self.dkg.master_secret, m)
        if not verify_signature(self.dkg.public_key, m, sigma):
            raise ValueError('Threshold signature verify failed')

        token = {
            'TU': {'c': c.hex(), 'rho': env.rho.hex()},
            'TCA': {
                'R0': [int(env.R0[0]), int(env.R0[1])],
                'R1': [int(env.R1[0]), int(env.R1[1])],
                'hA': int(hA),
                'sigma': sigma.hex(),
                'A': A,
                'tags': tags,
            },
            'biometric': [float(x) for x in W],
        }
        save_token(token)
        return token

    def retrieve(self, noisy_biometric) -> int | None:
        token = load_token()
        c = bytes.fromhex(token['TU']['c'])
        rho = bytes.fromhex(token['TU']['rho'])
        tca = token['TCA']
        R0 = tuple(tca['R0'])
        R1 = tuple(tca['R1'])
        hA = int(tca['hA'])
        sigma = bytes.fromhex(tca['sigma'])

        m = H2(R0, R1, hA)
        if not verify_signature(self.dkg.public_key, m, sigma):
            return None
        if rho in self._ca_local_used:
            return None
        self._ca_local_used.add(rho)

        # threshold helper combine from any t+1 shares
        quorum = self.dkg.shares[: self.params.t + 1]
        partials = {s.index: multiply(R0, s.share) for s in quorum}
        M = None
        from wallet.bekd_crypto import lagrange_coefficients_at_zero

        coeffs = lagrange_coefficients_at_zero(partials.keys(), N)
        for idx, part in partials.items():
            wpart = multiply(part, coeffs[idx])
            M = wpart if M is None else add(M, wpart)
        Kdec = add(R1, neg(M))

        matches = []
        for i in range(1, self.params.d + 1):
            wp = H0(float(noisy_biometric[i - 1]), c)
            Zi = H1(M, point_mul(wp, M))
            if Htag(i, rho, Zi, self.params.lambda_bytes).hex() == tca['tags'][i - 1]:
                matches.append((i, Zi))
        if len(matches) < self.params.tbio:
            return None

        selected = matches[: self.params.tbio]
        points = [(i, (tca['A'][i - 1] - Zi) % N) for i, Zi in selected]
        k = interpolate_zero(points)
        if not eq(point_mul(k), Kdec):
            return None
        return k

    def authenticate(self, k: int, user_op_hash: bytes = b'userop-hash'.ljust(32, b'\0')) -> bool:
        token = load_token()
        rho = bytes.fromhex(token['TU']['rho'])
        owner_addr = keys_from_scalar(k).public_key.to_canonical_address()
        typed = eip712_typed_hash(rho, user_op_hash, 31337, b'wallet-address-123456')
        sig = sign_hash(k, typed)
        recovered = recover_signer(typed, sig)
        if recovered != owner_addr:
            return False
        try:
            self.spent_set.mark_used(rho)
        except ValueError:
            return False
        return True


def keys_from_scalar(k: int):
    from eth_keys import keys

    return keys.PrivateKey(k.to_bytes(32, 'big'))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--action', required=True, choices=['enroll', 'retrieve', 'authenticate'])
    args = parser.parse_args()

    wallet = BEKDWallet()
    if args.action == 'enroll':
        token = wallet.enroll()
        print(f"enrolled rho={token['TU']['rho']}")
    elif args.action == 'retrieve':
        token = load_token()
        base = token['biometric']
        noisy = generate_noisy_biometric(__import__('numpy').array(base), match_ratio=0.96, seed=9)
        k = wallet.retrieve(noisy)
        print('retrieve', 'ok' if k else 'failed')
    else:
        token = load_token()
        base = token['biometric']
        noisy = generate_noisy_biometric(__import__('numpy').array(base), match_ratio=0.96, seed=9)
        k = wallet.retrieve(noisy)
        print('auth', wallet.authenticate(k) if k else False)


if __name__ == '__main__':
    main()
