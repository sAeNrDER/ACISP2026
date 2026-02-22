from __future__ import annotations

import csv
import secrets
import statistics
import time
from dataclasses import dataclass

from Crypto.Hash import keccak
from eth_keys import keys
from py_ecc.secp256k1.secp256k1 import G, N, add, multiply, neg


d = 128
tbio = 4
MATCH_COUNT = 120
NUM_RUNS = 50


Point = tuple[int, int]


def keccak256(data: bytes) -> bytes:
    k = keccak.new(digest_bits=256)
    k.update(data)
    return k.digest()


def serialize_point(P: Point) -> bytes:
    x, y = P
    return x.to_bytes(32, "big") + y.to_bytes(32, "big")


def H0(Wi_bytes: bytes, c: bytes) -> int:
    return int.from_bytes(keccak256(b"\x00" + Wi_bytes + c), "big") % N


def H1(M_point: Point, Mwi_point: Point) -> int:
    return int.from_bytes(keccak256(b"\x01" + serialize_point(M_point) + serialize_point(Mwi_point)), "big") % N


def H2(R0: Point, R1: Point, hA: int) -> int:
    return int.from_bytes(
        keccak256(b"\x02" + serialize_point(R0) + serialize_point(R1) + hA.to_bytes(32, "big")), "big"
    ) % N


def H3(data: bytes) -> int:
    return int.from_bytes(keccak256(b"\x03" + data), "big") % N


def Htag(i: int, rho: bytes, Zi: int) -> bytes:
    return keccak256(b"\x04" + i.to_bytes(4, "big") + rho + Zi.to_bytes(32, "big"))


def random_scalar() -> int:
    return secrets.randbelow(N - 1) + 1


def lagrange_coefficients_at_zero(indices: list[int]) -> dict[int, int]:
    coeffs: dict[int, int] = {}
    for i in indices:
        num, den = 1, 1
        for j in indices:
            if i == j:
                continue
            num = (num * (-j % N)) % N
            den = (den * (i - j)) % N
        coeffs[i] = (num * pow(den, -1, N)) % N
    return coeffs


def shamir_poly(secret: int, degree: int) -> list[int]:
    return [secret] + [random_scalar() for _ in range(degree)]


def poly_eval(coeffs: list[int], x: int) -> int:
    acc, xp = 0, 1
    for c in coeffs:
        acc = (acc + c * xp) % N
        xp = (xp * x) % N
    return acc


def interpolate_zero(points: list[tuple[int, int]]) -> int:
    coeffs = lagrange_coefficients_at_zero([i for i, _ in points])
    return sum((y * coeffs[i]) % N for i, y in points) % N


def summarize(times_ms: list[float]) -> tuple[float, float, float]:
    mean = statistics.mean(times_ms)
    std = statistics.pstdev(times_ms) if len(times_ms) > 1 else 0.0
    return statistics.median(times_ms), mean, std


def to_feature_bytes(v: float) -> bytes:
    return format(v, ".8f").encode()


@dataclass
class BenchContext:
    sk_ca: int
    pk_ca: Point
    W: list[float]
    W_prime: list[float]


@dataclass
class EnrollmentArtifacts:
    k: int
    c: bytes
    rho: bytes
    R0: Point
    R1: Point
    M: Point
    A: list[int]
    tags: list[bytes]
    hA: int
    m: int
    sigma: bytes


def make_context() -> BenchContext:
    sk_ca = random_scalar()
    pk_ca = multiply(G, sk_ca)
    W = [secrets.randbelow(10_000) / 1000.0 for _ in range(d)]

    match_positions = set(range(MATCH_COUNT))
    W_prime = []
    for i, val in enumerate(W):
        W_prime.append(val if i in match_positions else secrets.randbelow(10_000) / 777.0)
    return BenchContext(sk_ca=sk_ca, pk_ca=pk_ca, W=W, W_prime=W_prime)


def enrollment_wallet_once(ctx: BenchContext) -> EnrollmentArtifacts:
    k = random_scalar()
    c = secrets.token_bytes(32)
    wi = [H0(to_feature_bytes(ctx.W[i]), c) for i in range(d)]

    r = random_scalar()
    R0 = multiply(G, r)
    M = multiply(ctx.pk_ca, r)
    K = multiply(G, k)
    R1 = add(M, K)
    rho = keccak256(serialize_point(R0))

    coeffs = shamir_poly(k, tbio - 1)

    A: list[int] = []
    tags: list[bytes] = []
    for i in range(1, d + 1):
        Mwi = multiply(M, wi[i - 1])
        Zi = H1(M, Mwi)
        Ai = (poly_eval(coeffs, i) + Zi) % N
        A.append(Ai)
        tags.append(Htag(i, rho, Zi))

    hA = H3(b"".join(a.to_bytes(32, "big") for a in A) + b"".join(tags))
    m = H2(R0, R1, hA)
    return EnrollmentArtifacts(k=k, c=c, rho=rho, R0=R0, R1=R1, M=M, A=A, tags=tags, hA=hA, m=m, sigma=b"")


def threshold_shares(secret: int, t: int, n: int) -> list[tuple[int, int]]:
    coeffs = [secret] + [random_scalar() for _ in range(t)]
    return [(i, poly_eval(coeffs, i)) for i in range(1, n + 1)]


def enrollment_ca_sign_once(message: int) -> bytes:
    # benchmark proxy: two partial ECDSA signatures + cheap combine hash
    sk1, sk2 = random_scalar(), random_scalar()
    msg = message.to_bytes(32, "big")
    sig1 = keys.PrivateKey(sk1.to_bytes(32, "big")).sign_msg_hash(msg).to_bytes()
    sig2 = keys.PrivateKey(sk2.to_bytes(32, "big")).sign_msg_hash(msg).to_bytes()
    return keccak256(sig1 + sig2)


def retrieval_ca_once(ctx: BenchContext, art: EnrollmentArtifacts, quorum_size: int, n_shares: int) -> tuple[list[tuple[int, int]], Point]:
    # Verify enrollment signature once in flow terms (standard ECDSA verify)
    pub = keys.PrivateKey(ctx.sk_ca.to_bytes(32, "big")).public_key
    sig = keys.PrivateKey(ctx.sk_ca.to_bytes(32, "big")).sign_msg_hash(art.m.to_bytes(32, "big"))
    if not pub.verify_msg_hash(art.m.to_bytes(32, "big"), sig):
        raise RuntimeError("signature verification failed")

    shares = threshold_shares(ctx.sk_ca, quorum_size - 1, n_shares)
    quorum = shares[:quorum_size]

    partials: dict[int, Point] = {idx: multiply(art.R0, share) for idx, share in quorum}
    lambdas = lagrange_coefficients_at_zero(list(partials.keys()))
    M = None
    for idx, h in partials.items():
        weighted = multiply(h, lambdas[idx])
        M = weighted if M is None else add(M, weighted)

    Kdec = add(art.R1, neg(M))

    matches: list[tuple[int, int]] = []
    for i in range(1, d + 1):
        wpi = H0(to_feature_bytes(ctx.W_prime[i - 1]), art.c)
        Zpi = H1(M, multiply(M, wpi))
        if Htag(i, art.rho, Zpi) == art.tags[i - 1]:
            matches.append((i, Zpi))
    return matches, Kdec


def retrieval_wallet_once(art: EnrollmentArtifacts, matches: list[tuple[int, int]], Kdec: Point) -> int:
    chosen = matches[:tbio]
    points = [(i, (art.A[i - 1] - Zi) % N) for i, Zi in chosen]
    k = interpolate_zero(points)
    if multiply(G, k) != Kdec:
        raise RuntimeError("recovery check failed")
    return k


def ecdsa_sign_once(k: int) -> bytes:
    digest = keccak256(b"typed-hash-for-bekd-auth")
    return keys.PrivateKey(k.to_bytes(32, "big")).sign_msg_hash(digest).to_bytes()


def benchmark_enrollment_wallet(ctx: BenchContext) -> tuple[float, float, float]:
    times = []
    for _ in range(NUM_RUNS):
        st = time.perf_counter()
        enrollment_wallet_once(ctx)
        times.append((time.perf_counter() - st) * 1000)
    return summarize(times)


def benchmark_enrollment_ca_signing(message: int) -> tuple[float, float, float]:
    times = []
    for _ in range(NUM_RUNS):
        st = time.perf_counter()
        enrollment_ca_sign_once(message)
        times.append((time.perf_counter() - st) * 1000)
    return summarize(times)


def benchmark_retrieval_ca(ctx: BenchContext, art: EnrollmentArtifacts, quorum_size: int = 2, n_shares: int = 3) -> tuple[float, float, float]:
    times = []
    for _ in range(NUM_RUNS):
        st = time.perf_counter()
        retrieval_ca_once(ctx, art, quorum_size=quorum_size, n_shares=n_shares)
        times.append((time.perf_counter() - st) * 1000)
    return summarize(times)


def benchmark_retrieval_wallet(ctx: BenchContext, art: EnrollmentArtifacts) -> tuple[float, float, float]:
    times = []
    for _ in range(NUM_RUNS):
        matches, Kdec = retrieval_ca_once(ctx, art, quorum_size=2, n_shares=3)
        if len(matches) < tbio:
            raise RuntimeError("insufficient matches for wallet recovery benchmark")
        st = time.perf_counter()
        retrieval_wallet_once(art, matches, Kdec)
        times.append((time.perf_counter() - st) * 1000)
    return summarize(times)


def benchmark_ecdsa_sign(k: int) -> tuple[float, float, float]:
    times = []
    for _ in range(NUM_RUNS):
        st = time.perf_counter()
        ecdsa_sign_once(k)
        times.append((time.perf_counter() - st) * 1000)
    return summarize(times)


def benchmark_threshold_scalability(ctx: BenchContext, art: EnrollmentArtifacts) -> list[tuple[int, int, int, float, float, float]]:
    configs = [(1, 3), (2, 5), (3, 7), (5, 10)]
    rows = []
    for t_val, n_val in configs:
        quorum = t_val + 1
        med, mean, std = benchmark_retrieval_ca(ctx, art, quorum_size=quorum, n_shares=n_val)
        rows.append((t_val, n_val, quorum, med, mean, std))
    return rows


def main() -> None:
    ctx = make_context()
    base_art = enrollment_wallet_once(ctx)

    print("=" * 72)
    print("BEKD Off-Chain Performance Benchmark")
    print(f"Parameters: d={d}, tbio={tbio}, MATCH_COUNT={MATCH_COUNT}, NUM_RUNS={NUM_RUNS}")
    print("=" * 72)

    enroll_wallet = benchmark_enrollment_wallet(ctx)
    enroll_ca = benchmark_enrollment_ca_signing(base_art.m)
    retrieve_ca = benchmark_retrieval_ca(ctx, base_art)
    retrieve_wallet = benchmark_retrieval_wallet(ctx, base_art)
    ecdsa_sign = benchmark_ecdsa_sign(base_art.k)

    total_enroll = enroll_wallet[1] + enroll_ca[1]
    total_auth = retrieve_ca[1] + retrieve_wallet[1] + ecdsa_sign[1]

    print("\n--- Table A: Operation Latency Breakdown ---")
    print(f"{'Operation':<35} {'Median (ms)':>12} {'Mean (ms)':>12} {'Std (ms)':>10}")
    print("-" * 74)
    print(f"{'Enrollment (wallet)':<35} {enroll_wallet[0]:>12.2f} {enroll_wallet[1]:>12.2f} {enroll_wallet[2]:>10.2f}")
    print(f"{'Enrollment (CA signing)':<35} {enroll_ca[0]:>12.2f} {enroll_ca[1]:>12.2f} {enroll_ca[2]:>10.2f}")
    print(f"{'Retrieval (CA side)':<35} {retrieve_ca[0]:>12.2f} {retrieve_ca[1]:>12.2f} {retrieve_ca[2]:>10.2f}")
    print(
        f"{'Retrieval (wallet recovery)':<35} {retrieve_wallet[0]:>12.2f} {retrieve_wallet[1]:>12.2f} {retrieve_wallet[2]:>10.2f}"
    )
    print(f"{'ECDSA signing':<35} {ecdsa_sign[0]:>12.2f} {ecdsa_sign[1]:>12.2f} {ecdsa_sign[2]:>10.2f}")
    print("-" * 74)
    print(f"{'TOTAL Enrollment':<35} {'':>12} {total_enroll:>12.2f}")
    print(f"{'TOTAL Authentication':<35} {'':>12} {total_auth:>12.2f}")

    scalability = benchmark_threshold_scalability(ctx, base_art)
    print("\n--- Table B: Threshold Scalability ---")
    print(f"{'(t, n)':<10} {'Quorum':>8} {'Median (ms)':>12} {'Mean (ms)':>12} {'Std (ms)':>10}")
    print("-" * 58)
    for t_val, n_val, quorum, med, mean, std in scalability:
        print(f"{f'({t_val},{n_val})':<10} {quorum:>8} {med:>12.2f} {mean:>12.2f} {std:>10.2f}")

    with open("offchain_benchmark_results.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Operation", "Median_ms", "Mean_ms", "Std_ms"])
        writer.writerow(["Enrollment_wallet", *enroll_wallet])
        writer.writerow(["Enrollment_CA", *enroll_ca])
        writer.writerow(["Retrieval_CA", *retrieve_ca])
        writer.writerow(["Retrieval_wallet", *retrieve_wallet])
        writer.writerow(["ECDSA_sign", *ecdsa_sign])
        writer.writerow(["Total_enrollment", "", total_enroll, ""])
        writer.writerow(["Total_authentication", "", total_auth, ""])
        writer.writerow([])
        writer.writerow(["Threshold_t", "Threshold_n", "Quorum", "Median_ms", "Mean_ms", "Std_ms"])
        writer.writerows(scalability)

    print("\nResults saved to offchain_benchmark_results.csv")


if __name__ == "__main__":
    main()
