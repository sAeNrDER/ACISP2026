from py_ecc.secp256k1.secp256k1 import G, add, eq, multiply

from ca_consortium.threshold_crypto import run_simulated_dkg
from wallet.bekd_crypto import lagrange_coefficients_at_zero


def test_threshold_helper_aggregation_matches_master():
    dkg = run_simulated_dkg(3)
    r = 123456
    R0 = multiply(G, r)
    quorum = dkg.shares[:2]
    partials = {s.index: multiply(R0, s.share) for s in quorum}
    coeffs = lagrange_coefficients_at_zero(partials.keys())
    out = None
    for idx, part in partials.items():
        weighted = multiply(part, coeffs[idx])
        out = weighted if out is None else add(out, weighted)
    assert eq(out, multiply(R0, dkg.master_secret))
