import numpy as np

from wallet.biometric_sim import generate_noisy_biometric
from wallet.wallet_client import BEKDWallet


def test_retrieval_success_with_matching_features():
    wallet = BEKDWallet()
    token = wallet.enroll()
    noisy = generate_noisy_biometric(np.array(token['biometric']), match_ratio=0.95, seed=11)
    k = wallet.retrieve(noisy)
    assert k is not None


def test_retrieval_fails_with_low_matching_features():
    wallet = BEKDWallet()
    token = wallet.enroll()
    noisy = generate_noisy_biometric(np.array(token['biometric']), match_ratio=0.01, seed=17)
    k = wallet.retrieve(noisy)
    assert k is None
