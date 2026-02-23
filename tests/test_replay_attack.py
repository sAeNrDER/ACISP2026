import numpy as np

from wallet.biometric_sim import generate_noisy_biometric
from wallet.wallet_client import BEKDWallet


def test_replay_attack_second_auth_fails():
    wallet = BEKDWallet()
    token = wallet.enroll()
    noisy = generate_noisy_biometric(np.array(token['biometric']), match_ratio=0.95, seed=3)
    k = wallet.retrieve(noisy)
    assert wallet.authenticate(k) is True
    assert wallet.authenticate(k) is False
