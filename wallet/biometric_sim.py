import numpy as np


def generate_biometric(d: int = 128, seed: int | None = None) -> np.ndarray:
    rng = np.random.default_rng(seed)
    return rng.normal(0, 1, size=d)


def generate_noisy_biometric(
    original: np.ndarray,
    noise_std: float = 0.1,
    match_ratio: float = 0.95,
    seed: int | None = None,
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    noisy = original.copy()
    n_match = int(match_ratio * len(original))
    match_indices = set(rng.choice(len(original), n_match, replace=False).tolist())
    for i in range(len(original)):
        if i in match_indices:
            noisy[i] = original[i]
        else:
            noisy[i] = rng.normal(0, 1) + noise_std
    return noisy
