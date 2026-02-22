# Decentralized BEKD Biometric Authentication System

A reference implementation of a **privacy-preserving, decentralized biometric authentication architecture** that combines:

- **BEKD (Biometric-Enhanced Key Derivation)** for off-chain biometric-bound key recovery.
- A **(t, n) threshold CA consortium** (configured as `t=1, n=3`) to avoid single-point trust.
- **Ethereum smart contracts** for on-chain freshness enforcement and authorization.
- An **Account Abstraction-oriented wallet flow** with ECDSA/EIP-1271 style verification semantics.

> **Security principle:** biometric artifacts remain off-chain. The blockchain layer handles freshness and signature validation only.

---

## Highlights

- Domain-separated BEKD hash functions (`H0`, `H1`, `H2`, `H3`, `Htag`).
- Shamir secret sharing (`tbio=4`) over secp256k1 scalar field.
- Threshold helper aggregation using Lagrange interpolation without reconstructing CA master secret during retrieval.
- Replay defense via token identifier burn (`rho`) in `SpentSet`.
- End-to-end test scaffolding for enrollment, retrieval, replay resistance, and threshold correctness.

---

## System Architecture

```text
User Wallet (Off-chain)
  ├─ Biometric capture + BEKD token handling
  ├─ Key recovery and ECDSA signing
  └─ Calls CA consortium and chain-facing contracts

Threshold CA Consortium (Off-chain)
  ├─ n=3 nodes, threshold t=1 (2-of-3 participation)
  ├─ Enrollment signing helpers
  └─ Retrieval helper generation + local token-use tracking

Blockchain (On-chain)
  ├─ ParamRegistry (public parameters)
  ├─ Authorization (wallet allowlist)
  ├─ SpentSet (freshness / replay protection)
  └─ BiometricWallet (owner signature validation + mark-used)
```

---

## Repository Structure

```text
contracts/
  Authorization.sol
  ParamRegistry.sol
  SpentSet.sol
  BiometricWallet.sol
  interfaces/ISpentSet.sol

ca_consortium/
  ca_config.py
  ca_node.py
  run_consortium.py
  threshold_crypto.py

wallet/
  bekd_crypto.py
  biometric_sim.py
  eth_signer.py
  token_storage.py
  wallet_client.py

tests/
  test_enrollment.py
  test_retrieval.py
  test_authentication.py
  test_replay_attack.py
  test_threshold.py
  test_gas_costs.py

scripts/
  deploy.js
  interact.js
```

---

## Runtime Requirements

Recommended baseline environment:

- **OS:** Linux or macOS (Ubuntu 22.04+ recommended)
- **Python:** 3.10 (3.9+ compatible by design)
- **Node.js:** 18+
- **npm:** 9+
- Network access to package registries (PyPI/npm), or configured internal mirrors

Version sources in this repository:

- Python package constraints: `requirements.txt`
- Node/Hardhat dependencies: `package.json`
- Solidity compiler settings: `hardhat.config.js`

---

## Installation

From repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt

npm install
```

### Optional: mirror configuration for restricted networks

```bash
pip config set global.index-url https://pypi.tuna.tsinghua.edu.cn/simple
npm config set registry https://registry.npmmirror.com
```

---

## Build and Test

```bash
# Python protocol tests
pytest -q

# Solidity compilation
npx hardhat compile
```

---

## End-to-End Execution (Three-Terminal Workflow)

Open **three terminals**, all at repository root, with the same Python virtualenv activated.

### Terminal A — Start CA consortium

```bash
python ca_consortium/run_consortium.py
```

Expected: three Flask CA services bind to ports `5001`, `5002`, `5003`.

### Terminal B — Start local Ethereum node

```bash
npx hardhat node
```

### Terminal C — Deploy and execute wallet flow

```bash
# Deploy on localhost network
npx hardhat run scripts/deploy.js --network localhost

# 1) Enrollment
python wallet/wallet_client.py --action enroll

# 2) Retrieval
python wallet/wallet_client.py --action retrieve

# 3) Authentication
python wallet/wallet_client.py --action authenticate
```

---

## Troubleshooting

- **`pip install` fails with proxy/403 errors**
  - Configure proxy or switch to a reachable mirror, then retry.
- **`pytest` reports `ModuleNotFoundError` (e.g., `numpy`, `py_ecc`)**
  - Python dependencies are incomplete; reinstall `requirements.txt` inside the active venv.
- **`npx hardhat compile` fails**
  - Ensure `npm install` completed successfully and Node/npm versions meet minimum requirements.

---

## Disclaimer

This repository is a **research-oriented prototype** intended for architecture validation and experimentation. It is **not production-hardened** and should not be deployed in adversarial environments without a full security review, cryptographic audit, and protocol hardening.
