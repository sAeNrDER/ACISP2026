# Decentralized BEKD Biometric Authentication System

This repository implements a reference architecture for BEKD-based biometric authentication with:

- Off-chain BEKD enrollment/retrieval and biometric simulation
- Simulated threshold CA consortium (`t=1, n=3`) without master key reconstruction during helper aggregation
- Smart-contract freshness layer (`SpentSet`) and wallet signature validation flow
- Test coverage for enrollment, retrieval mismatch, replay prevention, and threshold helper correctness

## Project Layout

- `wallet/`: BEKD cryptography, biometric simulator, token storage, wallet flow logic
- `ca_consortium/`: threshold helper math, per-node Flask app, and 3-node launcher
- `contracts/`: ParamRegistry, SpentSet, Authorization, and BiometricWallet contracts
- `tests/`: end-to-end and protocol property tests

## Quickstart

```bash
pip install -r requirements.txt
npm install
pytest
```

Optionally compile contracts:

```bash
npx hardhat compile
```
