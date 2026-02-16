# Contracts Workspace (Phase 0)

This directory contains the AP2 on-chain mandate registry and Foundry-based tests/deployment scripts.

## Prerequisites

- [Foundry](https://book.getfoundry.sh/getting-started/installation)
- Base RPC URLs and Basescan API key

## Quick Start

```bash
cd contracts
forge install foundry-rs/forge-std
forge build
forge test -vv
```

## Environment Variables

- `BASE_SEPOLIA_RPC_URL`
- `BASE_RPC_URL`
- `BASESCAN_API_KEY`
- `DEPLOYER_PRIVATE_KEY`
- `MANDATE_GUARDIAN` (optional, defaults to deployer)

## Deploy

### Base Sepolia

```bash
cd contracts
forge script script/DeployMandateRegistry.s.sol:DeployMandateRegistry \
  --rpc-url base_sepolia \
  --broadcast \
  --verify \
  -vvvv
```

### Base Mainnet

```bash
cd contracts
forge script script/DeployMandateRegistry.s.sol:DeployMandateRegistry \
  --rpc-url base \
  --broadcast \
  --verify \
  -vvvv
```

## Test Focus (Phase 0)

- Trusted issuer authorization
- Pause controls
- Issuance/revocation authorization
- Expiry semantics
- Pagination over active + inactive mandates
