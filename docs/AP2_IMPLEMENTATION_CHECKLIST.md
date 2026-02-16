# AP2 Integration Implementation Checklist

**Source Spec:** `docs/AP2_INTEGRATION_SPEC.md` (v1.1, 2026-02-16)  
**Purpose:** Execution tracker for implementation and readiness sign-off.

---

## How To Use This Checklist

- Keep boxes unchecked until code is merged and validated.
- Attach evidence (test output, tx hash, screenshot, PR link) to each completed item.
- Do not start a new phase until the prior phase exit criteria are met.

---

## Phase 0: Contract and Trust Model

### 0.1 Scaffold and Contract Design
- [ ] Create `contracts/` workspace (Foundry or existing Solidity tooling) and document commands in `README`.
- [ ] Implement `contracts/MandateRegistry.sol` with:
- [ ] `trustedIssuerForAgent` mapping
- [ ] `agentPaused` mapping
- [ ] `MandateRecord` storage (`mandateHash`, `payloadHash`, `issuer`, `agent`, `issuedAt`, `expiresAt`, `revokedAt`, `metadataURI`)
- [ ] `setTrustedIssuer` access control
- [ ] `setAgentPaused` access control
- [ ] `issueMandateOnChain` authorization + duplicate protection
- [ ] `revokeMandate` issuer-only authorization
- [ ] `getMandateStatus` status view
- [ ] `getMandatesByAgentPaged` pagination
- [ ] Emit all required events (`TrustedIssuerUpdated`, `AgentPauseUpdated`, `MandateIssued`, `MandateRevoked`).

### 0.2 Contract Tests
- [ ] Add tests for trusted issuer gating.
- [ ] Add tests for paused agent behavior.
- [ ] Add tests for revoke authorization.
- [ ] Add tests for expiry semantics.
- [ ] Add tests for duplicate issuance rejection.
- [ ] Add tests for pagination behavior.

### 0.3 Deployment
- [ ] Deploy to Base Sepolia first.
- [ ] Run smoke tests on deployed Sepolia contract.
- [ ] Deploy to Base mainnet (`eip155:8453`).
- [ ] Verify contract on Basescan.
- [ ] Record addresses and ABI config in repo config docs.

### Phase 0 Exit Criteria
- [ ] All contract tests passing.
- [ ] Sepolia + mainnet addresses documented.
- [ ] Basescan verification links recorded.

---

## Phase 1: Canonical Payload and Local Store

### 1.1 Canonical Payload Utilities
- [ ] Extend `src/trustee/mandate.py` with canonical serialization/hashing helpers.
- [ ] Implement deterministic canonical JSON function.
- [ ] Normalize addresses (lowercase + `0x`).
- [ ] Normalize and sort unique recipient allowlist.
- [ ] Enforce integer base units for amounts.
- [ ] Enforce CAIP-style asset identifier support.

### 1.2 Mandate Store
- [ ] Add `src/trustee/mandate_store.py` with required APIs:
- [ ] `save_mandate`
- [ ] `get_mandate`
- [ ] `list_mandates`
- [ ] `update_status`
- [ ] `record_chain_confirmation`
- [ ] `cleanup_expired`
- [ ] Implement lifecycle statuses: `draft`, `pending_on_chain`, `active`, `revoked`, `expired`, `failed`.
- [ ] Enforce `pending_on_chain -> active` only after confirmed chain tx.
- [ ] Add atomic write strategy (temp-file + rename or sqlite).
- [ ] Add concurrent access protection.
- [ ] Add payload hash integrity check on load.

### 1.3 Tests
- [ ] Add unit tests for canonical hash determinism.
- [ ] Add unit tests for lifecycle transitions.
- [ ] Add concurrent read/write tests.
- [ ] Add tests for integrity mismatch failure behavior.

### Phase 1 Exit Criteria
- [ ] Deterministic payload hash tests passing.
- [ ] Concurrency tests passing.
- [ ] Lifecycle transition constraints enforced.

---

## Phase 2: Steward Enforcement Integration

### 2.1 Validator Implementation
- [ ] Add `src/trustee/mandate_validator.py`.
- [ ] Implement validation pipeline in required order from spec.
- [ ] Add deterministic mandate selection rules:
- [ ] explicit `mandate_hash` path
- [ ] single-candidate auto-select
- [ ] multi-candidate ambiguity rejection
- [ ] Verify EIP-712 signer and trusted issuer binding.
- [ ] Validate payload hash against canonical payload bytes.

### 2.2 Signing Path Integration
- [ ] Integrate validator into signing boundary in `src/trustee/steward.py` and/or payment orchestration.
- [ ] Require live `getMandateStatus` check immediately before signing.
- [ ] Enforce fail-closed on RPC/store/validation errors.
- [ ] Reject when agent is paused.

### 2.3 Budget Race Safety
- [ ] Reuse atomic reserve/commit/rollback path from `src/trustee/budget.py`.
- [ ] Remove or block non-atomic read-then-write spending checks.
- [ ] Ensure rollback on downstream signing/submission failures.

### 2.4 Tests
- [ ] Unit tests for mandate matching and ambiguity rejection.
- [ ] Integration test: issue -> validate -> sign success path.
- [ ] Integration test: revoke -> immediate rejection path.
- [ ] Integration test: paused agent rejection path.
- [ ] Integration test: metadata hash mismatch rejection.
- [ ] Integration test: RPC outage fail-closed behavior.
- [ ] Concurrency test: daily boundary double-spend race (only one success).

### Phase 2 Exit Criteria
- [ ] All validator/integration tests passing.
- [ ] Demonstrated immediate revocation enforcement at signing boundary.
- [ ] Concurrency tests prove no daily cap overspend.

---

## Phase 3: CLI and Ops Controls

### 3.1 CLI Commands
- [ ] Extend `src/trustee/cli.py` with `trustee mandate` group.
- [ ] Implement `mandate issue`.
- [ ] Implement `mandate revoke`.
- [ ] Implement `mandate list`.
- [ ] Implement `mandate status`.
- [ ] Implement `mandate trust-issuer`.
- [ ] Implement `mandate pause-agent`.
- [ ] Implement `mandate check-expiry`.

### 3.2 CLI Behavior Quality
- [ ] `issue` reports pending + confirmed chain status.
- [ ] `issue` does not claim success before confirmation.
- [ ] `list` and `status` reconcile with on-chain state.
- [ ] Add clear operator-facing error messages for fail-closed cases.

### 3.3 Template Presets
- [ ] Add local templates (`micro`, `daily_ops`, `vendor_locked`).
- [ ] Compile templates into explicit mandate fields before signing.
- [ ] Document template behavior and boundaries.

### 3.4 Notification Hook
- [ ] Add expiry warning command (`--within` duration parsing).
- [ ] Add optional webhook output mode.
- [ ] Add tests for threshold calculations and output behavior.

### 3.5 Ops Runbooks
- [ ] Document key rotation runbook.
- [ ] Document emergency kill switch runbook.
- [ ] Document outage/fail-closed runbook.
- [ ] Document any manual break-glass procedure with audit requirements.

### Phase 3 Exit Criteria
- [ ] End-to-end CLI flow works: trust issuer -> issue -> sign pay -> revoke -> reject.
- [ ] Runbooks complete and reviewed.

---

## Phase 4: Hardening and Production Readiness

### 4.1 Security Tests
- [ ] Forged signature test.
- [ ] Untrusted issuer test.
- [ ] Cross-chain replay rejection test.
- [ ] Expired mandate boundary tests.
- [ ] Cache poisoning attempt tests.

### 4.2 Logging and Audit
- [ ] Emit structured decision logs for every validation result.
- [ ] Ensure logs include `mandate_hash`, `issuer`, `agent`, reason code, and tx context.
- [ ] Ensure pause/kill-switch actions are logged.

### 4.3 Staging Validation
- [ ] Staging outage simulation: RPC down -> fail closed.
- [ ] Staging metadata retrieval failure -> fail closed.
- [ ] Staging budget store failure -> fail closed.

### 4.4 Mainnet Verification
- [ ] Execute one full mainnet happy-path transaction under mandate.
- [ ] Revoke mandate and verify subsequent rejection.
- [ ] Archive tx hashes and logs in docs.

### Phase 4 Exit Criteria
- [ ] No open critical/high severity defects.
- [ ] Coverage target met for AP2 modules (90%+).
- [ ] Operator documentation complete.

---

## Cross-Cutting Decisions (v1 Locked)

- [ ] Multi-signature mandates deferred to v2.
- [ ] Mandate inheritance/delegation deferred to v2.
- [ ] Analytics product features deferred; structured logs enabled now.
- [ ] Supported scope locked to Base mainnet USDC x402 path only.

---

## Final Go-Live Checklist

- [ ] Contract addresses and env config validated in production.
- [ ] Trusted issuer list reviewed and minimal.
- [ ] Kill switch tested in live-like environment.
- [ ] Key rotation rehearsal completed.
- [ ] Alerting/notification path validated.
- [ ] Incident response contacts and runbooks confirmed.

