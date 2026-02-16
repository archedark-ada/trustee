# AP2 Integration Specification for Trustee

**Version:** 1.1  
**Date:** 2026-02-16  
**Author:** Ada + Codex  
**Status:** Draft for Implementation (supersedes v1.0 draft dated 2026-02-15)

---

## Executive Summary

This specification defines AP2 mandate integration for Trustee with explicit security and operations requirements for production use. The v1.1 design keeps the MVP scope tight while closing high-risk gaps identified in v1.0.

Primary goals:
1. Cryptographically verifiable mandates with deterministic hashing and signature validation
2. On-chain revocation and issuer trust enforcement
3. Fail-closed steward enforcement at the signing boundary
4. Race-safe spending controls and clear operational runbooks

Design principle: ship a narrow, defensible v1, then expand with measured iteration.

---

## Scope and Non-Goals (v1)

### In Scope
- Single-chain support: Base mainnet (`eip155:8453`)
- Single asset support: USDC on Base mainnet
- Single issuer per mandate (with trusted issuer allowlisting)
- On-chain registry for mandate status and revocation
- Off-chain canonical payload storage referenced by hash
- Steward-side mandatory validation before every signature

### Explicitly Out of Scope
- m-of-n multi-signature mandates
- Mandate inheritance / transitive delegation
- Multi-asset FX normalization and cross-chain budgeting
- Complex analytics product features (dashboards, BI pipeline)

---

## Normative Language

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are to be interpreted as normative requirements.

---

## Architecture Overview

```
Issuer CLI -> Build canonical mandate payload -> Sign EIP-712 -> Submit on-chain
                    |                                 |
                    |                                 v
                    |                       Mandate Registry (Base)
                    v                                 |
        Local Mandate Store (JSON, durable)          | events/status
                    |                                 v
                    +-------> Steward Validator -> Final on-chain check -> Sign x402 tx
                                               |
                                               v
                                        Budget reserve/commit
```

Data of record by concern:
- Authorization status of a mandate: on-chain registry (source of truth)
- Full mandate constraints: canonical off-chain payload (validated by hash)
- Spending state (daily/session totals): Trustee budget tracker (durable, atomic)

---

## Component 1: Mandate Registry Contract

**Location:** `contracts/MandateRegistry.sol`

### Purpose
Immutable and queryable record of mandate issuance, trusted issuer permissions, and revocation state.

### Storage

```solidity
struct MandateRecord {
    bytes32 mandateHash;    // Hash of EIP-712 mandate object
    bytes32 payloadHash;    // keccak256(canonical mandate payload JSON bytes)
    address issuer;         // Recovered/declared issuer address
    address agent;          // Agent wallet authorized by this mandate
    uint64 issuedAt;        // block.timestamp at issuance
    uint64 expiresAt;       // 0 = no expiry
    uint64 revokedAt;       // 0 = active, non-zero = revoked
    string metadataURI;     // Content-addressed URI (ipfs://... or https://...)
}

mapping(bytes32 => MandateRecord) public mandates;
mapping(address => mapping(address => bool)) public trustedIssuerForAgent;
mapping(address => bool) public agentPaused;
mapping(address => bytes32[]) private mandateHashesByAgent;
```

### Events

```solidity
event TrustedIssuerUpdated(address indexed agent, address indexed issuer, bool allowed);
event AgentPauseUpdated(address indexed agent, bool paused, address indexed actor);

event MandateIssued(
    bytes32 indexed mandateHash,
    bytes32 indexed payloadHash,
    address indexed issuer,
    address agent,
    uint256 expiresAt,
    string metadataURI
);

event MandateRevoked(
    bytes32 indexed mandateHash,
    address indexed issuer,
    uint256 revokedAt
);
```

### Functions

```solidity
function setTrustedIssuer(address agent, address issuer, bool allowed) external;
function setAgentPaused(address agent, bool paused) external;

function issueMandateOnChain(
    bytes32 mandateHash,
    bytes32 payloadHash,
    address agent,
    uint64 expiresAt,
    string calldata metadataURI
) external;

function revokeMandate(bytes32 mandateHash) external;

function getMandateStatus(bytes32 mandateHash)
    external
    view
    returns (
        bool exists,
        bool active,
        bool revoked,
        uint64 expiresAt,
        address issuer,
        address agent,
        bytes32 payloadHash,
        string memory metadataURI
    );

function getMandatesByAgentPaged(address agent, uint256 cursor, uint256 size)
    external
    view
    returns (bytes32[] memory hashes, uint256 nextCursor);
```

### Access Control Rules
- `issueMandateOnChain` MUST revert unless `trustedIssuerForAgent[agent][msg.sender] == true`.
- `issueMandateOnChain` MUST revert if `agentPaused[agent] == true`.
- `revokeMandate` MUST only be callable by the original mandate issuer.
- `setTrustedIssuer` and `setAgentPaused` MUST be callable only by the agent and/or designated guardian authority (implementation choice, but MUST be documented in contract comments).
- Duplicate `mandateHash` issuance MUST revert.

### Contract Behavior Requirements
- `getMandatesByAgentPaged` MUST return both active and inactive hashes; callers MUST check status per hash.
- Registry MUST NOT encode local policy assumptions (for example "most permissive" selection logic).
- All state-changing operations MUST emit events for indexer reconciliation.

### Deployment
- Deploy to Base mainnet (`eip155:8453`)
- Verify source on Basescan
- Record contract address in environment/config and include in EIP-712 domain

---

## Component 2: Canonical Off-Chain Mandate Payload and Store

**Locations:**
- `src/trustee/mandate_store.py` (new)
- `src/trustee/mandate.py` (extend for canonical payload + hashing helpers)

### Purpose
Store full constraints off-chain while binding content integrity to on-chain `payloadHash`.

### Canonical Payload Requirements
- Payload MUST be serialized using deterministic canonical JSON (RFC 8785 JSON Canonicalization Scheme or an equivalent project-defined canonical function).
- Addresses MUST be normalized to lowercase hex with `0x` prefix.
- Amounts MUST be integers in base units, never floating point.
- `allowed_recipients` ordering MUST be normalized before hashing (sorted lowercase unique list).
- `asset_id` MUST use CAIP-19 style identifier for unambiguous chain+asset identity.

### v1 Payload Schema

```json
{
  "schema_version": "1",
  "mandate_hash": "0x...",
  "payload_hash": "0x...",
  "metadata_uri": "ipfs://...",
  "issuer": "0x...",
  "agent": "0x...",
  "network": "eip155:8453",
  "asset_id": "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913",
  "max_amount_per_tx": "1000000",
  "max_amount_per_day": "5000000",
  "allowed_recipients": ["0x...", "0x..."],
  "expires_at": 1771189200,
  "nonce": 1,
  "eip712_data": {"domain": {}, "types": {}, "message": {}},
  "issuer_signature": "0x...",
  "issued_at": 1770584400,
  "status": "pending_on_chain"
}
```

### Local Status Lifecycle
Allowed values: `draft`, `pending_on_chain`, `active`, `revoked`, `expired`, `failed`.

Lifecycle requirements:
1. New mandate MUST be persisted as `pending_on_chain` before network submission.
2. Status MUST transition to `active` only after on-chain transaction confirmation.
3. Failed submission MUST transition to `failed` and preserve error context.
4. Revocation events MUST update local status to `revoked`.
5. Expiry checks SHOULD mark `expired` lazily during reads and periodic cleanup.

### API Requirements

```python
class MandateStore:
    def save_mandate(self, mandate: Mandate) -> None: ...
    def get_mandate(self, mandate_hash: str) -> Optional[Mandate]: ...
    def list_mandates(self, agent: str, include_inactive: bool = False) -> list[Mandate]: ...
    def update_status(self, mandate_hash: str, status: str, reason: str | None = None) -> None: ...
    def record_chain_confirmation(self, mandate_hash: str, tx_hash: str, block_number: int) -> None: ...
    def cleanup_expired(self) -> int: ...
```

Durability and concurrency:
- Writes MUST be atomic (temp file + rename, or sqlite).
- Concurrent read/write access MUST be safe.
- Integrity check SHOULD include `payload_hash` recomputation on load.

---

## Component 3: Steward Enforcement

**Locations:**
- `src/trustee/mandate_validator.py` (new)
- `src/trustee/steward.py` (integration hook)
- `src/trustee/budget.py` (reuse existing atomic reserve/commit behavior)

### Purpose
Enforce mandate and budget constraints at the final signing boundary.

### Validation Pipeline (Required Order)
1. Parse normalized transaction intent (network, asset_id, recipient, amount_base_units).
2. Load candidate mandates for agent from local store.
3. Filter by local constraints (expiry, network, asset_id, recipient, per-tx bound).
4. Resolve mandate selection deterministically:
   - If `mandate_hash` is provided in request, only that mandate MAY be used.
   - If no `mandate_hash` and exactly one candidate matches, use it.
   - If no `mandate_hash` and multiple candidates match, reject as ambiguous.
5. Verify EIP-712 signature and recovered issuer against trusted issuer policy.
6. Reserve spend atomically using budget tracker (`reserve` then `commit`/`rollback`).
7. Immediately before signing, perform live on-chain status check (`getMandateStatus`) and confirm active/non-expired/non-paused.
8. Sign transaction.
9. Commit spend reservation; on failure, rollback reservation.

### Critical Security Requirements
- Cache MAY be used for candidate discovery only.
- Final on-chain status check at signing time MUST NOT be skipped.
- Any validation error, RPC error, metadata retrieval error, or budget store error MUST fail closed.
- Steward MUST reject transactions for paused agents.

### Revocation Freshness
- Validator SHOULD subscribe to `MandateRevoked` and `AgentPauseUpdated` events to invalidate cache quickly.
- Even with event-driven invalidation, final `getMandateStatus` check remains mandatory.

### Daily Limit Race Safety
- Daily/per-session limit checks MUST be atomic under concurrency.
- Non-atomic read-then-write spending checks are prohibited.
- Existing `BudgetTracker` transactional reserve/commit path SHOULD be reused instead of ad-hoc history summing.

---

## Component 4: CLI Tooling

**Location:** `src/trustee/cli.py` (extend with `trustee mandate ...` commands)

### Commands

```bash
trustee mandate issue \
  --agent 0xAgent \
  --asset-id eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913 \
  --max-per-tx 1000000 \
  --max-per-day 5000000 \
  --recipients 0xR1,0xR2 \
  --expires-in 30d \
  --issuer-key "op://Vault/Item/private key" \
  --metadata-uri ipfs://...

trustee mandate revoke --mandate-hash 0x... --issuer-key "op://..."
trustee mandate list --agent 0xAgent --include-inactive
trustee mandate status --mandate-hash 0x...
trustee mandate trust-issuer --agent 0xAgent --issuer 0xIssuer --allow
trustee mandate pause-agent --agent 0xAgent --pause true
trustee mandate check-expiry --within 72h
```

### CLI Behavior Requirements
- `issue` MUST print both local status and chain transaction status.
- `issue` MUST not report success until on-chain confirmation is observed.
- `list` and `status` SHOULD reconcile local status with on-chain state before output.
- Expiry check command SHOULD support optional notification sink (stdout/webhook).

### Template Support (Open Question Resolution)
- v1 SHOULD include CLI templates for common profiles (`micro`, `daily_ops`, `vendor_locked`).
- Templates are local presets only and MUST compile to explicit mandate fields before signing.
- On-chain/template IDs are out of scope for v1.

---

## EIP-712 Definitions

### Domain

```python
MANDATE_DOMAIN = {
    "name": "Trustee AP2",
    "version": "1",
    "chainId": 8453,
    "verifyingContract": "0xRegistryAddress"
}
```

### Types (v1)

```python
MANDATE_EIP712_TYPES = {
    "EIP712Domain": [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"}
    ],
    "Mandate": [
        {"name": "agent", "type": "address"},
        {"name": "payloadHash", "type": "bytes32"},
        {"name": "expiresAt", "type": "uint256"},
        {"name": "nonce", "type": "uint256"}
    ]
}
```

Notes:
- Full constraints live in the canonical payload and are integrity-bound by `payloadHash`.
- Steward MUST verify:
  1. `payloadHash == keccak256(canonical_payload_bytes)`
  2. EIP-712 signature recovers to trusted issuer
  3. `mandateHash` equals expected hash for signed message and matches registry record

---

## Operational Controls

### Key Rotation (Required Runbook)
1. Add new issuer as trusted for agent.
2. Issue replacement mandates with overlapping validity window.
3. Switch clients to new issuer key.
4. Revoke old mandates.
5. Remove old issuer from trusted list.

This runbook MUST be documented and test-rehearsed before production usage.

### Emergency Kill Switch
- On-chain: `setAgentPaused(agent, true)` MUST immediately block new mandate issuance and validation acceptance.
- Steward local: a runtime pause flag (for example `TRUSTEE_SIGNING_PAUSED=true`) SHOULD force immediate signing denial.
- All kill-switch activations MUST emit structured audit events.

### Outage and Degraded Mode Policy
- Registry RPC unavailable: reject signing (fail closed).
- Metadata URI fetch/canonicalization failure: reject signing.
- Budget storage unavailable: reject signing.
- Break-glass override MAY exist for manual operator workflows only and MUST be explicit, time-bounded, and fully audited. Agent-initiated payment path MUST NOT auto-fallback to break-glass.

---

## Supported Transaction Scope (v1)

v1 mandate enforcement applies only to x402 payment transactions that match all of:
- Network: Base mainnet (`eip155:8453`)
- Asset: Base USDC contract
- Transfer primitive: supported x402 USDC flow (EIP-3009)

Unsupported transaction classes in v1 (MUST reject):
- Native ETH transfers
- Arbitrary contract calls outside supported x402 flow
- Cross-chain or bridge operations
- Multi-asset baskets

---

## Security Considerations

### Threats and Mitigations

1. Unauthorized issuer creates mandate
- Mitigation: on-chain `trustedIssuerForAgent` check + steward trusted issuer verification

2. Payload tampering
- Mitigation: canonical JSON hash (`payloadHash`) checked by steward and bound in EIP-712 signature

3. Replay across chain/contract
- Mitigation: EIP-712 domain includes chainId and verifyingContract

4. Revocation bypass via stale cache
- Mitigation: mandatory final on-chain status check at signing time

5. Daily limit race under concurrency
- Mitigation: atomic budget reservation and commit/rollback

6. Ambiguous mandate selection
- Mitigation: explicit `mandate_hash` preferred; ambiguous auto-selection rejected

7. Outage-based bypass
- Mitigation: fail-closed policy, no silent fallback

8. Key compromise blast radius
- Mitigation: trusted issuer revocation + kill switch + rotation runbook

---

## Open Questions Resolved (v1 Decisions)

1. Multi-signature support
- Decision: not in v1.
- Follow-up: reserve schema/version extension point for m-of-n policy in v2.

2. Mandate templates
- Decision: yes, local CLI presets in v1.
- Follow-up: evaluate shared/template registry only after usage evidence.

3. Notification system
- Decision: yes, minimal expiry notifications in v1 (`check-expiry` + optional webhook sink).

4. Analytics
- Decision: no analytics product in v1.
- Follow-up: emit structured logs now to enable future analytics without schema rework.

5. Mandate inheritance
- Decision: not in v1.
- Follow-up: if revisited, require explicit non-transitive delegation and tighter subordinate limits.

---

## Implementation Phases

### Phase 0: Contract and Trust Model
- Implement `MandateRegistry.sol` with trusted issuer mapping, pause controls, paged query
- Deploy to Base Sepolia, then Base mainnet
- Verify on Basescan

Exit criteria:
- Contract tests pass (issuance auth, revoke auth, pause behavior, pagination)

### Phase 1: Canonical Payload + Store
- Implement `mandate_store.py` and canonical hash helpers
- Add payload hash integrity checks and lifecycle status transitions

Exit criteria:
- Concurrent safety tests pass
- Pending->active transition only after confirmed tx

### Phase 2: Steward Enforcement Integration
- Implement `mandate_validator.py`
- Integrate with signing path in `steward.py`/payment orchestration
- Enforce deterministic mandate selection and final on-chain status check

Exit criteria:
- Concurrency tests demonstrate no daily limit overspend
- Revocation effective immediately at signing boundary

### Phase 3: CLI and Operations
- Add `trustee mandate` command group
- Implement trust issuer management, pause commands, expiry checks, templates
- Add key rotation and emergency runbook docs

Exit criteria:
- End-to-end CLI workflow passes from issue->pay->revoke

### Phase 4: Hardening and Documentation
- Security checklist completion
- Structured audit log coverage for all decision points
- Operator docs for outage handling and break-glass policy

Exit criteria:
- No critical/high severity findings open

---

## Testing Strategy

### Unit Tests
- EIP-712 digest/signature verification and trusted issuer validation
- Canonical payload hashing determinism (same logical payload => same hash)
- Store lifecycle transitions and atomic file writes
- Mandate selection logic and ambiguity rejection

### Integration Tests
- Issue mandate -> confirm -> sign permitted tx
- Issue mandate -> revoke -> immediate rejection even with warm cache
- Agent paused -> rejection path
- RPC outage -> fail-closed rejection
- Metadata tamper (payload hash mismatch) -> rejection

### Concurrency Tests
- Two concurrent tx attempts at daily boundary: exactly one succeeds
- Reservation rollback on downstream signing failure

### Security Tests
- Forged signature
- Untrusted issuer
- Cross-chain replay attempt
- Expired mandate/time boundary tests
- Cache poisoning attempts

Coverage target: 90%+ for new AP2 modules.

---

## Success Criteria

AP2 integration is production-ready when all are true:
- All required tests pass
- Trusted issuer + pause controls deployed and exercised
- At least one real mandate issued, enforced, revoked on Base mainnet
- Key rotation runbook tested end-to-end
- Outage/fail-closed behavior verified in staging
- Operator documentation complete

---

## References

- EIP-712: https://eips.ethereum.org/EIPS/eip-712
- Base docs: https://docs.base.org/
- x402 protocol: https://github.com/base-org/x402
- AP2 status: awaiting official stable spec publication

