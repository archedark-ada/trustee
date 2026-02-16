"""Security-focused AP2 tests (Phase 4 hardening)."""

from __future__ import annotations

import logging
import time

from eth_account import Account

from trustee.audit import AuditTrail
from trustee.mandate import AP2MandateStatus, create_ap2_mandate, create_mandate, verify_ap2_mandate
from trustee.mandate_registry import LocalMandateRegistry
from trustee.mandate_store import MandateStore
from trustee.mandate_validator import MandateValidator, TransactionIntent
from trustee.payment import PaymentExecutor, PaymentRequest


USDC_BASE_MAINNET = "eip155:8453/erc20:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913"
REGISTRY_PLACEHOLDER = "0x0000000000000000000000000000000000000001"
RECIPIENT = "0x1234567890123456789012345678901234567890"


def _issue_active_mandate(store: MandateStore, registry: LocalMandateRegistry, issuer, agent, *, nonce: int = 1):
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=1_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=[RECIPIENT],
        expires_at=1_900_000_000,
        nonce=nonce,
        network="eip155:8453",
        verifying_contract=REGISTRY_PLACEHOLDER,
    )
    mandate.status = AP2MandateStatus.PENDING_ON_CHAIN.value
    store.save_mandate(mandate)
    registry.set_trusted_issuer(agent.address, issuer.address, True)
    registry.issue_mandate(
        mandate_hash=mandate.mandate_hash,
        payload_hash=mandate.payload_hash,
        issuer=issuer.address,
        agent=agent.address,
        expires_at=mandate.expires_at,
        metadata_uri=mandate.metadata_uri,
    )
    store.record_chain_confirmation(mandate.mandate_hash, tx_hash=f"0xtx{nonce}", block_number=nonce)
    return mandate


def test_forged_signature_is_rejected():
    issuer = Account.create()
    agent = Account.create()
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=1_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=[RECIPIENT],
        expires_at=1_900_000_000,
        nonce=7,
        verifying_contract=REGISTRY_PLACEHOLDER,
    )

    bad_sig = mandate.issuer_signature[:-1] + ("0" if mandate.issuer_signature[-1] != "0" else "1")
    mandate.issuer_signature = bad_sig

    ok, reason = verify_ap2_mandate(mandate)
    assert not ok
    assert "failed" in reason.lower() or "signature" in reason.lower()


def test_untrusted_issuer_is_rejected_by_validator(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store, registry, issuer, agent)

    registry.set_trusted_issuer(agent.address, issuer.address, False)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "not trusted" in (err or "").lower()


def test_cross_chain_replay_attempt_is_rejected(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store, registry, issuer, agent)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:84532",  # wrong network
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "does not match" in (err or "").lower()


def test_expired_mandate_is_rejected(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = create_ap2_mandate(
        issuer_key=issuer.key.hex(),
        agent=agent.address,
        asset_id=USDC_BASE_MAINNET,
        max_amount_per_tx=1_000_000,
        max_amount_per_day=5_000_000,
        allowed_recipients=[RECIPIENT],
        expires_at=int(time.time()) - 5,
        nonce=8,
        network="eip155:8453",
        verifying_contract=REGISTRY_PLACEHOLDER,
    )
    mandate.status = AP2MandateStatus.ACTIVE.value
    store.save_mandate(mandate)
    registry.set_trusted_issuer(agent.address, issuer.address, True)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "does not match" in (err or "").lower() or "expired" in (err or "").lower()


def test_cache_poisoning_does_not_bypass_final_registry_check(tmp_path):
    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store, registry, issuer, agent)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert ok, err

    # Poison cache with stale/forged status, then revoke on registry.
    validator._status_cache[mandate.mandate_hash] = (  # noqa: SLF001 - intentional test
        registry.get_mandate_status(mandate.mandate_hash),
        time.time(),
    )
    registry.revoke_mandate(mandate.mandate_hash, issuer.address)

    ok, err, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok
    assert "not active" in (err or "").lower() or "revoked" in (err or "").lower()


def test_structured_decision_and_pause_logs(caplog, tmp_path):
    caplog.set_level(logging.INFO)

    store = MandateStore(tmp_path / "mandates")
    registry = LocalMandateRegistry(tmp_path / "registry.json")
    validator = MandateValidator(registry, store)

    issuer = Account.create()
    agent = Account.create()
    mandate = _issue_active_mandate(store, registry, issuer, agent)

    registry.set_agent_paused(agent.address, True)

    ok, _, _ = validator.validate_transaction(
        TransactionIntent(
            network="eip155:8453",
            asset_id=USDC_BASE_MAINNET,
            recipient=RECIPIENT,
            amount_base_units=500_000,
            mandate_hash=mandate.mandate_hash,
        ),
        agent.address,
    )
    assert not ok

    messages = "\n".join(record.getMessage() for record in caplog.records)
    assert "ap2_mandate_decision" in messages
    assert "reason_code=agent_paused" in messages
    assert "mandate_hash" in messages
    assert "ap2_registry_action action=set_agent_paused" in messages


def test_budget_store_failure_fails_closed(tmp_path):
    class BrokenBudget:
        def authorize_and_reserve(self, **kwargs):
            raise RuntimeError("sqlite unavailable")

    issuer = Account.create()
    delegate = Account.create()
    legacy_mandate = create_mandate(
        delegator_key=issuer.key.hex(),
        delegate_address=delegate.address,
        max_total_usd=10.0,
        max_per_tx_usd=1.0,
        duration_hours=24,
        network="eip155:8453",
    )

    executor = PaymentExecutor(
        budget=BrokenBudget(),  # type: ignore[arg-type]
        audit=AuditTrail(path=tmp_path / "audit.jsonl"),
        dry_run=True,
    )

    result = executor.execute(
        legacy_mandate,
        PaymentRequest(
            mandate_id=legacy_mandate.mandate_id,
            amount_usd=0.25,
            merchant="OpenAI",
            description="fail closed test",
            network="eip155:8453",
        ),
    )

    assert not result.success
    assert "budget store error" in (result.reason or "").lower()
