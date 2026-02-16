"""AP2 mandate validation at the signing boundary."""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from typing import Optional

from .mandate import (
    AP2Mandate,
    AP2MandateStatus,
    validate_caip19_asset_id,
    normalize_address,
    normalize_caip2_network,
    verify_ap2_mandate,
)
from .mandate_registry import MandateRegistryClient, MandateRegistryStatus
from .mandate_store import MandateStore

logger = logging.getLogger(__name__)


@dataclass
class TransactionIntent:
    network: str
    asset_id: str
    recipient: str
    amount_base_units: int
    mandate_hash: Optional[str] = None


class MandateValidator:
    """Validates AP2 mandates against local constraints and registry truth."""

    def __init__(self, registry: MandateRegistryClient, store: MandateStore, cache_ttl: int = 300):
        self.registry = registry
        self.store = store
        self.cache_ttl = cache_ttl
        self._status_cache: dict[str, tuple[MandateRegistryStatus, float]] = {}

    def validate_transaction(
        self,
        intent: TransactionIntent,
        agent_address: str,
    ) -> tuple[bool, Optional[str], Optional[AP2Mandate]]:
        """Validate transaction against active mandates and final chain state."""
        selected: Optional[AP2Mandate] = None
        try:
            normalized_agent = normalize_address(agent_address)
            normalized_network = normalize_caip2_network(intent.network)
            normalized_asset = validate_caip19_asset_id(intent.asset_id)
            normalized_recipient = normalize_address(intent.recipient)
            if intent.amount_base_units <= 0:
                self._log_decision(
                    outcome="deny",
                    reason_code="invalid_amount",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=intent.mandate_hash or "",
                )
                return False, "Amount must be positive base units", None

            if self.registry.is_agent_paused(normalized_agent):
                self._log_decision(
                    outcome="deny",
                    reason_code="agent_paused",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=intent.mandate_hash or "",
                )
                return False, "Agent is paused", None

            candidates = self._candidate_mandates(normalized_agent, intent.mandate_hash)
            matches = [
                mandate
                for mandate in candidates
                if self._matches_local_constraints(
                    mandate,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                )
            ]

            if not matches:
                self._log_decision(
                    outcome="deny",
                    reason_code="no_matching_mandate",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=intent.mandate_hash or "",
                )
                return False, "Transaction does not match any active mandate", None

            if intent.mandate_hash is None and len(matches) > 1:
                self._log_decision(
                    outcome="deny",
                    reason_code="ambiguous_match",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash="",
                )
                return False, "Multiple active mandates match; mandate_hash is required", None

            selected = matches[0]
            valid, reason = verify_ap2_mandate(selected)
            if not valid:
                self._log_decision(
                    outcome="deny",
                    reason_code="invalid_signature_or_payload",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=selected.mandate_hash,
                    issuer=selected.issuer,
                )
                return False, f"Mandate verification failed: {reason}", None

            if not self.registry.is_trusted_issuer(normalized_agent, selected.issuer):
                self._log_decision(
                    outcome="deny",
                    reason_code="untrusted_issuer",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=selected.mandate_hash,
                    issuer=selected.issuer,
                )
                return False, "Issuer is not trusted for this agent", None

            on_chain_ok, chain_reason = self._verify_on_chain(selected, normalized_agent)
            if not on_chain_ok:
                self._log_decision(
                    outcome="deny",
                    reason_code="registry_status_check_failed",
                    agent=normalized_agent,
                    network=normalized_network,
                    asset_id=normalized_asset,
                    recipient=normalized_recipient,
                    amount_base_units=intent.amount_base_units,
                    mandate_hash=selected.mandate_hash,
                    issuer=selected.issuer,
                )
                return False, chain_reason, None

            self._log_decision(
                outcome="allow",
                reason_code="ok",
                agent=normalized_agent,
                network=normalized_network,
                asset_id=normalized_asset,
                recipient=normalized_recipient,
                amount_base_units=intent.amount_base_units,
                mandate_hash=selected.mandate_hash,
                issuer=selected.issuer,
            )
            return True, None, selected
        except Exception as exc:
            self._log_decision(
                outcome="deny",
                reason_code="validation_exception",
                agent=agent_address,
                network=intent.network,
                asset_id=intent.asset_id,
                recipient=intent.recipient,
                amount_base_units=intent.amount_base_units,
                mandate_hash=(selected.mandate_hash if selected else (intent.mandate_hash or "")),
                error=str(exc),
            )
            return False, f"Validation error: {exc}", None

    def _candidate_mandates(self, agent_address: str, mandate_hash: Optional[str]) -> list[AP2Mandate]:
        if mandate_hash is not None:
            mandate = self.store.get_mandate(mandate_hash)
            if mandate is None:
                return []
            return [mandate] if mandate.agent == agent_address else []

        return self.store.list_mandates(agent_address, include_inactive=False)

    def _matches_local_constraints(
        self,
        mandate: AP2Mandate,
        *,
        network: str,
        asset_id: str,
        recipient: str,
        amount_base_units: int,
    ) -> bool:
        if mandate.status != AP2MandateStatus.ACTIVE.value:
            return False
        if mandate.is_expired:
            return False
        if mandate.network != network:
            return False
        if mandate.asset_id != asset_id:
            return False
        if amount_base_units > mandate.max_amount_per_tx:
            return False
        if mandate.allowed_recipients and recipient not in mandate.allowed_recipients:
            return False
        return True

    def _verify_on_chain(self, mandate: AP2Mandate, agent_address: str) -> tuple[bool, str]:
        # Cache can be used for discovery/debugging, but signing boundary check is live.
        status = self.registry.get_mandate_status(mandate.mandate_hash)
        self._status_cache[mandate.mandate_hash] = (status, time.time())

        if self.registry.is_agent_paused(agent_address):
            return False, "Agent is paused"

        if not status.exists:
            return False, "Mandate not found on registry"
        if not status.active:
            return False, "Mandate is not active on registry"
        if status.revoked:
            return False, "Mandate revoked on registry"
        if normalize_address(status.agent) != mandate.agent:
            return False, "Registry agent mismatch"
        if normalize_address(status.issuer) != mandate.issuer:
            return False, "Registry issuer mismatch"
        if status.payload_hash != mandate.payload_hash:
            return False, "Registry payload hash mismatch"
        if status.expires_at != mandate.expires_at:
            return False, "Registry expiresAt mismatch"

        return True, "OK"

    def _log_decision(
        self,
        *,
        outcome: str,
        reason_code: str,
        agent: str,
        network: str,
        asset_id: str,
        recipient: str,
        amount_base_units: int,
        mandate_hash: str,
        issuer: str = "",
        error: str = "",
    ) -> None:
        logger.info(
            "ap2_mandate_decision outcome=%s reason_code=%s agent=%s network=%s asset_id=%s recipient=%s amount_base_units=%s mandate_hash=%s issuer=%s error=%s",
            outcome,
            reason_code,
            agent,
            network,
            asset_id,
            recipient,
            amount_base_units,
            mandate_hash,
            issuer,
            error,
        )
