"""
Real x402 payment client integration.

Wraps the official x402 Python SDK to execute actual USDC payments
on Base (mainnet) or Base Sepolia (testnet) through the Coinbase facilitator.

This is the bridge between Trustee's mandate/budget system and the
x402 payment protocol. The flow:

1. Agent has a mandate (authorization from delegator)
2. Budget check passes
3. This module executes the actual crypto payment via x402
4. Returns payment proof for audit trail
"""

from __future__ import annotations

import base64
import json
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

import httpx
from eth_account import Account
from eth_account.signers.local import LocalAccount

from x402 import x402ClientSync
from x402.mechanisms.evm.exact import ExactEvmScheme

logger = logging.getLogger(__name__)


class Network(str, Enum):
    """Supported x402 networks."""
    BASE_MAINNET = "eip155:8453"
    BASE_SEPOLIA = "eip155:84532"


# Default facilitator URLs
FACILITATORS = {
    Network.BASE_MAINNET: "https://x402.org/facilitator",
    Network.BASE_SEPOLIA: "https://x402.org/facilitator",
}


@dataclass
class X402Config:
    """Configuration for x402 payment client."""
    network: Network = Network.BASE_SEPOLIA
    facilitator_url: Optional[str] = None
    timeout_seconds: float = 30.0
    max_amount_usd: float = 10.0  # Safety cap per payment
    
    @property
    def effective_facilitator_url(self) -> str:
        return self.facilitator_url or FACILITATORS[self.network]


@dataclass
class X402PaymentResult:
    """Result from an x402 payment execution."""
    success: bool
    payment_id: Optional[str] = None
    tx_hash: Optional[str] = None
    network: Optional[str] = None
    amount_usdc: Optional[float] = None
    error: Optional[str] = None
    raw_response: Optional[dict] = field(default=None, repr=False)
    
    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "payment_id": self.payment_id,
            "tx_hash": self.tx_hash,
            "network": self.network,
            "amount_usdc": self.amount_usdc,
            "error": self.error,
        }


class X402PaymentClient:
    """
    Executes real x402 payments using the official SDK.
    
    Usage:
        # Create with agent's private key (from bagman session key)
        client = X402PaymentClient.from_private_key(
            private_key="0x...",
            config=X402Config(network=Network.BASE_SEPOLIA),
        )
        
        # Pay for a resource
        result = client.pay(url="https://api.example.com/data", method="GET")
        
        # Or pay with explicit amount (direct transfer)
        result = client.pay_amount(
            recipient="0x...",
            amount_usd=0.01,
            description="API access fee",
        )
    """
    
    def __init__(self, account: LocalAccount, config: X402Config):
        self.account = account
        self.config = config
        self._client = x402ClientSync()
        self._client.register(
            config.network.value,
            ExactEvmScheme(signer=account),
        )
        self._http = httpx.Client(timeout=config.timeout_seconds)
    
    @classmethod
    def from_private_key(
        cls, private_key: str, config: Optional[X402Config] = None,
    ) -> "X402PaymentClient":
        """Create client from a private key (hex string with or without 0x prefix)."""
        account = Account.from_key(private_key)
        return cls(account=account, config=config or X402Config())
    
    @property
    def address(self) -> str:
        """Agent's wallet address."""
        return self.account.address
    
    def pay(self, url: str, method: str = "GET", **kwargs) -> X402PaymentResult:
        """
        Pay for access to an x402-protected resource.
        
        Makes the initial request, gets 402 Payment Required response,
        creates payment payload via x402 SDK, retries with payment header.
        
        Args:
            url: The x402-protected resource URL
            method: HTTP method (GET, POST, etc.)
            **kwargs: Additional arguments passed to httpx request
            
        Returns:
            X402PaymentResult with payment proof
        """
        try:
            # Step 1: Hit the resource, expect 402
            response = self._http.request(method, url, **kwargs)
            
            if response.status_code != 402:
                if response.status_code == 200:
                    return X402PaymentResult(
                        success=True,
                        payment_id="free-access",
                        network=self.config.network.value,
                        error=None,
                    )
                return X402PaymentResult(
                    success=False,
                    error=f"Unexpected status {response.status_code}: {response.text[:200]}",
                )
            
            # Step 2: Parse payment requirements from 402 response
            payment_required_header = (
                response.headers.get("PAYMENT-REQUIRED")  # v2
                or response.headers.get("X-PAYMENT")  # v1 legacy
            )
            
            if not payment_required_header:
                return X402PaymentResult(
                    success=False,
                    error="402 response missing payment requirements header",
                )
            
            requirements = json.loads(base64.b64decode(payment_required_header))
            
            # Step 3: Safety check - don't pay more than configured max
            if isinstance(requirements, list):
                req = requirements[0]
            else:
                req = requirements
                
            price_str = req.get("price", "0")
            price_usd = float(price_str.replace("$", ""))
            
            if price_usd > self.config.max_amount_usd:
                return X402PaymentResult(
                    success=False,
                    error=f"Price ${price_usd} exceeds safety cap ${self.config.max_amount_usd}",
                    amount_usdc=price_usd,
                )
            
            # Step 4: Create payment payload via x402 SDK
            payload = self._client.create_payment_payload(req)
            
            # Step 5: Retry with payment header
            encoded_payload = base64.b64encode(
                json.dumps(payload).encode() if isinstance(payload, dict) 
                else payload.encode() if isinstance(payload, str)
                else payload
            ).decode()
            
            headers = {**kwargs.pop("headers", {}), "PAYMENT-SIGNATURE": encoded_payload}
            paid_response = self._http.request(method, url, headers=headers, **kwargs)
            
            if paid_response.status_code == 200:
                # Extract payment response/proof
                payment_response_header = (
                    paid_response.headers.get("PAYMENT-RESPONSE")
                    or paid_response.headers.get("X-PAYMENT-RESPONSE")
                )
                
                proof = {}
                if payment_response_header:
                    proof = json.loads(base64.b64decode(payment_response_header))
                
                return X402PaymentResult(
                    success=True,
                    payment_id=proof.get("payment_id", encoded_payload[:16]),
                    tx_hash=proof.get("tx_hash"),
                    network=self.config.network.value,
                    amount_usdc=price_usd,
                    raw_response=proof,
                )
            else:
                return X402PaymentResult(
                    success=False,
                    error=f"Payment rejected: {paid_response.status_code} {paid_response.text[:200]}",
                    amount_usdc=price_usd,
                )
                
        except Exception as e:
            logger.exception("x402 payment failed")
            return X402PaymentResult(
                success=False,
                error=f"Payment execution error: {type(e).__name__}: {str(e)}",
            )
    
    def close(self):
        """Clean up HTTP client."""
        self._http.close()
    
    def __enter__(self):
        return self
    
    def __exit__(self, *args):
        self.close()
