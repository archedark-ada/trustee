"""Money conversion helpers using fixed micro-dollar precision."""

from __future__ import annotations

from decimal import Decimal, ROUND_HALF_UP


MICROS_PER_USD = 1_000_000
_USD_QUANT = Decimal("0.000001")


def usd_to_micros(value: Decimal | float | int | str) -> int:
    """Convert USD value to integer micro-dollars."""
    dec = Decimal(str(value)).quantize(_USD_QUANT, rounding=ROUND_HALF_UP)
    return int(dec * MICROS_PER_USD)


def micros_to_usd_decimal(value: int) -> Decimal:
    """Convert integer micro-dollars to Decimal USD."""
    return (Decimal(value) / Decimal(MICROS_PER_USD)).quantize(
        _USD_QUANT, rounding=ROUND_HALF_UP
    )


def micros_to_usd_float(value: int) -> float:
    """Convert integer micro-dollars to float USD (for display APIs)."""
    return float(micros_to_usd_decimal(value))


def format_usd_from_micros(value: int) -> str:
    """Format integer micro-dollars as a currency string."""
    return f"${micros_to_usd_decimal(value):.2f}"
