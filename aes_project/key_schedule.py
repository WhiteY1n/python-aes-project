"""AES key expansion (key schedule) skeleton."""

from __future__ import annotations

from dataclasses import dataclass

from constants import AES128_KEY_SIZE_BYTES


@dataclass(frozen=True)
class RoundKeys:
    """Container for expanded AES round keys."""

    words: list[int]
    rounds: int


def validate_key_size(key: bytes) -> None:
    """Validate that key size matches the AES-128 public API requirement."""
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise ValueError(
            f"AES-128 key must be {AES128_KEY_SIZE_BYTES} bytes, got {len(key)}",
        )


def key_expansion(key: bytes) -> RoundKeys:
    """Expand a 16-byte AES-128 key into round keys."""
    validate_key_size(key)
    # TODO: Implement AES-128 key schedule.
    raise NotImplementedError("AES key schedule is not implemented yet")


def expand_key(master_key: bytes) -> RoundKeys:
    """Backward-compatible alias for key_expansion."""
    return key_expansion(master_key)