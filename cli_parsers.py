"""CLI parsing helpers for AES key/IV hex inputs."""

from __future__ import annotations

import argparse
import string

from constants import AES128_KEY_SIZE, IV_SIZE


def _parse_fixed_hex(
    value: str,
    *,
    field_name: str,
    expected_bytes: int,
) -> bytes:
    """Parse and validate a fixed-size hex string into bytes."""
    normalized = value.strip()
    expected_hex_chars = expected_bytes * 2

    if len(normalized) != expected_hex_chars:
        raise argparse.ArgumentTypeError(
            f"{field_name} must be exactly {expected_hex_chars} hex characters "
            f"({expected_bytes} bytes). Example: 00112233445566778899aabbccddeeff",
        )

    if any(character not in string.hexdigits for character in normalized):
        raise argparse.ArgumentTypeError(
            f"{field_name} has invalid characters. Use only 0-9, a-f, A-F.",
        )

    try:
        parsed = bytes.fromhex(normalized)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            f"{field_name} is not valid hexadecimal input."
            f" Remove spaces and non-hex symbols.",
        ) from error

    if len(parsed) != expected_bytes:
        raise argparse.ArgumentTypeError(
            f"{field_name} must decode to exactly {expected_bytes} bytes.",
        )

    return parsed


def parse_hex_key(value: str) -> bytes:
    """Parse AES-128 key from CLI hex string (32 hex chars -> 16 bytes)."""
    return _parse_fixed_hex(
        value=value,
        field_name="AES-128 key",
        expected_bytes=AES128_KEY_SIZE,
    )


def parse_hex_iv(value: str) -> bytes:
    """Parse CBC IV from CLI hex string (32 hex chars -> 16 bytes)."""
    return _parse_fixed_hex(
        value=value,
        field_name="CBC IV",
        expected_bytes=IV_SIZE,
    )
