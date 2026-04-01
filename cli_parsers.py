"""CLI parsing helpers for AES key/IV hex inputs."""

from __future__ import annotations

import argparse
import string

from constants import IV_SIZE, VALID_AES_KEY_SIZES


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
    """Parse AES key from CLI hex string for 128/192/256-bit lengths."""
    normalized = value.strip()
    allowed_hex_lengths = {size * 2 for size in VALID_AES_KEY_SIZES}

    if len(normalized) not in allowed_hex_lengths:
        allowed_display = ", ".join(str(length) for length in sorted(allowed_hex_lengths))
        raise argparse.ArgumentTypeError(
            "AES key must be one of "
            f"{allowed_display} hex characters "
            "(16/24/32 bytes).",
        )

    if any(character not in string.hexdigits for character in normalized):
        raise argparse.ArgumentTypeError(
            "AES key has invalid characters. Use only 0-9, a-f, A-F.",
        )

    try:
        parsed = bytes.fromhex(normalized)
    except ValueError as error:
        raise argparse.ArgumentTypeError(
            "AES key is not valid hexadecimal input."
            " Remove spaces and non-hex symbols.",
        ) from error

    if len(parsed) not in VALID_AES_KEY_SIZES:
        raise argparse.ArgumentTypeError(
            "AES key must decode to 16, 24, or 32 bytes.",
        )

    return parsed


def parse_hex_iv(value: str) -> bytes:
    """Parse CBC IV from CLI hex string (32 hex chars -> 16 bytes)."""
    return _parse_fixed_hex(
        value=value,
        field_name="CBC IV",
        expected_bytes=IV_SIZE,
    )
