"""Padding helpers for block cipher modes."""

from __future__ import annotations

from constants import BLOCK_SIZE_BYTES


def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """Apply PKCS#7 padding to input bytes."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")

    pad_length = block_size - (len(data) % block_size)
    if pad_length == 0:
        pad_length = block_size
    return data + bytes([pad_length]) * pad_length


def pkcs7_unpad(padded: bytes, block_size: int = BLOCK_SIZE_BYTES) -> bytes:
    """Remove PKCS#7 padding from input bytes."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")
    if not padded:
        raise ValueError("padded data must not be empty")
    if len(padded) % block_size != 0:
        raise ValueError("padded data length must be multiple of block_size")

    pad_length = padded[-1]
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("invalid PKCS#7 pad length")

    if padded[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("invalid PKCS#7 padding bytes")

    return padded[:-pad_length]


# TODO: Add stream-friendly padding wrappers for chunked processing.