"""Ham ho tro them/bo dem PKCS#7 cho block cipher."""

from __future__ import annotations

def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """Them dem PKCS#7 vao du lieu dau vao."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")

    pad_length = block_size - (len(data) % block_size)
    if pad_length == 0:
        pad_length = block_size
    return data + bytes([pad_length]) * pad_length


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """Loai bo dem PKCS#7 khoi du lieu dau vao."""
    if block_size <= 0 or block_size > 255:
        raise ValueError("block_size must be in range 1..255")
    if not data:
        raise ValueError("data must not be empty")
    if len(data) % block_size != 0:
        raise ValueError("padded data length must be multiple of block_size")

    pad_length = data[-1]
    if pad_length < 1 or pad_length > block_size:
        raise ValueError("invalid PKCS#7 pad length")

    if data[-pad_length:] != bytes([pad_length]) * pad_length:
        raise ValueError("invalid PKCS#7 padding bytes")

    return data[:-pad_length]