"""Shared utility helpers for file, byte, and safety operations."""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Iterator

DEFAULT_CHUNK_SIZE: int = 64 * 1024


def chunk_reader(file_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    """Yield file content in fixed-size chunks."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    with file_path.open("rb") as file_obj:
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            yield chunk


def random_bytes(length: int) -> bytes:
    """Return cryptographically strong random bytes."""
    if length < 0:
        raise ValueError("length must not be negative")
    return secrets.token_bytes(length)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR two byte strings of equal length."""
    if len(left) != len(right):
        raise ValueError("left and right must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def secure_compare(left: bytes, right: bytes) -> bool:
    """Compare two byte strings in constant time."""
    return hmac.compare_digest(left, right)


def atomic_rename(source: Path, destination: Path) -> None:
    """Atomically replace destination with source when possible."""
    os.replace(source, destination)


# TODO: Add secure file wipe helper if project scope requires it.