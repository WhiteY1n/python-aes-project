"""Cac ham tien ich dung chung cho file, bytes va an toan so sanh."""

from __future__ import annotations

import hmac
import os
import secrets
from pathlib import Path
from typing import Iterator

DEFAULT_CHUNK_SIZE: int = 64 * 1024


def chunk_reader(file_path: Path, chunk_size: int = DEFAULT_CHUNK_SIZE) -> Iterator[bytes]:
    """Tra ve noi dung file theo tung khoi co kich thuoc co dinh."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    with file_path.open("rb") as file_obj:
        while True:
            chunk = file_obj.read(chunk_size)
            if not chunk:
                break
            yield chunk


def random_bytes(length: int) -> bytes:
    """Tra ve bytes ngau nhien co do manh phu hop cho mat ma."""
    if length < 0:
        raise ValueError("length must not be negative")
    return secrets.token_bytes(length)


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR hai chuoi bytes co do dai bang nhau."""
    if len(left) != len(right):
        raise ValueError("left and right must have the same length")
    return bytes(a ^ b for a, b in zip(left, right))


def secure_compare(left: bytes, right: bytes) -> bool:
    """So sanh hai chuoi bytes theo thoi gian hang so."""
    return hmac.compare_digest(left, right)


def atomic_rename(source: Path, destination: Path) -> None:
    """Doi ten/thay the file theo cach nguyen tu neu he dieu hanh ho tro."""
    os.replace(source, destination)


# TODO: Bo sung ham xoa file an toan neu scope du an can.