"""Luong xu ly ma hoa/giai ma du lieu o muc file."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from constants import BLOCK_SIZE, VALID_AES_KEY_SIZES
from modes import cbc_decrypt, cbc_encrypt

DEFAULT_CHUNK_SIZE: int = 64 * 1024


@dataclass(frozen=True)
class FileCryptoConfig:
    """Tuy chon khi chay cho ma hoa va giai ma file."""

    chunk_size: int = DEFAULT_CHUNK_SIZE
    overwrite: bool = False


def normalize_mode(mode: str) -> str:
    """Chuan hoa mode thanh in hoa va chi chap nhan CBC."""
    normalized = mode.strip().upper()
    if normalized != "CBC":
        raise ValueError(f"Unsupported cipher mode: {mode}. This project supports CBC only.")
    return normalized


def encrypt_file_to_bytes(
    input_path: str,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Doc file nhi phan va tra ve bytes da ma hoa AES-CBC."""
    if len(key) not in VALID_AES_KEY_SIZES:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

    plaintext = read_binary_file(input_path)
    return cbc_encrypt(data=plaintext, key=key, iv=iv)


def decrypt_bytes_to_file(
    ciphertext: bytes,
    output_path: str,
    key: bytes,
    iv: bytes,
) -> None:
    """Giai ma bytes AES-CBC va ghi plaintext ra file nhi phan."""
    if len(key) not in VALID_AES_KEY_SIZES:
        raise ValueError("AES key must be 16, 24, or 32 bytes")
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"IV must be {BLOCK_SIZE} bytes")

    plaintext = cbc_decrypt(ciphertext=ciphertext, key=key, iv=iv)
    write_binary_file(output_path, plaintext)


def read_binary_file(path: str) -> bytes:
    """Doc toan bo file duoi dang bytes thuan."""
    try:
        with open(path, "rb") as file_obj:
            return file_obj.read()
    except FileNotFoundError as error:
        raise FileNotFoundError(f"Input file not found: {path}") from error
    except OSError as error:
        raise OSError(f"Failed to read binary file '{path}': {error}") from error


def write_binary_file(path: str, data: bytes) -> None:
    """Ghi bytes thuan vao file."""
    try:
        with open(path, "wb") as file_obj:
            file_obj.write(data)
    except OSError as error:
        raise OSError(f"Failed to write binary file '{path}': {error}") from error


def encrypt_file(
    input_path: Path,
    output_path: Path,
    key: bytes,
    iv: bytes,
    config: FileCryptoConfig,
) -> None:
    """Ham ma hoa file-to-file de giu tuong thich nguoc."""
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    if output_path.exists() and not config.overwrite:
        raise FileExistsError(output_path)

    ciphertext = encrypt_file_to_bytes(str(input_path), key=key, iv=iv)
    write_binary_file(str(output_path), ciphertext)


def decrypt_file(
    input_path: Path,
    output_path: Path,
    key: bytes,
    iv: bytes,
    config: FileCryptoConfig,
) -> None:
    """Ham giai ma file-to-file de giu tuong thich nguoc."""
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    if output_path.exists() and not config.overwrite:
        raise FileExistsError(output_path)

    ciphertext = read_binary_file(str(input_path))
    decrypt_bytes_to_file(ciphertext, str(output_path), key=key, iv=iv)