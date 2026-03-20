"""File-level encryption/decryption workflow skeleton."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from constants import AES128_KEY_SIZE_BYTES, BLOCK_SIZE_BYTES, DEFAULT_CHUNK_SIZE, DEFAULT_MODE


@dataclass(frozen=True)
class FileCryptoConfig:
    """Runtime options for file encryption and decryption."""

    mode: str = DEFAULT_MODE
    chunk_size: int = DEFAULT_CHUNK_SIZE
    overwrite: bool = False


def normalize_mode(mode: str) -> str:
    """Normalize mode value to uppercase and validate supported options."""
    normalized = mode.strip().upper()
    if normalized not in {"CBC", "CTR"}:
        raise ValueError(f"Unsupported cipher mode: {mode}")
    return normalized


def encrypt_file_to_bytes(
    input_path: Path,
    key: bytes,
    iv: bytes,
    mode: str = DEFAULT_MODE,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> bytes:
    """Read a file and return encrypted bytes for transport/storage."""
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise ValueError(f"AES-128 key must be {AES128_KEY_SIZE_BYTES} bytes")
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(f"IV must be {BLOCK_SIZE_BYTES} bytes")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    normalized_mode = normalize_mode(mode)
    _ = normalized_mode
    # TODO: Read file as bytes and encrypt with selected mode.
    raise NotImplementedError("encrypt_file_to_bytes is not implemented yet")


def decrypt_bytes_to_file(
    ciphertext: bytes,
    output_path: Path,
    key: bytes,
    iv: bytes,
    mode: str = DEFAULT_MODE,
    overwrite: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> None:
    """Decrypt ciphertext bytes and write plaintext bytes to a file."""
    if output_path.exists() and not overwrite:
        raise FileExistsError(output_path)
    if len(key) != AES128_KEY_SIZE_BYTES:
        raise ValueError(f"AES-128 key must be {AES128_KEY_SIZE_BYTES} bytes")
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(f"IV must be {BLOCK_SIZE_BYTES} bytes")
    if chunk_size <= 0:
        raise ValueError("chunk_size must be greater than 0")

    normalized_mode = normalize_mode(mode)
    _ = (ciphertext, normalized_mode)
    # TODO: Decrypt bytes and write plaintext bytes to output_path.
    raise NotImplementedError("decrypt_bytes_to_file is not implemented yet")


def encrypt_file(
    input_path: Path,
    output_path: Path,
    master_key: bytes,
    iv_or_nonce: bytes,
    config: FileCryptoConfig,
) -> None:
    """Backward-compatible file-to-file encryption skeleton."""
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    if output_path.exists() and not config.overwrite:
        raise FileExistsError(output_path)

    _ = (master_key, iv_or_nonce, config)
    # TODO: Bridge to encrypt_file_to_bytes and persist ciphertext to output_path.
    raise NotImplementedError("encrypt_file is not implemented yet")


def decrypt_file(
    input_path: Path,
    output_path: Path,
    master_key: bytes,
    iv_or_nonce: bytes,
    config: FileCryptoConfig,
) -> None:
    """Backward-compatible file-to-file decryption skeleton."""
    if not input_path.exists():
        raise FileNotFoundError(input_path)
    if output_path.exists() and not config.overwrite:
        raise FileExistsError(output_path)

    _ = (master_key, iv_or_nonce, config)
    # TODO: Bridge to decrypt_bytes_to_file after reading ciphertext bytes.
    raise NotImplementedError("decrypt_file is not implemented yet")