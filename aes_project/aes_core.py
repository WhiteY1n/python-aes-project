"""Core AES block encryption/decryption skeleton."""

from __future__ import annotations

from typing import TypeAlias

from constants import BLOCK_SIZE_BYTES
from key_schedule import RoundKeys, key_expansion

State: TypeAlias = list[list[int]]


def bytes_to_state(block: bytes) -> State:
    """Convert a 16-byte block into an AES state matrix."""
    if len(block) != BLOCK_SIZE_BYTES:
        raise ValueError(f"AES block must be {BLOCK_SIZE_BYTES} bytes")
    # TODO: Implement column-major block-to-state mapping.
    raise NotImplementedError("bytes_to_state is not implemented yet")


def state_to_bytes(state: State) -> bytes:
    """Convert an AES state matrix back to 16 bytes."""
    # TODO: Implement state-to-block conversion.
    raise NotImplementedError("state_to_bytes is not implemented yet")


def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Encrypt one 16-byte block and return ciphertext bytes."""
    if len(block) != BLOCK_SIZE_BYTES:
        raise ValueError(f"AES block must be {BLOCK_SIZE_BYTES} bytes")

    _round_keys: RoundKeys = key_expansion(key)
    # TODO: Implement SubBytes, ShiftRows, MixColumns, AddRoundKey flow.
    raise NotImplementedError("encrypt_block is not implemented yet")


def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Decrypt one 16-byte block and return plaintext bytes."""
    if len(block) != BLOCK_SIZE_BYTES:
        raise ValueError(f"AES block must be {BLOCK_SIZE_BYTES} bytes")

    _round_keys: RoundKeys = key_expansion(key)
    # TODO: Implement inverse AES round transformations.
    raise NotImplementedError("decrypt_block is not implemented yet")