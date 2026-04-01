"""Core AES block encryption/decryption skeleton."""

from __future__ import annotations

from typing import TypeAlias

from constants import BLOCK_SIZE, INV_S_BOX, S_BOX
from key_schedule import key_expansion

State: TypeAlias = list[list[int]]


def _validate_state_shape(state: State) -> None:
    """Validate that state is a 4x4 matrix of byte values."""
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("state must be a 4x4 matrix")

    for row in state:
        for value in row:
            if not 0 <= value <= 0xFF:
                raise ValueError("state values must be in range 0..255")


def bytes_to_state(block: bytes) -> State:
    """Convert a 16-byte block into an AES state matrix."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")

    # AES state uses column-major ordering: state[row][col] = block[col * 4 + row].
    state: State = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col * 4 + row]
    return state


def state_to_bytes(state: State) -> bytes:
    """Convert an AES state matrix back to 16 bytes."""
    _validate_state_shape(state)

    output = bytearray(BLOCK_SIZE)
    for col in range(4):
        for row in range(4):
            output[col * 4 + row] = state[row][col]
    return bytes(output)


def xtime(a: int) -> int:
    """Multiply a byte by x in GF(2^8) with AES reduction polynomial."""
    if not 0 <= a <= 0xFF:
        raise ValueError("a must be in range 0..255")

    shifted = (a << 1) & 0xFF
    if a & 0x80:
        shifted ^= 0x1B
    return shifted


def gmul(a: int, b: int) -> int:
    """Multiply two bytes in GF(2^8)."""
    if not 0 <= a <= 0xFF or not 0 <= b <= 0xFF:
        raise ValueError("a and b must be in range 0..255")

    result = 0
    multiplicand = a
    multiplier = b

    # Russian peasant multiplication over GF(2^8).
    for _ in range(8):
        if multiplier & 1:
            result ^= multiplicand
        multiplicand = xtime(multiplicand)
        multiplier >>= 1

    return result


def add_round_key(state: State, round_key: bytes) -> None:
    """XOR current state with a 16-byte round key in-place."""
    _validate_state_shape(state)
    if len(round_key) != BLOCK_SIZE:
        raise ValueError(f"round key must be {BLOCK_SIZE} bytes")

    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[col * 4 + row]


def sub_bytes(state: State) -> None:
    """Apply S-Box substitution to each state byte in-place."""
    _validate_state_shape(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]


def inv_sub_bytes(state: State) -> None:
    """Apply inverse S-Box substitution to each state byte in-place."""
    _validate_state_shape(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = INV_S_BOX[state[row][col]]


def shift_rows(state: State) -> None:
    """Rotate state rows left by row index in-place."""
    _validate_state_shape(state)

    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def inv_shift_rows(state: State) -> None:
    """Rotate state rows right by row index in-place."""
    _validate_state_shape(state)

    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def mix_columns(state: State) -> None:
    """Apply MixColumns transformation to each state column in-place."""
    _validate_state_shape(state)

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = gmul(s0, 0x02) ^ gmul(s1, 0x03) ^ s2 ^ s3
        state[1][col] = s0 ^ gmul(s1, 0x02) ^ gmul(s2, 0x03) ^ s3
        state[2][col] = s0 ^ s1 ^ gmul(s2, 0x02) ^ gmul(s3, 0x03)
        state[3][col] = gmul(s0, 0x03) ^ s1 ^ s2 ^ gmul(s3, 0x02)


def inv_mix_columns(state: State) -> None:
    """Apply inverse MixColumns transformation to each state column in-place."""
    _validate_state_shape(state)

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        state[0][col] = gmul(s0, 0x0E) ^ gmul(s1, 0x0B) ^ gmul(s2, 0x0D) ^ gmul(s3, 0x09)
        state[1][col] = gmul(s0, 0x09) ^ gmul(s1, 0x0E) ^ gmul(s2, 0x0B) ^ gmul(s3, 0x0D)
        state[2][col] = gmul(s0, 0x0D) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0E) ^ gmul(s3, 0x0B)
        state[3][col] = gmul(s0, 0x0B) ^ gmul(s1, 0x0D) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0E)


def encrypt_block(
    block: bytes,
    key: bytes | None = None,
    *,
    master_key: bytes | None = None,
) -> bytes:
    """Encrypt one 16-byte block and return ciphertext bytes.

    Accepts either `key` (preferred) or `master_key` (legacy keyword).
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")
    if key is None and master_key is None:
        raise ValueError("key is required")
    if key is not None and master_key is not None:
        raise ValueError("provide only one of key or master_key")

    effective_key = key if key is not None else master_key
    if effective_key is None:  # pragma: no cover - defensive guard
        raise ValueError("key is required")

    round_keys = key_expansion(effective_key)
    state = bytes_to_state(block)

    nr = len(round_keys) - 1
    if nr not in (10, 12, 14):
        raise ValueError("expanded key produced unsupported round count")

    # Initial whitening step before the AES rounds.
    add_round_key(state, round_keys[0])

    # Rounds 1..Nr-1 include MixColumns.
    for round_index in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    # Final round omits MixColumns.
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[nr])

    return state_to_bytes(state)


def decrypt_block(
    block: bytes,
    key: bytes | None = None,
    *,
    master_key: bytes | None = None,
) -> bytes:
    """Decrypt one 16-byte block and return plaintext bytes.

    Accepts either `key` (preferred) or `master_key` (legacy keyword).
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")
    if key is None and master_key is None:
        raise ValueError("key is required")
    if key is not None and master_key is not None:
        raise ValueError("provide only one of key or master_key")

    effective_key = key if key is not None else master_key
    if effective_key is None:  # pragma: no cover - defensive guard
        raise ValueError("key is required")

    round_keys = key_expansion(effective_key)
    state = bytes_to_state(block)

    nr = len(round_keys) - 1
    if nr not in (10, 12, 14):
        raise ValueError("expanded key produced unsupported round count")

    # Start from the last round key and invert operations in reverse order.
    add_round_key(state, round_keys[nr])

    for round_index in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    # Final inverse round omits InvMixColumns.
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)