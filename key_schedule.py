"""AES-128 key schedule helpers."""

from __future__ import annotations

from constants import AES128_KEY_SIZE, NB, NK, NR, RCON, S_BOX

Word = bytes


def validate_key_size(key: bytes) -> None:
    """Validate that key size matches the AES-128 public API requirement."""
    if len(key) != AES128_KEY_SIZE:
        raise ValueError(
            f"AES-128 key must be {AES128_KEY_SIZE} bytes, got {len(key)}",
        )


def rot_word(word: bytes) -> bytes:
    """Rotate a 4-byte word left by one byte."""
    if len(word) != 4:
        raise ValueError("word must be exactly 4 bytes")
    return word[1:] + word[:1]


def sub_word(word: bytes) -> bytes:
    """Apply AES S-Box substitution to each byte in a 4-byte word."""
    if len(word) != 4:
        raise ValueError("word must be exactly 4 bytes")
    return bytes(S_BOX[value] for value in word)


def _xor_words(left: Word, right: Word) -> Word:
    """XOR two 4-byte words."""
    return bytes(a ^ b for a, b in zip(left, right))


def key_expansion(
    key: bytes | None = None,
    *,
    master_key: bytes | None = None,
) -> list[bytes]:
    """Expand a 16-byte AES-128 key into 11 round keys of 16 bytes.

    Accepts either `key` (preferred) or `master_key` (legacy keyword).
    """
    if key is None and master_key is None:
        raise ValueError("key is required")
    if key is not None and master_key is not None:
        raise ValueError("provide only one of key or master_key")

    effective_key = key if key is not None else master_key
    if effective_key is None:  # pragma: no cover - defensive guard
        raise ValueError("key is required")

    validate_key_size(effective_key)

    # Start from the original 4 key words (AES-128 uses NK=4).
    words: list[Word] = [
        effective_key[index : index + 4]
        for index in range(0, AES128_KEY_SIZE, 4)
    ]

    total_words = NB * (NR + 1)
    for index in range(NK, total_words):
        temp = words[index - 1]

        # Every NK words, apply the schedule core: RotWord, SubWord, and Rcon.
        if index % NK == 0:
            rcon_word = bytes((RCON[index // NK], 0x00, 0x00, 0x00))
            temp = _xor_words(sub_word(rot_word(temp)), rcon_word)

        words.append(_xor_words(words[index - NK], temp))

    round_keys: list[bytes] = []
    for round_index in range(NR + 1):
        start = round_index * NB
        round_key = b"".join(words[start : start + NB])
        round_keys.append(round_key)

    return round_keys


def expand_key(key: bytes) -> list[bytes]:
    """Backward-compatible alias for key_expansion."""
    return key_expansion(key)