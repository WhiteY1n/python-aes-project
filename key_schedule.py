"""AES key schedule helpers for 128/192/256-bit keys."""

from __future__ import annotations

from constants import NB, RCON, S_BOX, VALID_AES_KEY_SIZES

Word = bytes


def validate_key_size(key: bytes) -> None:
    """Validate that key size matches AES-128/192/256 requirements."""
    if len(key) not in VALID_AES_KEY_SIZES:
        allowed_sizes = ", ".join(str(size) for size in VALID_AES_KEY_SIZES)
        raise ValueError(
            f"AES key must be one of [{allowed_sizes}] bytes, got {len(key)}",
        )


def _nr_from_nk(nk: int) -> int:
    """Map Nk words to AES number of rounds."""
    mapping = {4: 10, 6: 12, 8: 14}
    try:
        return mapping[nk]
    except KeyError as error:  # pragma: no cover - guarded by validate_key_size
        raise ValueError(f"unsupported Nk value: {nk}") from error


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
    """Expand AES key into round keys of 16 bytes.

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

    nk = len(effective_key) // 4
    nr = _nr_from_nk(nk)

    # Start from original key words.
    words: list[Word] = [
        effective_key[index : index + 4]
        for index in range(0, len(effective_key), 4)
    ]

    total_words = NB * (nr + 1)
    for index in range(nk, total_words):
        temp = words[index - 1]

        # Every Nk words, apply schedule core: RotWord, SubWord, and Rcon.
        if index % nk == 0:
            rcon_word = bytes((RCON[index // nk], 0x00, 0x00, 0x00))
            temp = _xor_words(sub_word(rot_word(temp)), rcon_word)
        elif nk > 6 and index % nk == 4:
            # AES-256 applies an extra SubWord halfway through each Nk group.
            temp = sub_word(temp)

        words.append(_xor_words(words[index - nk], temp))

    round_keys: list[bytes] = []
    for round_index in range(nr + 1):
        start = round_index * NB
        round_key = b"".join(words[start : start + NB])
        round_keys.append(round_key)

    return round_keys


def expand_key(key: bytes) -> list[bytes]:
    """Backward-compatible alias for key_expansion."""
    return key_expansion(key)