"""AES block cipher mode skeletons (CBC only)."""

from __future__ import annotations

from aes_core import decrypt_block as aes_decrypt_block
from aes_core import encrypt_block as aes_encrypt_block
from constants import BLOCK_SIZE
from padding import pkcs7_pad, pkcs7_unpad


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR two byte strings of the same length."""
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    return bytes(left ^ right for left, right in zip(a, b))


def cbc_encrypt(
    data: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Encrypt bytes with AES-CBC using PKCS#7 padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"CBC IV must be {BLOCK_SIZE} bytes")

    padded = pkcs7_pad(data, block_size=BLOCK_SIZE)
    previous = iv
    output = bytearray()

    for offset in range(0, len(padded), BLOCK_SIZE):
        block = padded[offset : offset + BLOCK_SIZE]
        xored = xor_bytes(block, previous)
        encrypted = aes_encrypt_block(xored, key)
        output.extend(encrypted)
        previous = encrypted

    return bytes(output)


def cbc_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Decrypt AES-CBC bytes and remove PKCS#7 padding."""
    if len(iv) != BLOCK_SIZE:
        raise ValueError(f"CBC IV must be {BLOCK_SIZE} bytes")
    if not ciphertext:
        raise ValueError("ciphertext must not be empty")
    if len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("ciphertext length must be a multiple of block size")

    previous = iv
    padded_plaintext = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[offset : offset + BLOCK_SIZE]
        decrypted = aes_decrypt_block(block, key)
        padded_plaintext.extend(xor_bytes(decrypted, previous))
        previous = block

    return pkcs7_unpad(bytes(padded_plaintext), block_size=BLOCK_SIZE)


def encrypt_cbc(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Backward-compatible alias for cbc_encrypt."""
    return cbc_encrypt(
        data=plaintext,
        key=key,
        iv=iv,
    )


def decrypt_cbc(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
) -> bytes:
    """Backward-compatible alias for cbc_decrypt."""
    return cbc_decrypt(
        ciphertext=ciphertext,
        key=key,
        iv=iv,
    )