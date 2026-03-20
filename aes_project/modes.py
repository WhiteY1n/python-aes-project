"""AES block cipher mode skeletons (CBC and CTR)."""

from __future__ import annotations

from typing import Callable

from aes_core import decrypt_block as aes_decrypt_block
from aes_core import encrypt_block as aes_encrypt_block
from constants import BLOCK_SIZE_BYTES

BlockEncryptor = Callable[[bytes, bytes], bytes]
BlockDecryptor = Callable[[bytes, bytes], bytes]


def cbc_encrypt(
    plaintext: bytes,
    key: bytes,
    iv: bytes,
    block_encryptor: BlockEncryptor = aes_encrypt_block,
) -> bytes:
    """Encrypt plaintext bytes using CBC mode with a 16-byte IV."""
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(f"CBC IV must be {BLOCK_SIZE_BYTES} bytes")

    _ = (plaintext, key, block_encryptor)
    # TODO: Implement CBC chaining + block loop.
    raise NotImplementedError("cbc_encrypt is not implemented yet")


def cbc_decrypt(
    ciphertext: bytes,
    key: bytes,
    iv: bytes,
    block_decryptor: BlockDecryptor = aes_decrypt_block,
) -> bytes:
    """Decrypt ciphertext bytes using CBC mode with a 16-byte IV."""
    if len(iv) != BLOCK_SIZE_BYTES:
        raise ValueError(f"CBC IV must be {BLOCK_SIZE_BYTES} bytes")

    _ = (ciphertext, key, block_decryptor)
    # TODO: Implement CBC decryption + XOR with previous block.
    raise NotImplementedError("cbc_decrypt is not implemented yet")


def encrypt_cbc(
    plaintext: bytes,
    master_key: bytes,
    iv: bytes,
    block_encryptor: BlockEncryptor = aes_encrypt_block,
) -> bytes:
    """Backward-compatible alias for cbc_encrypt."""
    return cbc_encrypt(
        plaintext=plaintext,
        key=master_key,
        iv=iv,
        block_encryptor=block_encryptor,
    )


def decrypt_cbc(
    ciphertext: bytes,
    master_key: bytes,
    iv: bytes,
    block_decryptor: BlockDecryptor = aes_decrypt_block,
) -> bytes:
    """Backward-compatible alias for cbc_decrypt."""
    return cbc_decrypt(
        ciphertext=ciphertext,
        key=master_key,
        iv=iv,
        block_decryptor=block_decryptor,
    )


def encrypt_ctr(
    plaintext: bytes,
    master_key: bytes,
    nonce: bytes,
    initial_counter: int = 0,
    block_encryptor: BlockEncryptor = aes_encrypt_block,
) -> bytes:
    """Encrypt bytes using CTR mode."""
    if len(nonce) != BLOCK_SIZE_BYTES:
        raise ValueError(f"CTR nonce must be {BLOCK_SIZE_BYTES} bytes")
    if initial_counter < 0:
        raise ValueError("initial_counter must be non-negative")

    _ = block_encryptor
    # TODO: Implement counter block construction and keystream XOR.
    raise NotImplementedError("encrypt_ctr is not implemented yet")


def decrypt_ctr(
    ciphertext: bytes,
    master_key: bytes,
    nonce: bytes,
    initial_counter: int = 0,
    block_encryptor: BlockEncryptor = aes_encrypt_block,
) -> bytes:
    """Decrypt bytes using CTR mode (symmetric with encryption)."""
    return encrypt_ctr(
        plaintext=ciphertext,
        master_key=master_key,
        nonce=nonce,
        initial_counter=initial_counter,
        block_encryptor=block_encryptor,
    )