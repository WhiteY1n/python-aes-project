"""Tests for AES core skeleton."""

from __future__ import annotations

import unittest

from aes_core import decrypt_block, encrypt_block


class TestAESCore(unittest.TestCase):
    """Validate AES core function contracts."""

    def test_encrypt_block_requires_block_size(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_block(block=b"too short", key=b"\x00" * 16)

    def test_encrypt_block_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            encrypt_block(block=b"\x00" * 16, key=b"\x00" * 16)

    def test_decrypt_block_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            decrypt_block(block=b"\x00" * 16, key=b"\x00" * 16)


if __name__ == "__main__":
    unittest.main()