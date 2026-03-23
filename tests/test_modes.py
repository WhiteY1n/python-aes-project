"""Tests for mode skeleton functions."""

from __future__ import annotations

import unittest

from modes import cbc_decrypt, cbc_encrypt, xor_bytes


class TestModes(unittest.TestCase):
    """Validate basic mode-level contracts."""

    def test_xor_bytes(self) -> None:
        self.assertEqual(xor_bytes(b"\x0f\xf0", b"\xf0\x0f"), b"\xff\xff")

    def test_encrypt_cbc_rejects_short_iv(self) -> None:
        with self.assertRaises(ValueError):
            cbc_encrypt(
                data=b"\x00" * 16,
                key=b"\x00" * 16,
                iv=b"short",
            )

    def test_cbc_roundtrip(self) -> None:
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        plaintext = b"This is a CBC mode test over bytes."
        ciphertext = cbc_encrypt(data=plaintext, key=key, iv=iv)
        restored = cbc_decrypt(ciphertext=ciphertext, key=key, iv=iv)
        self.assertEqual(restored, plaintext)

    def test_cbc_decrypt_rejects_non_block_length(self) -> None:
        with self.assertRaises(ValueError):
            cbc_decrypt(
                ciphertext=b"\x00" * 15,
                key=b"\x00" * 16,
                iv=b"\x02" * 16,
            )

    def test_cbc_decrypt_rejects_empty(self) -> None:
        with self.assertRaises(ValueError):
            cbc_decrypt(
                ciphertext=b"",
                key=b"\x00" * 16,
                iv=b"\x02" * 16,
            )


if __name__ == "__main__":
    unittest.main()