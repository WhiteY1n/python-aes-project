"""Tests for mode skeleton functions."""

from __future__ import annotations

import unittest

from modes import cbc_encrypt, decrypt_ctr


class TestModes(unittest.TestCase):
    """Validate basic mode-level contracts."""

    def test_encrypt_cbc_rejects_short_iv(self) -> None:
        with self.assertRaises(ValueError):
            cbc_encrypt(
                plaintext=b"\x00" * 16,
                key=b"\x00" * 16,
                iv=b"short",
            )

    def test_cbc_encrypt_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            cbc_encrypt(
                plaintext=b"\x00" * 16,
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
            )

    def test_decrypt_ctr_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            decrypt_ctr(
                ciphertext=b"\x00" * 16,
                master_key=b"\x00" * 16,
                nonce=b"\x02" * 16,
            )


if __name__ == "__main__":
    unittest.main()