"""Tests for PKCS#7 padding helpers."""

from __future__ import annotations

import unittest

from padding import pkcs7_pad, pkcs7_unpad


class TestPadding(unittest.TestCase):
    """Validate pad/unpad behavior."""

    def test_pad_unpad_roundtrip(self) -> None:
        original = b"hello"
        padded = pkcs7_pad(original, block_size=16)
        restored = pkcs7_unpad(padded, block_size=16)
        self.assertEqual(restored, original)

    def test_unpad_invalid_bytes(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"ABCDEF\x02\x03", block_size=8)


if __name__ == "__main__":
    unittest.main()