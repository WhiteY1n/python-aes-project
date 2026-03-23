"""Tests for PKCS#7 padding helpers."""

from __future__ import annotations

import unittest

from padding import pkcs7_pad, pkcs7_unpad


class TestPadding(unittest.TestCase):
    """Validate pad/unpad behavior."""

    def test_pad_unpad_empty(self) -> None:
        original = b""
        padded = pkcs7_pad(original, block_size=16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(pkcs7_unpad(padded, block_size=16), original)

    def test_pad_unpad_1_byte(self) -> None:
        original = b"a"
        padded = pkcs7_pad(original, block_size=16)
        self.assertEqual(len(padded), 16)
        self.assertEqual(pkcs7_unpad(padded, block_size=16), original)

    def test_pad_unpad_16_bytes(self) -> None:
        original = b"A" * 16
        padded = pkcs7_pad(original, block_size=16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(pkcs7_unpad(padded, block_size=16), original)

    def test_pad_unpad_17_bytes(self) -> None:
        original = b"B" * 17
        padded = pkcs7_pad(original, block_size=16)
        self.assertEqual(len(padded), 32)
        self.assertEqual(pkcs7_unpad(padded, block_size=16), original)

    def test_unpad_invalid_bytes(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"ABCDEF\x02\x03", block_size=8)

    def test_unpad_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"not-multiple", block_size=16)

    def test_unpad_empty_raises(self) -> None:
        with self.assertRaises(ValueError):
            pkcs7_unpad(b"", block_size=16)


if __name__ == "__main__":
    unittest.main()