"""Tests for protocol skeleton behavior."""

from __future__ import annotations

import unittest

from constants import PROTOCOL_MAGIC, PROTOCOL_VERSION
from protocol import TransferHeader, decode_header, encode_header, unpack_length_prefixed


class TestProtocol(unittest.TestCase):
    """Validate protocol framing contracts."""

    def test_encode_header_prefix(self) -> None:
        header = TransferHeader(
            file_name="demo.txt",
            file_size=123,
            iv_hex="01020304",
        )
        encoded = encode_header(header)
        self.assertTrue(encoded.startswith(PROTOCOL_MAGIC + bytes([PROTOCOL_VERSION])))

    def test_decode_header_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            decode_header(b"dummy")

    def test_unpack_length_prefixed_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            unpack_length_prefixed(b"\x00\x00\x00\x04test")


if __name__ == "__main__":
    unittest.main()