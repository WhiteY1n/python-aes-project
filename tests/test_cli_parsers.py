"""Tests for CLI key/IV hex parsing helpers."""

from __future__ import annotations

import argparse
import unittest

from cli_parsers import parse_hex_iv, parse_hex_key


class TestCliParsers(unittest.TestCase):
    """Validate key/IV parsing and friendly validation errors."""

    def test_parse_hex_key_valid_128(self) -> None:
        key = parse_hex_key("00112233445566778899aabbccddeeff")
        self.assertEqual(len(key), 16)

    def test_parse_hex_key_valid_192(self) -> None:
        key = parse_hex_key("000102030405060708090a0b0c0d0e0f1011121314151617")
        self.assertEqual(len(key), 24)

    def test_parse_hex_key_valid_256(self) -> None:
        key = parse_hex_key(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
        )
        self.assertEqual(len(key), 32)

    def test_parse_hex_iv_valid(self) -> None:
        iv = parse_hex_iv("0102030405060708090a0b0c0d0e0f10")
        self.assertEqual(len(iv), 16)

    def test_parse_hex_key_invalid_length(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError) as context:
            parse_hex_key("001122")
        self.assertIn("32, 48, 64", str(context.exception))

    def test_parse_hex_iv_invalid_length(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError) as context:
            parse_hex_iv("abcd")
        self.assertIn("exactly 32 hex characters", str(context.exception))

    def test_parse_hex_key_invalid_character(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError) as context:
            parse_hex_key("00112233445566778899aabbccddeefg")
        self.assertIn("0-9, a-f, A-F", str(context.exception))

    def test_parse_hex_iv_invalid_character(self) -> None:
        with self.assertRaises(argparse.ArgumentTypeError) as context:
            parse_hex_iv("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
        self.assertIn("0-9, a-f, A-F", str(context.exception))


if __name__ == "__main__":
    unittest.main()
