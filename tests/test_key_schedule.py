"""Tests for key schedule skeleton."""

from __future__ import annotations

import unittest

from key_schedule import expand_key, key_expansion, rot_word, sub_word, validate_key_size


class TestKeySchedule(unittest.TestCase):
    """Validate key schedule entry points."""

    def test_validate_key_size_rejects_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            validate_key_size(b"short")

    def test_rot_word(self) -> None:
        self.assertEqual(rot_word(bytes.fromhex("00112233")), bytes.fromhex("11223300"))

    def test_sub_word(self) -> None:
        self.assertEqual(sub_word(bytes.fromhex("00112233")), bytes.fromhex("638293c3"))

    def test_key_expansion_returns_11_round_keys(self) -> None:
        round_keys = key_expansion(b"\x00" * 16)
        self.assertEqual(len(round_keys), 11)
        self.assertTrue(all(isinstance(round_key, bytes) for round_key in round_keys))
        self.assertTrue(all(len(round_key) == 16 for round_key in round_keys))

    def test_key_expansion_first_round_key_matches_master_key(self) -> None:
        master_key = bytes.fromhex("00112233445566778899aabbccddeeff")
        round_keys = key_expansion(master_key)
        self.assertEqual(round_keys[0], master_key)

    def test_key_expansion_aes_192_round_count(self) -> None:
        key_192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        round_keys = key_expansion(key_192)
        self.assertEqual(len(round_keys), 13)
        self.assertTrue(all(len(round_key) == 16 for round_key in round_keys))

    def test_key_expansion_aes_256_round_count(self) -> None:
        key_256 = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
        )
        round_keys = key_expansion(key_256)
        self.assertEqual(len(round_keys), 15)
        self.assertTrue(all(len(round_key) == 16 for round_key in round_keys))

    def test_expand_key_alias(self) -> None:
        master_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        self.assertEqual(expand_key(master_key), key_expansion(master_key))


if __name__ == "__main__":
    unittest.main()