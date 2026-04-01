"""Tests for AES core skeleton."""

from __future__ import annotations

import unittest

from aes_core import (
    add_round_key,
    bytes_to_state,
    decrypt_block,
    encrypt_block,
    gmul,
    inv_mix_columns,
    inv_shift_rows,
    inv_sub_bytes,
    mix_columns,
    shift_rows,
    state_to_bytes,
    sub_bytes,
    xtime,
)


class TestAESCore(unittest.TestCase):
    """Validate AES core function contracts."""

    def test_bytes_to_state_and_back_roundtrip(self) -> None:
        block = bytes(range(16))
        state = bytes_to_state(block)
        self.assertEqual(state_to_bytes(state), block)

    def test_bytes_to_state_column_major_mapping(self) -> None:
        block = bytes(range(16))
        state = bytes_to_state(block)
        self.assertEqual(state[0], [0, 4, 8, 12])
        self.assertEqual(state[1], [1, 5, 9, 13])
        self.assertEqual(state[2], [2, 6, 10, 14])
        self.assertEqual(state[3], [3, 7, 11, 15])

    def test_xtime(self) -> None:
        self.assertEqual(xtime(0x57), 0xAE)
        self.assertEqual(xtime(0x83), 0x1D)

    def test_gmul(self) -> None:
        self.assertEqual(gmul(0x57, 0x13), 0xFE)

    def test_add_round_key(self) -> None:
        state = bytes_to_state(bytes(range(16)))
        round_key = bytes([0xFF] * 16)
        add_round_key(state, round_key)
        self.assertEqual(state_to_bytes(state), bytes(value ^ 0xFF for value in range(16)))

    def test_sub_and_inv_sub_bytes_roundtrip(self) -> None:
        state = bytes_to_state(bytes(range(16)))
        original = state_to_bytes(state)
        sub_bytes(state)
        inv_sub_bytes(state)
        self.assertEqual(state_to_bytes(state), original)

    def test_shift_and_inv_shift_rows_roundtrip(self) -> None:
        state = bytes_to_state(bytes(range(16)))
        original = state_to_bytes(state)
        shift_rows(state)
        inv_shift_rows(state)
        self.assertEqual(state_to_bytes(state), original)

    def test_mix_and_inv_mix_columns_roundtrip(self) -> None:
        state = bytes_to_state(bytes(range(16)))
        original = state_to_bytes(state)
        mix_columns(state)
        inv_mix_columns(state)
        self.assertEqual(state_to_bytes(state), original)

    def test_encrypt_block_requires_block_size(self) -> None:
        with self.assertRaises(ValueError):
            encrypt_block(block=b"too short", master_key=b"\x00" * 16)

    def test_encrypt_block_known_vector(self) -> None:
        master_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        self.assertEqual(encrypt_block(plaintext, master_key), expected_ciphertext)

    def test_decrypt_block_known_vector(self) -> None:
        master_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ciphertext = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")
        expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(decrypt_block(ciphertext, master_key), expected_plaintext)

    def test_encrypt_block_known_vector_aes_192(self) -> None:
        key_192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        self.assertEqual(encrypt_block(plaintext, key_192), expected_ciphertext)

    def test_encrypt_block_known_vector_aes_256(self) -> None:
        key_256 = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
        )
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected_ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        self.assertEqual(encrypt_block(plaintext, key_256), expected_ciphertext)

    def test_decrypt_block_known_vector_aes_192(self) -> None:
        key_192 = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        ciphertext = bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191")
        expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(decrypt_block(ciphertext, key_192), expected_plaintext)

    def test_decrypt_block_known_vector_aes_256(self) -> None:
        key_256 = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
        )
        ciphertext = bytes.fromhex("8ea2b7ca516745bfeafc49904b496089")
        expected_plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        self.assertEqual(decrypt_block(ciphertext, key_256), expected_plaintext)

    def test_encrypt_then_decrypt_block_roundtrip(self) -> None:
        master_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        ciphertext = encrypt_block(plaintext, master_key)
        restored = decrypt_block(ciphertext, master_key)
        self.assertEqual(restored, plaintext)


if __name__ == "__main__":
    unittest.main()