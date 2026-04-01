"""Bo test cho cac ham mode."""

from __future__ import annotations

import unittest

from modes import cbc_decrypt, cbc_encrypt, xor_bytes


class TestModes(unittest.TestCase):
    """Kiem tra cac hop dong co ban o tang mode."""

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

    def test_cbc_roundtrip_aes_192(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
        iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        plaintext = b"CBC test with AES-192 key size support"
        ciphertext = cbc_encrypt(data=plaintext, key=key, iv=iv)
        restored = cbc_decrypt(ciphertext=ciphertext, key=key, iv=iv)
        self.assertEqual(restored, plaintext)

    def test_cbc_roundtrip_aes_256(self) -> None:
        key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f",
        )
        iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        plaintext = b"CBC test with AES-256 key size support"
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