"""Bo test cho luong file crypto."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from file_crypto import (
    decrypt_bytes_to_file,
    encrypt_file_to_bytes,
    read_binary_file,
    write_binary_file,
)


class TestFileCrypto(unittest.TestCase):
    """Kiem tra hop dong o tang xu ly file crypto."""

    def test_read_write_binary_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "data.bin"
            expected = b"\x00\x01\x02hello\xff"
            write_binary_file(str(file_path), expected)
            self.assertEqual(read_binary_file(str(file_path)), expected)

    def test_encrypt_file_to_bytes_requires_existing_input(self) -> None:
        with self.assertRaises(FileNotFoundError):
            encrypt_file_to_bytes(
                input_path="missing.bin",
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
            )

    def test_encrypt_file_to_bytes_returns_ciphertext(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "input.bin"
            input_path.write_bytes(b"hello world")

            ciphertext = encrypt_file_to_bytes(
                input_path=str(input_path),
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
            )
            self.assertIsInstance(ciphertext, bytes)
            self.assertGreater(len(ciphertext), 0)

    def test_encrypt_then_decrypt_roundtrip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "plain.bin"
            output_path = Path(tmp_dir) / "restored.bin"
            plaintext = b"Binary\x00data\x01for CBC file crypto."
            input_path.write_bytes(plaintext)

            key = bytes.fromhex("00112233445566778899aabbccddeeff")
            iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

            ciphertext = encrypt_file_to_bytes(str(input_path), key=key, iv=iv)
            decrypt_bytes_to_file(ciphertext, str(output_path), key=key, iv=iv)

            self.assertEqual(output_path.read_bytes(), plaintext)

    def test_encrypt_then_decrypt_roundtrip_aes_192(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "plain192.bin"
            output_path = Path(tmp_dir) / "restored192.bin"
            plaintext = b"AES-192 file crypto roundtrip"
            input_path.write_bytes(plaintext)

            key = bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617")
            iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

            ciphertext = encrypt_file_to_bytes(str(input_path), key=key, iv=iv)
            decrypt_bytes_to_file(ciphertext, str(output_path), key=key, iv=iv)

            self.assertEqual(output_path.read_bytes(), plaintext)

    def test_encrypt_then_decrypt_roundtrip_aes_256(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "plain256.bin"
            output_path = Path(tmp_dir) / "restored256.bin"
            plaintext = b"AES-256 file crypto roundtrip"
            input_path.write_bytes(plaintext)

            key = bytes.fromhex(
                "000102030405060708090a0b0c0d0e0f"
                "101112131415161718191a1b1c1d1e1f",
            )
            iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")

            ciphertext = encrypt_file_to_bytes(str(input_path), key=key, iv=iv)
            decrypt_bytes_to_file(ciphertext, str(output_path), key=key, iv=iv)

            self.assertEqual(output_path.read_bytes(), plaintext)


if __name__ == "__main__":
    unittest.main()