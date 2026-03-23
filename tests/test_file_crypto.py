"""Tests for file crypto workflow skeleton."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from file_crypto import (
    FileCryptoConfig,
    decrypt_bytes_to_file,
    decrypt_file,
    encrypt_file,
    encrypt_file_to_bytes,
    normalize_mode,
)


class TestFileCrypto(unittest.TestCase):
    """Validate high-level file crypto contracts."""

    def test_normalize_mode(self) -> None:
        self.assertEqual(normalize_mode("cbc"), "CBC")
        self.assertEqual(normalize_mode("CBC"), "CBC")

    def test_normalize_mode_rejects_invalid(self) -> None:
        with self.assertRaises(ValueError):
            normalize_mode("CTR")

    def test_encrypt_file_requires_existing_input(self) -> None:
        config = FileCryptoConfig()
        with self.assertRaises(FileNotFoundError):
            encrypt_file(
                input_path=Path("missing.bin"),
                output_path=Path("out.bin"),
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
                config=config,
            )

    def test_encrypt_file_to_bytes_requires_existing_input(self) -> None:
        with self.assertRaises(FileNotFoundError):
            encrypt_file_to_bytes(
                input_path=Path("missing.bin"),
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
            )

    def test_encrypt_file_to_bytes_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "input.bin"
            input_path.write_bytes(b"hello world")

            with self.assertRaises(NotImplementedError):
                encrypt_file_to_bytes(
                    input_path=input_path,
                    key=b"\x00" * 16,
                    iv=b"\x01" * 16,
                )

    def test_encrypt_file_placeholder(self) -> None:
        config = FileCryptoConfig(overwrite=True)
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "input.bin"
            output_path = Path(tmp_dir) / "output.bin"
            input_path.write_bytes(b"hello world")

            with self.assertRaises(NotImplementedError):
                encrypt_file(
                    input_path=input_path,
                    output_path=output_path,
                    key=b"\x00" * 16,
                    iv=b"\x01" * 16,
                    config=config,
                )

    def test_decrypt_file_requires_existing_input(self) -> None:
        config = FileCryptoConfig()
        with self.assertRaises(FileNotFoundError):
            decrypt_file(
                input_path=Path("missing.enc"),
                output_path=Path("out.txt"),
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
                config=config,
            )

    def test_decrypt_bytes_to_file_placeholder(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = Path(tmp_dir) / "out.txt"
            with self.assertRaises(NotImplementedError):
                decrypt_bytes_to_file(
                    ciphertext=b"\x00" * 16,
                    output_path=output_path,
                    key=b"\x00" * 16,
                    iv=b"\x01" * 16,
                    overwrite=True,
                )


if __name__ == "__main__":
    unittest.main()