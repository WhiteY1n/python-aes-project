"""Bo test cho cac ham tien ich."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from utils import chunk_reader, random_bytes, secure_compare, xor_bytes


class TestUtils(unittest.TestCase):
    """Unit test cho cac ham tien ich."""

    def test_xor_bytes(self) -> None:
        result = xor_bytes(b"\x0f\xf0", b"\xf0\x0f")
        self.assertEqual(result, b"\xff\xff")

    def test_xor_bytes_requires_equal_length(self) -> None:
        with self.assertRaises(ValueError):
            xor_bytes(b"\x00", b"\x00\x00")

    def test_secure_compare(self) -> None:
        self.assertTrue(secure_compare(b"abc", b"abc"))
        self.assertFalse(secure_compare(b"abc", b"xyz"))

    def test_random_bytes_length(self) -> None:
        token = random_bytes(8)
        self.assertEqual(len(token), 8)

    def test_chunk_reader(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            file_path = Path(tmp_dir) / "data.bin"
            file_path.write_bytes(b"abcdefghij")
            chunks = list(chunk_reader(file_path=file_path, chunk_size=4))
            self.assertEqual(chunks, [b"abcd", b"efgh", b"ij"])


if __name__ == "__main__":
    unittest.main()