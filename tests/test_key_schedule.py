"""Tests for key schedule skeleton."""

from __future__ import annotations

import unittest

from key_schedule import expand_key, key_expansion, validate_key_size


class TestKeySchedule(unittest.TestCase):
    """Validate key schedule entry points."""

    def test_validate_key_size_rejects_invalid_length(self) -> None:
        with self.assertRaises(ValueError):
            validate_key_size(b"short")

    def test_key_expansion_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            key_expansion(b"\x00" * 16)

    def test_expand_key_alias_placeholder(self) -> None:
        with self.assertRaises(NotImplementedError):
            expand_key(b"\x00" * 16)


if __name__ == "__main__":
    unittest.main()