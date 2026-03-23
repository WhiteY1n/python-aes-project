"""Basic tests for constant definitions."""

from __future__ import annotations

import unittest

import constants


class TestConstants(unittest.TestCase):
    """Validate expected constant values."""

    def test_block_size(self) -> None:
        self.assertEqual(constants.BLOCK_SIZE_BYTES, 16)

    def test_key_sizes(self) -> None:
        self.assertEqual(constants.AES128_KEY_SIZE_BYTES, 16)
        self.assertEqual(constants.VALID_KEY_SIZES, (16,))

    def test_iv_size_matches_block_size(self) -> None:
        self.assertEqual(constants.IV_SIZE_BYTES, constants.BLOCK_SIZE_BYTES)


if __name__ == "__main__":
    unittest.main()