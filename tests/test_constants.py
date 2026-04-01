"""Basic tests for constant definitions."""

from __future__ import annotations

import unittest

import constants


class TestConstants(unittest.TestCase):
    """Validate expected constant values."""

    def test_block_size(self) -> None:
        self.assertEqual(constants.BLOCK_SIZE, 16)

    def test_key_sizes(self) -> None:
        self.assertEqual(constants.AES128_KEY_SIZE, 16)
        self.assertEqual(constants.AES192_KEY_SIZE, 24)
        self.assertEqual(constants.AES256_KEY_SIZE, 32)
        self.assertEqual(constants.VALID_AES_KEY_SIZES, (16, 24, 32))

    def test_aes_nb_constant(self) -> None:
        self.assertEqual(constants.NB, 4)

    def test_iv_size_matches_block_size(self) -> None:
        self.assertEqual(constants.IV_SIZE, constants.BLOCK_SIZE)


if __name__ == "__main__":
    unittest.main()