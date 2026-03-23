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

    def test_aes_round_structure_constants(self) -> None:
        self.assertEqual(constants.NB, 4)
        self.assertEqual(constants.NK, 4)
        self.assertEqual(constants.NR, 10)

    def test_iv_size_matches_block_size(self) -> None:
        self.assertEqual(constants.IV_SIZE, constants.BLOCK_SIZE)


if __name__ == "__main__":
    unittest.main()