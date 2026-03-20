"""Tests for receiver networking skeleton."""

from __future__ import annotations

import unittest
from pathlib import Path

from network_receiver import FileReceiver, ReceiverConfig


class TestNetworkReceiver(unittest.TestCase):
    """Validate receiver API contracts."""

    def test_receiver_config_defaults(self) -> None:
        config = ReceiverConfig()
        self.assertEqual(config.host, "0.0.0.0")
        self.assertEqual(config.port, 9000)

    def test_receive_header_placeholder(self) -> None:
        receiver = FileReceiver(ReceiverConfig())
        with self.assertRaises(NotImplementedError):
            receiver.receive_header(connection=None)  # type: ignore[arg-type]

    def test_receive_encrypted_file_placeholder(self) -> None:
        receiver = FileReceiver(ReceiverConfig())
        with self.assertRaises(NotImplementedError):
            receiver.receive_encrypted_file(
                connection=None,  # type: ignore[arg-type]
                output_path=Path("dummy.enc"),
                expected_size=0,
            )


if __name__ == "__main__":
    unittest.main()