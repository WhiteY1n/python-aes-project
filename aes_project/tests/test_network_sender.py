"""Tests for sender networking skeleton."""

from __future__ import annotations

import unittest

from network_sender import FileSender, SenderConfig
from protocol import TransferHeader


class TestNetworkSender(unittest.TestCase):
    """Validate sender API contracts."""

    def test_sender_config_fields(self) -> None:
        config = SenderConfig(host="127.0.0.1", port=9000)
        self.assertEqual(config.host, "127.0.0.1")
        self.assertEqual(config.port, 9000)

    def test_send_header_placeholder(self) -> None:
        sender = FileSender(SenderConfig(host="127.0.0.1", port=9000))
        header = TransferHeader(
            file_name="a.bin",
            file_size=10,
            mode="CBC",
            iv_or_nonce_hex="00",
        )
        with self.assertRaises(NotImplementedError):
            sender.send_header(connection=None, header=header)  # type: ignore[arg-type]


if __name__ == "__main__":
    unittest.main()