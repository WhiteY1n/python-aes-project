"""Bo test cho luong networking phia sender."""

from __future__ import annotations

import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from network_sender import _resolve_preferred_host, send_file


class _FakeConnection:
    def __init__(self) -> None:
        self.timeout: float | None = None
        self.sent_data: bytes = b""

    def settimeout(self, value: float) -> None:
        self.timeout = value

    def sendall(self, data: bytes) -> None:
        self.sent_data += data

    def __enter__(self) -> "_FakeConnection":
        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        return None


class TestNetworkSender(unittest.TestCase):
    """Kiem tra hop dong API cua sender."""

    def test_send_file_requires_existing_input(self) -> None:
        with self.assertRaises(FileNotFoundError):
            send_file(
                host="127.0.0.1",
                port=9000,
                input_path="missing.bin",
                key=b"\x00" * 16,
                iv=b"\x01" * 16,
            )

    def test_send_file_sends_packet(self) -> None:
        fake_connection = _FakeConnection()
        with tempfile.TemporaryDirectory() as tmp_dir:
            input_path = Path(tmp_dir) / "demo.bin"
            input_path.write_bytes(b"hello sender")

            with patch("network_sender.socket.create_connection", return_value=fake_connection):
                send_file(
                    host="127.0.0.1",
                    port=9000,
                    input_path=str(input_path),
                    key=b"\x00" * 16,
                    iv=b"\x01" * 16,
                )

        self.assertGreater(len(fake_connection.sent_data), 0)

    def test_resolve_preferred_host_returns_ipv4_for_hostname(self) -> None:
        fake_infos = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.10", 0)),
        ]
        with patch("network_sender.socket.getaddrinfo", return_value=fake_infos):
            resolved = _resolve_preferred_host("receiver-host")

        self.assertEqual(resolved, "192.168.1.10")

    def test_resolve_preferred_host_falls_back_to_original_on_dns_error(self) -> None:
        with patch("network_sender.socket.getaddrinfo", side_effect=socket.gaierror("dns error")):
            resolved = _resolve_preferred_host("unknown-host")

        self.assertEqual(resolved, "unknown-host")


if __name__ == "__main__":
    unittest.main()