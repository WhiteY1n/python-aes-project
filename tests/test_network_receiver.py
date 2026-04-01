"""Bo test cho luong networking phia receiver."""

from __future__ import annotations

import socket
import tempfile
import threading
import unittest
from pathlib import Path

from modes import cbc_encrypt
from network_receiver import start_receiver
from protocol import build_packet


class TestNetworkReceiver(unittest.TestCase):
    """Kiem tra hop dong API cua receiver."""

    def test_start_receiver_receives_and_writes_file(self) -> None:
        key = bytes.fromhex("00112233445566778899aabbccddeeff")
        iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        plaintext = b"receiver integration test payload"
        ciphertext = cbc_encrypt(plaintext, key=key, iv=iv)
        packet = build_packet(
            file_name="demo.bin",
            original_file_size=len(plaintext),
            iv=iv,
            ciphertext=ciphertext,
        )

        with tempfile.TemporaryDirectory() as tmp_dir:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
                probe.bind(("127.0.0.1", 0))
                host, port = probe.getsockname()

            receiver_thread = threading.Thread(
                target=start_receiver,
                args=(host, port, tmp_dir, key),
                daemon=True,
            )
            receiver_thread.start()

            with socket.create_connection((host, port), timeout=2.0) as client:
                client.sendall(packet)

            receiver_thread.join(timeout=3.0)
            self.assertFalse(receiver_thread.is_alive())

            output_path = Path(tmp_dir) / "demo.bin"
            self.assertTrue(output_path.exists())
            self.assertEqual(output_path.read_bytes(), plaintext)


if __name__ == "__main__":
    unittest.main()