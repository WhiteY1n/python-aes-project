"""Tests for protocol skeleton behavior."""

from __future__ import annotations

import socket
import unittest

from protocol import (
    build_packet,
    parse_header,
    recv_exact,
)


class TestProtocol(unittest.TestCase):
    """Validate protocol framing contracts."""

    def test_build_and_parse_packet(self) -> None:
        file_name = "demo.txt"
        file_size = 123
        iv = bytes.fromhex("0102030405060708090a0b0c0d0e0f10")
        ciphertext = b"\xaa\xbb\xcc\xdd"

        packet = build_packet(
            file_name=file_name,
            original_file_size=file_size,
            iv=iv,
            ciphertext=ciphertext,
        )

        header, ciphertext_offset, ciphertext_length = parse_header(packet)
        self.assertEqual(header.file_name, file_name)
        self.assertEqual(header.file_size, file_size)
        self.assertEqual(header.iv, iv)
        self.assertEqual(ciphertext_length, len(ciphertext))
        self.assertEqual(packet[ciphertext_offset : ciphertext_offset + ciphertext_length], ciphertext)

    def test_recv_exact_collects_partial_chunks(self) -> None:
        left, right = socket.socketpair()
        try:
            right.sendall(b"ab")
            right.sendall(b"cd")
            self.assertEqual(recv_exact(left, 4), b"abcd")
        finally:
            left.close()
            right.close()

    def test_recv_exact_raises_when_socket_closed_early(self) -> None:
        left, right = socket.socketpair()
        try:
            right.sendall(b"ab")
            right.close()
            with self.assertRaises(ConnectionError):
                recv_exact(left, 4)
        finally:
            left.close()


if __name__ == "__main__":
    unittest.main()