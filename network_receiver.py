"""Ham ho tro receiver cho luong truyen file AES-CBC mot lan qua TCP."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from file_crypto import write_binary_file
from modes import cbc_decrypt
from protocol import parse_header, recv_exact

DEFAULT_SOCKET_TIMEOUT: float = 10.0
_PREFIX_STRUCT = struct.Struct("!4sBH")
_SUFFIX_STRUCT = struct.Struct("!Q16sQ")


def start_receiver(host: str, port: int, output_dir: str, key: bytes) -> None:
    """Lang nghe TCP mot lan, nhan packet, giai ma va ghi file dau ra."""
    output_path = Path(output_dir)
    output_path.mkdir(parents=True, exist_ok=True)

    print(f"[receiver] Listening on {host}:{port}")
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(DEFAULT_SOCKET_TIMEOUT)
        server_socket.bind((host, port))
        server_socket.listen(1)
    except OSError as error:
        raise ConnectionError(f"Failed to start receiver on {host}:{port}: {error}") from error

    with server_socket:
        connection, client_address = server_socket.accept()
        print(f"[receiver] Connected by {client_address[0]}:{client_address[1]}")

        with connection:
            connection.settimeout(DEFAULT_SOCKET_TIMEOUT)

            # Doc prefix co do dai co dinh de biet do dai ten file.
            prefix = recv_exact(connection, _PREFIX_STRUCT.size)
            _magic, _version, filename_length = _PREFIX_STRUCT.unpack(prefix)

            filename_bytes = recv_exact(connection, filename_length)
            suffix = recv_exact(connection, _SUFFIX_STRUCT.size)
            _file_size, _iv, ciphertext_length = _SUFFIX_STRUCT.unpack(suffix)
            ciphertext = recv_exact(connection, ciphertext_length)

            packet = prefix + filename_bytes + suffix + ciphertext
            header, ciphertext_offset, declared_ciphertext_length = parse_header(packet)

            packet_ciphertext = packet[
                ciphertext_offset : ciphertext_offset + declared_ciphertext_length
            ]

            print(f"[receiver] Decrypting file: {header.file_name}")
            plaintext = cbc_decrypt(packet_ciphertext, key=key, iv=header.iv)

            output_file = output_path / header.file_name
            write_binary_file(str(output_file), plaintext)
            print(f"[receiver] Saved: {output_file}")

            if len(plaintext) != header.file_size:
                print(
                    "[receiver] Warning: decrypted size differs from header "
                    f"({len(plaintext)} != {header.file_size})"
                )