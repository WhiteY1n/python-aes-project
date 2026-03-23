"""Sender helper for one-shot AES-CBC file transfer over TCP."""

from __future__ import annotations

import socket
from pathlib import Path

from file_crypto import encrypt_file_to_bytes, read_binary_file
from protocol import build_packet

DEFAULT_SOCKET_TIMEOUT: float = 10.0


def send_file(host: str, port: int, input_path: str, key: bytes, iv: bytes) -> None:
    """Read file, encrypt with AES-CBC, build packet, and send over TCP."""
    path_obj = Path(input_path)
    if not path_obj.exists():
        raise FileNotFoundError(f"Input file not found: {input_path}")

    print(f"[sender] Reading file: {input_path}")
    plaintext = read_binary_file(input_path)

    print("[sender] Encrypting with AES-CBC...")
    ciphertext = encrypt_file_to_bytes(input_path, key=key, iv=iv)

    print("[sender] Building packet...")
    packet = build_packet(
        file_name=path_obj.name,
        original_file_size=len(plaintext),
        iv=iv,
        ciphertext=ciphertext,
    )

    print(f"[sender] Connecting to {host}:{port}")
    try:
        with socket.create_connection((host, port), timeout=DEFAULT_SOCKET_TIMEOUT) as connection:
            connection.settimeout(DEFAULT_SOCKET_TIMEOUT)
            connection.sendall(packet)
    except OSError as error:
        raise ConnectionError(f"Failed to send file to {host}:{port}: {error}") from error

    print(f"[sender] Sent {len(ciphertext)} encrypted bytes from {path_obj.name}")