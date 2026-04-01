"""Ham ho tro sender cho luong truyen file AES-CBC mot lan qua TCP."""

from __future__ import annotations

import socket
from pathlib import Path

from file_crypto import encrypt_file_to_bytes, read_binary_file
from protocol import build_packet

DEFAULT_CONNECT_TIMEOUT: float = 10.0
DEFAULT_SEND_TIMEOUT: float = 120.0


def _resolve_preferred_host(host: str) -> str:
    """Phan giai host va uu tien dia chi IPv4 khi receiver bind IPv4."""
    try:
        ipv4_infos = socket.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return host

    if not ipv4_infos:
        return host

    return str(ipv4_infos[0][4][0])


def send_file(host: str, port: int, input_path: str, key: bytes, iv: bytes) -> None:
    """Doc file, ma hoa AES-CBC, dong goi packet va gui qua TCP."""
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

    target_host = _resolve_preferred_host(host)
    print(f"[sender] Connecting to {target_host}:{port}")
    try:
        with socket.create_connection(
            (target_host, port),
            timeout=DEFAULT_CONNECT_TIMEOUT,
        ) as connection:
            connection.settimeout(DEFAULT_SEND_TIMEOUT)
            connection.sendall(packet)
    except OSError as error:
        raise ConnectionError(
            f"Failed to send file to {target_host}:{port}: {error}"
        ) from error

    print(f"[sender] Sent {len(ciphertext)} encrypted bytes from {path_obj.name}")