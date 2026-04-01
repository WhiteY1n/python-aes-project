"""Giao thuc packet TCP toi gian cho truyen file da ma hoa."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass

PROTOCOL_MAGIC: bytes = b"AESF"
PROTOCOL_VERSION: int = 1
HEADER_ENCODING: str = "utf-8"
IV_SIZE_BYTES: int = 16

_PREFIX_STRUCT = struct.Struct("!4sBH")
_SUFFIX_STRUCT = struct.Struct("!Q16sQ")


@dataclass(frozen=True)
class TransferHeader:
    """Thong tin metadata di kem truoc payload da ma hoa."""

    file_name: str
    file_size: int
    iv: bytes


def build_packet(
    file_name: str,
    original_file_size: int,
    iv: bytes,
    ciphertext: bytes,
) -> bytes:
    """Tao mot packet truyen gom header va payload ciphertext."""
    if not file_name:
        raise ValueError("file_name must not be empty")
    if original_file_size < 0:
        raise ValueError("original_file_size must be non-negative")
    if len(iv) != IV_SIZE_BYTES:
        raise ValueError(f"iv must be exactly {IV_SIZE_BYTES} bytes")

    filename_bytes = file_name.encode(HEADER_ENCODING)
    if len(filename_bytes) > 0xFFFF:
        raise ValueError("file_name is too long for protocol field")

    # Prefix co do dai co dinh va chua magic/version/do dai ten file.
    prefix = _PREFIX_STRUCT.pack(
        PROTOCOL_MAGIC,
        PROTOCOL_VERSION,
        len(filename_bytes),
    )
    # Suffix chua kich thuoc file goc, IV va do dai ciphertext.
    suffix = _SUFFIX_STRUCT.pack(
        original_file_size,
        iv,
        len(ciphertext),
    )
    return prefix + filename_bytes + suffix + ciphertext


def parse_header(packet: bytes) -> tuple[TransferHeader, int, int]:
    """Phan tich header protocol va tra ve metadata + vi tri ciphertext."""
    if len(packet) < _PREFIX_STRUCT.size + _SUFFIX_STRUCT.size:
        raise ValueError("packet too short for protocol header")

    magic, version, filename_length = _PREFIX_STRUCT.unpack_from(packet, 0)
    if magic != PROTOCOL_MAGIC:
        raise ValueError("invalid protocol magic")
    if version != PROTOCOL_VERSION:
        raise ValueError("unsupported protocol version")

    # Tinh bien phan tu bien do dai de cat packet an toan.
    filename_start = _PREFIX_STRUCT.size
    filename_end = filename_start + filename_length
    suffix_end = filename_end + _SUFFIX_STRUCT.size
    if len(packet) < suffix_end:
        raise ValueError("packet too short for declared filename/header")

    filename_bytes = packet[filename_start:filename_end]
    try:
        file_name = filename_bytes.decode(HEADER_ENCODING)
    except UnicodeDecodeError as error:
        raise ValueError("filename is not valid UTF-8") from error

    file_size, iv, ciphertext_length = _SUFFIX_STRUCT.unpack_from(packet, filename_end)
    ciphertext_offset = suffix_end
    if len(packet) < ciphertext_offset + ciphertext_length:
        raise ValueError("packet too short for declared ciphertext length")

    header = TransferHeader(file_name=file_name, file_size=file_size, iv=iv)
    return header, ciphertext_offset, ciphertext_length


def recv_exact(sock: socket.socket, n: int) -> bytes:
    """Nhan dung n bytes tu socket, thieu du lieu thi bao loi."""
    if n < 0:
        raise ValueError("n must be non-negative")

    buffer = bytearray()
    while len(buffer) < n:
        chunk = sock.recv(n - len(buffer))
        if not chunk:
            raise ConnectionError("socket closed before receiving expected bytes")
        buffer.extend(chunk)
    return bytes(buffer)


def extract_ciphertext(packet: bytes, offset: int, length: int) -> bytes:
    """Cat payload ciphertext dua tren bien offset/length da parse."""
    return packet[offset : offset + length]