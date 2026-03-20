"""Wire protocol skeleton for AES file transfer."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

from constants import HEADER_ENCODING, LENGTH_PREFIX_BYTES, PROTOCOL_MAGIC, PROTOCOL_VERSION


@dataclass(frozen=True)
class TransferHeader:
    """Metadata sent before encrypted file payload."""

    file_name: str
    file_size: int
    mode: str
    iv_or_nonce_hex: str


def pack_length_prefixed(payload: bytes) -> bytes:
    """Prefix payload with fixed-size big-endian length."""
    if len(payload) >= (1 << (LENGTH_PREFIX_BYTES * 8)):
        raise ValueError("payload too large for configured length prefix")
    return len(payload).to_bytes(LENGTH_PREFIX_BYTES, "big") + payload


def unpack_length_prefixed(frame: bytes) -> bytes:
    """Extract payload from a length-prefixed frame."""
    _ = frame
    # TODO: Validate frame size and parse length-prefixed payload.
    raise NotImplementedError("unpack_length_prefixed is not implemented yet")


def encode_header(header: TransferHeader) -> bytes:
    """Serialize transfer header into protocol bytes."""
    payload_dict = asdict(header)
    payload_bytes = json.dumps(payload_dict, separators=(",", ":")).encode(HEADER_ENCODING)
    framed_payload = pack_length_prefixed(payload_bytes)
    return PROTOCOL_MAGIC + bytes([PROTOCOL_VERSION]) + framed_payload


def decode_header(raw: bytes) -> TransferHeader:
    """Deserialize protocol bytes into TransferHeader."""
    _ = raw
    # TODO: Validate protocol magic/version and decode JSON payload.
    raise NotImplementedError("decode_header is not implemented yet")