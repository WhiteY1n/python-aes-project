"""Network sending skeleton for encrypted file transfer."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from constants import DEFAULT_SOCKET_TIMEOUT
from protocol import TransferHeader


@dataclass(frozen=True)
class SenderConfig:
    """Connection settings for sender client."""

    host: str
    port: int
    timeout: float = DEFAULT_SOCKET_TIMEOUT


class FileSender:
    """Client-side helper to send metadata and encrypted bytes."""

    def __init__(self, config: SenderConfig) -> None:
        self.config = config

    def _connect(self) -> socket.socket:
        """Open a TCP connection to the receiver."""
        connection = socket.create_connection(
            (self.config.host, self.config.port),
            timeout=self.config.timeout,
        )
        connection.settimeout(self.config.timeout)
        return connection

    def send_header(self, connection: socket.socket, header: TransferHeader) -> None:
        """Send transfer header to receiver."""
        _ = (connection, header)
        # TODO: Send encoded header and wait for ACK.
        raise NotImplementedError("send_header is not implemented yet")

    def send_encrypted_file(self, connection: socket.socket, encrypted_path: Path) -> None:
        """Stream encrypted file content to receiver."""
        if not encrypted_path.exists():
            raise FileNotFoundError(encrypted_path)

        _ = connection
        # TODO: Stream framed payload chunks and finalize transfer.
        raise NotImplementedError("send_encrypted_file is not implemented yet")

    def send_file(self, encrypted_path: Path, header: TransferHeader) -> None:
        """Perform full sender workflow in one call."""
        with self._connect() as connection:
            self.send_header(connection, header)
            self.send_encrypted_file(connection, encrypted_path)