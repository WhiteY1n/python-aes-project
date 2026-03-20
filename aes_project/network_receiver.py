"""Network receiver skeleton for encrypted file transfer."""

from __future__ import annotations

import socket
from dataclasses import dataclass
from pathlib import Path

from constants import DEFAULT_SOCKET_TIMEOUT
from protocol import TransferHeader


@dataclass(frozen=True)
class ReceiverConfig:
    """Listening settings for receiver server."""

    host: str = "0.0.0.0"
    port: int = 9000
    timeout: float = DEFAULT_SOCKET_TIMEOUT
    backlog: int = 1


class FileReceiver:
    """Server-side helper to receive metadata and encrypted bytes."""

    def __init__(self, config: ReceiverConfig) -> None:
        self.config = config

    def _create_server_socket(self) -> socket.socket:
        """Create and bind a listening TCP socket."""
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.settimeout(self.config.timeout)
        server_socket.bind((self.config.host, self.config.port))
        server_socket.listen(self.config.backlog)
        return server_socket

    def receive_header(self, connection: socket.socket) -> TransferHeader:
        """Receive and decode transfer header."""
        _ = connection
        # TODO: Read and decode framed header bytes from socket.
        raise NotImplementedError("receive_header is not implemented yet")

    def receive_encrypted_file(
        self,
        connection: socket.socket,
        output_path: Path,
        expected_size: int,
    ) -> None:
        """Receive encrypted payload and write to file."""
        _ = (connection, output_path, expected_size)
        # TODO: Read payload frames until expected size is fully written.
        raise NotImplementedError("receive_encrypted_file is not implemented yet")

    def receive_once(self, output_directory: Path) -> tuple[TransferHeader, Path]:
        """Handle a single incoming transfer."""
        output_directory.mkdir(parents=True, exist_ok=True)

        with self._create_server_socket() as server_socket:
            connection, _client_address = server_socket.accept()
            with connection:
                header = self.receive_header(connection)
                encrypted_output = output_directory / f"{header.file_name}.enc"
                self.receive_encrypted_file(
                    connection=connection,
                    output_path=encrypted_output,
                    expected_size=header.file_size,
                )
                return header, encrypted_output