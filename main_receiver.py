"""CLI entry point for receiver workflow."""

from __future__ import annotations

import argparse
from pathlib import Path

from cli_parsers import parse_hex_iv, parse_hex_key
from constants import DEFAULT_CHUNK_SIZE, DEFAULT_SOCKET_TIMEOUT
from file_crypto import FileCryptoConfig, decrypt_file
from network_receiver import FileReceiver, ReceiverConfig


def build_argument_parser() -> argparse.ArgumentParser:
    """Build receiver CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Receive encrypted file and decrypt with AES skeleton flow.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to bind")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("received"),
        help="Directory for received encrypted/decrypted files",
    )
    parser.add_argument(
        "--key-hex",
        type=parse_hex_key,
        required=True,
        help="AES-128 key in hex (exactly 32 hex chars)",
    )
    parser.add_argument(
        "--iv-hex",
        type=parse_hex_iv,
        required=True,
        help="CBC IV in hex (exactly 32 hex chars)",
    )
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_SOCKET_TIMEOUT)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run receiver workflow."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    receiver = FileReceiver(
        ReceiverConfig(
            host=args.host,
            port=args.port,
            timeout=args.timeout,
        )
    )

    file_config = FileCryptoConfig(
        chunk_size=args.chunk_size,
        overwrite=args.overwrite,
    )

    try:
        header, encrypted_path = receiver.receive_once(args.output_dir)
        decrypted_output = args.output_dir / header.file_name
        decrypt_file(
            input_path=encrypted_path,
            output_path=decrypted_output,
            key=args.key_hex,
            iv=args.iv_hex,
            config=file_config,
        )
    except NotImplementedError as error:
        print(f"TODO: {error}")
        return 2
    except Exception as error:  # pragma: no cover - CLI guard path
        print(f"Receiver failed: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())