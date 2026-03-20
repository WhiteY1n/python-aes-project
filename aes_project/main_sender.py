"""CLI entry point for sender workflow."""

from __future__ import annotations

import argparse
from pathlib import Path

from cli_parsers import parse_hex_iv, parse_hex_key
from constants import DEFAULT_CHUNK_SIZE, DEFAULT_SOCKET_TIMEOUT
from file_crypto import FileCryptoConfig, encrypt_file, normalize_mode
from network_sender import FileSender, SenderConfig
from protocol import TransferHeader


def build_argument_parser() -> argparse.ArgumentParser:
    """Build sender CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Encrypt a file with AES skeleton flow, then send it to receiver.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Receiver host")
    parser.add_argument("--port", type=int, default=9000, help="Receiver port")
    parser.add_argument("--input", type=Path, required=True, help="Input file path")
    parser.add_argument(
        "--encrypted-output",
        type=Path,
        required=True,
        help="Path to write encrypted file",
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
    parser.add_argument("--mode", default="CBC", choices=["CBC", "CTR"], help="Cipher mode")
    parser.add_argument("--chunk-size", type=int, default=DEFAULT_CHUNK_SIZE)
    parser.add_argument("--timeout", type=float, default=DEFAULT_SOCKET_TIMEOUT)
    parser.add_argument("--overwrite", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    """Run sender workflow."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    file_config = FileCryptoConfig(
        mode=normalize_mode(args.mode),
        chunk_size=args.chunk_size,
        overwrite=args.overwrite,
    )

    try:
        encrypt_file(
            input_path=args.input,
            output_path=args.encrypted_output,
            master_key=args.key_hex,
            iv_or_nonce=args.iv_hex,
            config=file_config,
        )

        encrypted_size = args.encrypted_output.stat().st_size if args.encrypted_output.exists() else 0
        header = TransferHeader(
            file_name=args.input.name,
            file_size=encrypted_size,
            mode=file_config.mode,
            iv_or_nonce_hex=args.iv_hex.hex(),
        )

        sender = FileSender(
            SenderConfig(
                host=args.host,
                port=args.port,
                timeout=args.timeout,
            )
        )
        sender.send_file(encrypted_path=args.encrypted_output, header=header)
    except NotImplementedError as error:
        print(f"TODO: {error}")
        return 2
    except Exception as error:  # pragma: no cover - CLI guard path
        print(f"Sender failed: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())