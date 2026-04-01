"""Diem vao CLI cho luong receiver."""

from __future__ import annotations

import argparse
from pathlib import Path

from cli_parsers import parse_hex_key
from network_receiver import start_receiver


def build_argument_parser() -> argparse.ArgumentParser:
    """Khoi tao bo parser tham so CLI cho receiver."""
    parser = argparse.ArgumentParser(
        description="Receive encrypted file and decrypt with AES skeleton flow.",
    )
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind")
    parser.add_argument("--port", type=int, default=9000, help="Port to bind")
    parser.add_argument(
        "--out-dir",
        type=Path,
        default=Path("received"),
        help="Directory for received encrypted/decrypted files",
    )
    parser.add_argument(
        "--key-hex",
        type=parse_hex_key,
        required=True,
        help="AES key in hex (32/48/64 hex chars for 128/192/256-bit)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Chay luong receiver."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        start_receiver(
            host=args.host,
            port=args.port,
            output_dir=str(args.out_dir),
            key=args.key_hex,
        )
    except Exception as error:  # pragma: no cover - nhanh bao ve cho CLI
        print(f"Receiver failed: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())