"""Diem vao CLI cho luong sender."""

from __future__ import annotations

import argparse
from pathlib import Path

from cli_parsers import parse_hex_iv, parse_hex_key
from network_sender import send_file


def build_argument_parser() -> argparse.ArgumentParser:
    """Khoi tao bo parser tham so CLI cho sender."""
    parser = argparse.ArgumentParser(
        description="Encrypt a file with AES skeleton flow, then send it to receiver.",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Receiver host")
    parser.add_argument("--port", type=int, default=9000, help="Receiver port")
    parser.add_argument("--file", type=Path, required=True, help="Input file path")
    parser.add_argument(
        "--key-hex",
        type=parse_hex_key,
        required=True,
        help="AES key in hex (32/48/64 hex chars for 128/192/256-bit)",
    )
    parser.add_argument(
        "--iv-hex",
        type=parse_hex_iv,
        required=True,
        help="CBC IV in hex (exactly 32 hex chars)",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    """Chay luong sender."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    try:
        send_file(
            host=args.host,
            port=args.port,
            input_path=str(args.file),
            key=args.key_hex,
            iv=args.iv_hex,
        )
    except Exception as error:  # pragma: no cover - nhanh bao ve cho CLI
        print(f"Sender failed: {error}")
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())