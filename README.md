# AES File Transfer Skeleton (Python Standard Library Only)

This project is a starter scaffold for a course assignment:

- Encrypt/decrypt files using AES (to be implemented later).
- Transfer encrypted files between machines over TCP.
- Use only Python standard library.

Important:

- The current code is a skeleton only.
- AES internals and network protocol details are intentionally not completed.
- Many functions include TODO and raise NotImplementedError.

## Project structure

```text
aes_core.py
key_schedule.py
padding.py
modes.py
file_crypto.py
protocol.py
network_sender.py
network_receiver.py
utils.py
constants.py
main_sender.py
main_receiver.py
tests/
  test_aes_core.py
  test_key_schedule.py
  test_padding.py
  test_modes.py
  test_file_crypto.py
  test_protocol.py
  test_network_sender.py
  test_network_receiver.py
  test_utils.py
  test_constants.py
```

## Unified data convention

- Public AES block APIs use bytes for input/output.
- One AES block is always 16 bytes.
- AES-128 key size is fixed at 16 bytes for this project skeleton.
- CBC IV size is fixed at 16 bytes.
- Public APIs do not accept plaintext string directly.
- File crypto APIs are byte-oriented (encrypt file to bytes, decrypt bytes to file).
- Internal helper logic may use list[int] or 4x4 state representation.

## Architecture overview

- constants: Shared constants (block size, protocol metadata, defaults).
- utils: Generic helper functions (chunk read, XOR, random bytes, safe compare).
- key_schedule: AES key expansion interface and validation.
- aes_core: AES single-block encrypt/decrypt skeleton.
- padding: PKCS#7 pad/unpad helpers.
- modes: CBC mode skeleton built on block cipher functions.
- file_crypto: High-level file encryption/decryption workflow.
- protocol: Header/frame encoding skeleton for socket transfer.
- network_sender: Sender-side TCP workflow skeleton.
- network_receiver: Receiver-side TCP workflow skeleton.
- main_sender: Sender CLI entry point.
- main_receiver: Receiver CLI entry point.
- tests: Unit-test skeleton for each module.

## Run examples

Open terminal in project root and run receiver first:

```bash
python main_receiver.py --host 0.0.0.0 --port 9000 --output-dir received --key-hex 00112233445566778899aabbccddeeff --iv-hex 0102030405060708090a0b0c0d0e0f10
```

Run sender on another machine (or same machine with localhost):

```bash
python main_sender.py --host 127.0.0.1 --port 9000 --input sample.txt --encrypted-output sample.txt.enc --key-hex 00112233445566778899aabbccddeeff --iv-hex 0102030405060708090a0b0c0d0e0f10
```

Because this is still a scaffold, commands may stop at TODO points and print NotImplementedError.

## Run tests

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Next implementation steps

1. Implement key schedule and AES core rounds in key_schedule and aes_core.
2. Implement CBC in modes, then wire chunked file IO in file_crypto.
3. Finalize protocol framing and ACK flow in protocol and network modules.
4. Expand tests with real vectors and end-to-end transfer checks.