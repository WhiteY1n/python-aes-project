# Python AES File Transfer

Project demo truyền file bằng Python standard library, dùng:

- AES-128
- CBC mode
- PKCS#7 padding
- TCP file transfer

## Cấu trúc chính

- `main_receiver.py`: CLI nhận file
- `main_sender.py`: CLI gửi file
- `network_receiver.py` / `network_sender.py`: luồng TCP
- `protocol.py`: đóng gói packet (header + ciphertext)
- `file_crypto.py`: mã hóa/giải mã dữ liệu file
- `modes.py`, `padding.py`, `aes_core.py`, `key_schedule.py`: lõi AES/CBC/PKCS#7
- `tests/`: unit tests
## Sau khi pull chạy 2 lệnh
- python -m venv .venv
- .venv\Scripts\activate
## Cách chạy nhanh

Mở terminal tại thư mục project.

1. Chạy receiver trước:

```bash
python main_receiver.py --host 127.0.0.1 --port 9000 --out-dir received --key-hex 00112233445566778899aabbccddeeff
```

2. Chạy sender ở terminal khác:

```bash
python main_sender.py --host 127.0.0.1 --port 9000 --file sample.bin --key-hex 00112233445566778899aabbccddeeff --iv-hex 0102030405060708090a0b0c0d0e0f10
```

## Key/IV hợp lệ

- `key-hex`: 32 ký tự hex (16 byte), ví dụ: `00112233445566778899aabbccddeeff`
- `iv-hex`: 32 ký tự hex (16 byte), ví dụ: `0102030405060708090a0b0c0d0e0f10`

Chỉ dùng ký tự `0-9`, `a-f`, `A-F`.

## Chạy test

```bash
python -m unittest discover -s tests -p "test_*.py"
```

## Kiểm tra file nhận đúng không

So sánh SHA256:

```bash
certutil -hashfile sample.bin SHA256
certutil -hashfile received\sample.bin SHA256
```

Nếu 2 hash giống nhau thì file nhận đúng.

## Lỗi thường gặp

- Sai key/iv: kiểm tra lại đủ 32 ký tự hex.
- Không kết nối được: chạy receiver trước, kiểm tra host/port.
- Lỗi ghi file: kiểm tra quyền ghi thư mục `--out-dir`.
- Padding error khi nhận: thường do key sai hoặc dữ liệu truyền lỗi.