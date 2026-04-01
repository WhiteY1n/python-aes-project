"""Loi ma hoa/giai ma AES theo tung block 16 byte."""

from __future__ import annotations

from typing import TypeAlias

from constants import BLOCK_SIZE, INV_S_BOX, S_BOX
from key_schedule import key_expansion

State: TypeAlias = list[list[int]]


def _validate_state_shape(state: State) -> None:
    """Kiem tra state co dung ma tran 4x4 gia tri byte hay khong."""
    if len(state) != 4 or any(len(row) != 4 for row in state):
        raise ValueError("state must be a 4x4 matrix")

    for row in state:
        for value in row:
            if not 0 <= value <= 0xFF:
                raise ValueError("state values must be in range 0..255")


def bytes_to_state(block: bytes) -> State:
    """Chuyen block 16 byte thanh state AES (ma tran 4x4)."""
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")

    # AES nap du lieu theo cot, khong theo hang.
    # Vi du: block[0:4] se lap day cot dau tien tu row 0..3.
    state: State = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            state[row][col] = block[col * 4 + row]
    return state


def state_to_bytes(state: State) -> bytes:
    """Chuyen state AES nguoc lai ve block 16 byte."""
    _validate_state_shape(state)

    # Dao nguoc bytes_to_state(): trai phang theo tung cot.
    output = bytearray(BLOCK_SIZE)
    for col in range(4):
        for row in range(4):
            output[col * 4 + row] = state[row][col]
    return bytes(output)


def xtime(a: int) -> int:
    """Nhan byte voi x trong GF(2^8) theo da thuc rut gon cua AES."""
    if not 0 <= a <= 0xFF:
        raise ValueError("a must be in range 0..255")

    shifted = (a << 1) & 0xFF
    if a & 0x80:
        shifted ^= 0x1B
    return shifted


def gmul(a: int, b: int) -> int:
    """Nhan hai byte trong GF(2^8)."""
    if not 0 <= a <= 0xFF or not 0 <= b <= 0xFF:
        raise ValueError("a and b must be in range 0..255")

    result = 0
    multiplicand = a
    multiplier = b

    # Nhan theo bit trong GF(2^8): neu bit hien tai cua multiplier = 1
    # thi xor multiplicand vao ket qua, sau do xtime() cho bit tiep theo.
    for _ in range(8):
        if multiplier & 1:
            result ^= multiplicand
        multiplicand = xtime(multiplicand)
        multiplier >>= 1

    return result


def add_round_key(state: State, round_key: bytes) -> None:
    """XOR state hien tai voi round key 16 byte (in-place)."""
    _validate_state_shape(state)
    if len(round_key) != BLOCK_SIZE:
        raise ValueError(f"round key must be {BLOCK_SIZE} bytes")

    # Round key duoc map vao state cung layout theo cot.
    for col in range(4):
        for row in range(4):
            state[row][col] ^= round_key[col * 4 + row]


def sub_bytes(state: State) -> None:
    """Thay the tung byte bang S-Box (in-place)."""
    _validate_state_shape(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = S_BOX[state[row][col]]


def inv_sub_bytes(state: State) -> None:
    """Thay the tung byte bang inverse S-Box (in-place)."""
    _validate_state_shape(state)

    for row in range(4):
        for col in range(4):
            state[row][col] = INV_S_BOX[state[row][col]]


def shift_rows(state: State) -> None:
    """Xoay trai cac hang theo chi so hang (in-place)."""
    _validate_state_shape(state)

    # Hang 0 giu nguyen; hang 1/2/3 xoay trai lan luot 1/2/3 buoc.
    for row in range(1, 4):
        state[row] = state[row][row:] + state[row][:row]


def inv_shift_rows(state: State) -> None:
    """Xoay phai cac hang theo chi so hang (in-place)."""
    _validate_state_shape(state)

    # Dao nguoc shift_rows: xoay phai theo chi so hang.
    for row in range(1, 4):
        state[row] = state[row][-row:] + state[row][:-row]


def mix_columns(state: State) -> None:
    """Ap dung MixColumns cho tung cot cua state (in-place)."""
    _validate_state_shape(state)

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        # Nhan ma tran theo dac ta AES tren GF(2^8).
        state[0][col] = gmul(s0, 0x02) ^ gmul(s1, 0x03) ^ s2 ^ s3
        state[1][col] = s0 ^ gmul(s1, 0x02) ^ gmul(s2, 0x03) ^ s3
        state[2][col] = s0 ^ s1 ^ gmul(s2, 0x02) ^ gmul(s3, 0x03)
        state[3][col] = gmul(s0, 0x03) ^ s1 ^ s2 ^ gmul(s3, 0x02)


def inv_mix_columns(state: State) -> None:
    """Ap dung inverse MixColumns cho tung cot cua state (in-place)."""
    _validate_state_shape(state)

    for col in range(4):
        s0 = state[0][col]
        s1 = state[1][col]
        s2 = state[2][col]
        s3 = state[3][col]

        # Ma tran nghich dao cho cac vong giai ma.
        state[0][col] = gmul(s0, 0x0E) ^ gmul(s1, 0x0B) ^ gmul(s2, 0x0D) ^ gmul(s3, 0x09)
        state[1][col] = gmul(s0, 0x09) ^ gmul(s1, 0x0E) ^ gmul(s2, 0x0B) ^ gmul(s3, 0x0D)
        state[2][col] = gmul(s0, 0x0D) ^ gmul(s1, 0x09) ^ gmul(s2, 0x0E) ^ gmul(s3, 0x0B)
        state[3][col] = gmul(s0, 0x0B) ^ gmul(s1, 0x0D) ^ gmul(s2, 0x09) ^ gmul(s3, 0x0E)


def encrypt_block(
    block: bytes,
    key: bytes | None = None,
    *,
    master_key: bytes | None = None,
) -> bytes:
    """Ma hoa mot block 16 byte va tra ve ciphertext.

    Chap nhan `key` (uu tien) hoac `master_key` (de tuong thich cu).
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")
    if key is None and master_key is None:
        raise ValueError("key is required")
    if key is not None and master_key is not None:
        raise ValueError("provide only one of key or master_key")

    effective_key = key if key is not None else master_key
    if effective_key is None:  # pragma: no cover - chan phong ve
        raise ValueError("key is required")

    # key_expansion tra ve Nr+1 round key (Nr phu thuoc do dai key).
    round_keys = key_expansion(effective_key)
    state = bytes_to_state(block)

    nr = len(round_keys) - 1
    if nr not in (10, 12, 14):
        raise ValueError("expanded key produced unsupported round count")

    # Vong 0: chi AddRoundKey (khong Sub/Shift/Mix).
    add_round_key(state, round_keys[0])

    # Cac vong giua: SubBytes -> ShiftRows -> MixColumns -> AddRoundKey.
    for round_index in range(1, nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, round_keys[round_index])

    # Vong cuoi bo MixColumns theo dung thiet ke AES.
    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[nr])

    return state_to_bytes(state)


def decrypt_block(
    block: bytes,
    key: bytes | None = None,
    *,
    master_key: bytes | None = None,
) -> bytes:
    """Giai ma mot block 16 byte va tra ve plaintext.

    Chap nhan `key` (uu tien) hoac `master_key` (de tuong thich cu).
    """
    if len(block) != BLOCK_SIZE:
        raise ValueError(f"AES block must be {BLOCK_SIZE} bytes")
    if key is None and master_key is None:
        raise ValueError("key is required")
    if key is not None and master_key is not None:
        raise ValueError("provide only one of key or master_key")

    effective_key = key if key is not None else master_key
    if effective_key is None:  # pragma: no cover - chan phong ve
        raise ValueError("key is required")

    round_keys = key_expansion(effective_key)
    state = bytes_to_state(block)

    nr = len(round_keys) - 1
    if nr not in (10, 12, 14):
        raise ValueError("expanded key produced unsupported round count")

    # Bat dau tu round key cuoi, sau do dao nguoc thu tu encrypt.
    add_round_key(state, round_keys[nr])

    # Cac vong nghich dao giua: InvShiftRows -> InvSubBytes -> AddRoundKey -> InvMixColumns.
    for round_index in range(nr - 1, 0, -1):
        inv_shift_rows(state)
        inv_sub_bytes(state)
        add_round_key(state, round_keys[round_index])
        inv_mix_columns(state)

    # Vong nghich dao cuoi bo InvMixColumns (doi xung voi vong cuoi encrypt).
    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[0])

    return state_to_bytes(state)