"""Toshiba IOLife security: key derivation, AES, sign, encoding."""

from hashlib import sha256, md5

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

APP_KEY = "09c4d09f0da1513bb62dc7b6b0af9c11"
APP_ID = "1203"
APP_SRC = "203"
HOST = "app.iolife.toshiba-lifestyle.com"
SERVER_VERSION = "v1"
SCHEME = "https"
CLIENT_TYPE = "1"
APP_ENTERPRISE = "0008"
DEFAULT_LANGUAGE = "ja_JP"


def md5_hex(text: str) -> str:
    return md5(text.encode("utf-8")).hexdigest().lower()


def sha256_hex(text: str) -> str:
    return sha256(text.encode("utf-8")).hexdigest().lower()


def app_key_crypto_key(app_key: str = APP_KEY) -> str:
    return md5_hex(app_key)[:16]


def decode_with_app_key(cipher_hex: str, app_key: str = APP_KEY) -> str:
    """AES/ECB decrypt with MD5(app_key)[:16] as ASCII key.

    Used to derive dataKey from accessToken and dataIV from randomData.
    """
    key = app_key_crypto_key(app_key).encode("utf-8")
    raw = bytes.fromhex(cipher_hex)
    cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(raw), 16).decode("utf-8")


def aes_encrypt_hex(plain_text: str, key_text: str, iv_text: str | None = None) -> str:
    """AES encrypt (ECB/CBC) with PKCS7 padding. Key is text (ASCII bytes)."""
    key = key_text.encode("utf-8")
    data = pad(plain_text.encode("utf-8"), 16)
    if iv_text:
        iv = iv_text.encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(data).hex()


def aes_decrypt_hex(cipher_hex: str, key_text: str, iv_text: str | None = None) -> str:
    """AES decrypt (reverse of aes_encrypt_hex)."""
    key = key_text.encode("utf-8")
    raw = bytes.fromhex(cipher_hex)
    if iv_text:
        iv = iv_text.encode("utf-8")
        cipher = AES.new(key, AES.MODE_CBC, iv)
    else:
        cipher = AES.new(key, AES.MODE_ECB)
    return unpad(cipher.decrypt(raw), 16).decode("utf-8")


def encrypt_password(raw_password: str) -> str:
    return aes_encrypt_hex(raw_password, app_key_crypto_key())


def decrypt_password(encrypted: str) -> str:
    return aes_decrypt_hex(encrypted, app_key_crypto_key())


def bytes_to_dec_string(data: bytes) -> str:
    """Convert raw bytes to comma-separated signed decimal string."""
    return ",".join(str(b - 256 if b > 127 else b) for b in data)


def dec_string_to_bytes(data: str) -> bytes:
    """Convert comma-separated signed decimal string back to raw bytes."""
    values: list[int] = []
    for part in data.split(","):
        part = part.strip()
        if not part:
            continue
        values.append((int(part) + 256) % 256)
    return bytes(values)


def sign_v1(path: str, params: dict[str, str]) -> str:
    """Compute V1 sign: SHA256(path + sorted_params + APP_KEY)."""
    sorted_items = sorted(params.items(), key=lambda x: x[0])
    payload = "&".join(f"{k}={v}" for k, v in sorted_items)
    message = path + payload + APP_KEY
    return sha256_hex(message)[:64]


CRC8_854_TABLE = [
    0, 94, 188, 226, 97, 63, 221, 131, 194, 156, 126, 32, 163, 253, 31, 65,
    157, 195, 33, 127, 252, 162, 64, 30, 95, 1, 227, 189, 62, 96, 130, 220,
    35, 125, 159, 193, 66, 28, 254, 160, 225, 191, 93, 3, 128, 222, 60, 98,
    190, 224, 2, 92, 223, 129, 99, 61, 124, 34, 192, 158, 29, 67, 161, 255,
    70, 24, 250, 164, 39, 121, 155, 197, 132, 218, 56, 102, 229, 187, 89, 7,
    219, 133, 103, 57, 186, 228, 6, 88, 25, 71, 165, 251, 120, 38, 196, 154,
    101, 59, 217, 135, 4, 90, 184, 230, 167, 249, 27, 69, 198, 152, 122, 36,
    248, 166, 68, 26, 153, 199, 37, 123, 58, 100, 134, 216, 91, 5, 231, 185,
    140, 210, 48, 110, 237, 179, 81, 15, 78, 16, 242, 172, 47, 113, 147, 205,
    17, 79, 173, 243, 112, 46, 204, 146, 211, 141, 111, 49, 178, 236, 14, 80,
    175, 241, 19, 77, 206, 144, 114, 44, 109, 51, 209, 143, 12, 82, 176, 238,
    50, 108, 142, 208, 83, 13, 239, 177, 240, 174, 76, 18, 145, 207, 45, 115,
    202, 148, 118, 40, 171, 245, 23, 73, 8, 86, 180, 234, 105, 55, 213, 139,
    87, 9, 235, 181, 54, 104, 138, 212, 149, 203, 41, 119, 244, 170, 72, 22,
    233, 183, 85, 11, 136, 214, 52, 106, 43, 117, 151, 201, 74, 20, 246, 168,
    116, 42, 200, 150, 21, 75, 169, 247, 182, 232, 10, 84, 215, 137, 107, 53,
]


def crc8_854(data: list[int], start_pos: int, end_pos: int) -> int:
    crc = 0
    for si in range(start_pos, end_pos + 1):
        crc = CRC8_854_TABLE[(crc ^ data[si]) & 0xFF]
    return crc


def crc16_ccitt(data: list[int], start_pos: int, end_pos: int) -> int:
    crc = 0
    for si in range(start_pos, end_pos + 1):
        crc ^= (data[si] << 8)
        for _ in range(8):
            if crc & 0x8000:
                crc = ((crc << 1) ^ 0x1021) & 0xFFFF
            else:
                crc = (crc << 1) & 0xFFFF
    return crc & 0xFFFF
