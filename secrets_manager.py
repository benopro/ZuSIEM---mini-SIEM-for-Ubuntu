#!/usr/bin/env python3
"""
ZuSIEM - Secrets Manager
Mã hoá secret (Telegram token, email password...) bằng AES-256-GCM.

Mô hình bảo vệ (ĐỌC KỸ):
  - Bảo vệ TỐT khi: file siem.conf bị lộ/zip gửi nhầm mà KHÔNG kèm file khoá.
  - KHÔNG bảo vệ khi: kẻ tấn công đã có root/đọc được file khoá hoặc RAM.
  => Luôn để file khoá tách khỏi config, chmod 600, KHÔNG commit/zip kèm.

Khoá lấy theo thứ tự ưu tiên:
  1. Biến môi trường ZUSIEM_MASTER_KEY  (base64 của 32 byte)  -- tốt nhất cho systemd
  2. File khoá  ~/.config/zusiem/secret.key  (chmod 600)
Nếu chưa có, chạy lệnh `init-key` để tạo.

Yêu cầu:  pip install cryptography
"""
import os
import sys
import base64
import getpass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ENC_PREFIX = "enc:"                       # token trong conf sẽ có dạng  enc:<base64>
KEY_ENV    = "ZUSIEM_MASTER_KEY"
KEY_FILE   = Path.home() / ".config" / "zusiem" / "secret.key"
NONCE_LEN  = 12                           # 96-bit nonce — chuẩn cho AES-GCM


# ─── QUẢN LÝ KHOÁ ─────────────────────────────────────────
def generate_key_file(path: Path = KEY_FILE) -> bytes:
    """Tạo khoá AES-256 (32 byte) ngẫu nhiên, lưu vào file chmod 600."""
    path.parent.mkdir(parents=True, exist_ok=True)
    key = AESGCM.generate_key(bit_length=256)
    # Ghi với quyền chặt ngay từ đầu (tránh cửa sổ world-readable)
    fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(base64.b64encode(key))
    os.chmod(path, 0o600)
    return key


def load_key() -> bytes:
    """Lấy khoá 32 byte từ env hoặc file. Raise nếu không có."""
    env_val = os.environ.get(KEY_ENV)
    if env_val:
        key = base64.b64decode(env_val)
        if len(key) != 32:
            raise ValueError(f"{KEY_ENV} phải là base64 của đúng 32 byte (AES-256)")
        return key

    if KEY_FILE.exists():
        # Cảnh báo nếu file khoá để quyền lỏng
        mode = os.stat(KEY_FILE).st_mode & 0o077
        if mode:
            print(f"[!] CẢNH BÁO: {KEY_FILE} quyền lỏng — chạy: chmod 600 {KEY_FILE}",
                  file=sys.stderr)
        return base64.b64decode(KEY_FILE.read_bytes())

    raise FileNotFoundError(
        f"Không tìm thấy khoá. Đặt biến {KEY_ENV} hoặc chạy: "
        f"python3 secrets_manager.py init-key"
    )


# ─── MÃ HOÁ / GIẢI MÃ ─────────────────────────────────────
def encrypt(plaintext: str, key: bytes = None) -> str:
    """Trả về chuỗi  enc:<base64(nonce|ciphertext|tag)>  để dán vào conf."""
    key   = key or load_key()
    aes   = AESGCM(key)
    nonce = os.urandom(NONCE_LEN)
    ct    = aes.encrypt(nonce, plaintext.encode("utf-8"), None)  # tag gắn sẵn cuối ct
    blob  = base64.b64encode(nonce + ct).decode("ascii")
    return ENC_PREFIX + blob


def decrypt(value: str, key: bytes = None) -> str:
    """Giải mã chuỗi enc:... Nếu value không có prefix thì trả về nguyên (plaintext)."""
    if not value or not value.startswith(ENC_PREFIX):
        return value                       # tương thích ngược: chưa mã hoá thì dùng thẳng
    key  = key or load_key()
    raw  = base64.b64decode(value[len(ENC_PREFIX):])
    nonce, ct = raw[:NONCE_LEN], raw[NONCE_LEN:]
    aes  = AESGCM(key)
    return aes.decrypt(nonce, ct, None).decode("utf-8")   # ném lỗi nếu bị sửa/đổi khoá


# ─── CLI ──────────────────────────────────────────────────
def _cli():
    args = sys.argv[1:]
    cmd  = args[0] if args else "help"

    if cmd == "init-key":
        if KEY_FILE.exists() and "--force" not in args:
            print(f"Khoá đã tồn tại: {KEY_FILE} (dùng --force để ghi đè)")
            return
        generate_key_file()
        print(f"[+] Đã tạo khoá AES-256: {KEY_FILE} (chmod 600)")
        print(f"    Backup khoá này nơi an toàn. MẤT KHOÁ = mất token đã mã hoá.")

    elif cmd == "encrypt":
        secret = getpass.getpass("Dán secret cần mã hoá (ẩn): ").strip()
        if not secret:
            print("Trống, bỏ qua."); return
        print("\nDán dòng dưới vào siem.conf (thay cho token plaintext):\n")
        print("  " + encrypt(secret) + "\n")

    elif cmd == "decrypt":   # chỉ để kiểm tra
        val = input("Dán chuỗi enc:... : ").strip()
        print(decrypt(val))

    else:
        print(__doc__)
        print("Lệnh:")
        print("  init-key            Tạo khoá AES-256 (chmod 600)")
        print("  encrypt             Mã hoá 1 secret -> chuỗi enc:... dán vào conf")
        print("  decrypt             Giải mã thử 1 chuỗi enc:...")


if __name__ == "__main__":
    _cli()
