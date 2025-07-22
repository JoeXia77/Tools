#!/usr/bin/env python3

## how to use:
## set up source path of the folder you hold .enc files, and also password when encrypt.
## then run (Uncomment) decrypt_enc_folder method at the bottom 
## if need, pip install cryptography tqdm

"""
secure_pack v2  —  “one‑folder‑one‑blob” edition
================================================
Encrypt **each first‑level item** (file *or* sub‑folder) in a source directory
into its own 1.enc, 2.enc, 3.enc … The .enc names reveal nothing; the *original*
name is stored **inside the ciphertext header**, so decryption can restore the
exact names automatically.

Key points
----------
* Still AES‑256‑GCM + PBKDF2‑HMAC‑SHA256 (200 k) + per‑chunk nonces.
* Each .enc therefore protects a single logical item → corruption / re‑upload
  risk is isolated.
* Decryption works on an entire folder of .enc files at once.
* Only walks **one directory level**; deeper levels remain untouched.

Install once
------------
    pip install cryptography tqdm
"""
from __future__ import annotations

import os
import io
import shutil
import struct
import tempfile
from pathlib import Path
from typing import Iterable, BinaryIO

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from tqdm import tqdm

# ───────────────────────── constants / params ──────────────────────────
MAGIC = b"ENCR1"   # 5‑byte file magic
SALT_LEN = 16
NONCE_LEN = 12
PBKDF2_ITERS = 200_000
KEY_LEN = 32
DEFAULT_CHUNK_MB = 64

# ──────────────────────────── helpers ──────────────────────────────────

def _derive_key(password: bytes, salt: bytes) -> bytes:
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_LEN,
        salt=salt,
        iterations=PBKDF2_ITERS,
    ).derive(password)


def _chunked(reader: BinaryIO, size: int) -> Iterable[bytes]:
    while True:
        block = reader.read(size)
        if not block:
            break
        yield block


def _zip_path(src: Path) -> Path:
    """Return temp ZIP path (no compression) containing *src*.
    For a file, the zip will contain that single file under its own name.
    For a directory, zip preserves directory structure one level deep.
    """
    tmpdir = tempfile.mkdtemp(prefix="secure_pack_")
    base = Path(tmpdir) / "data"
    if src.is_dir():
        archive = shutil.make_archive(str(base), "zip", root_dir=src)
    else:  # single file → zip containing that file at root level
        with tempfile.TemporaryDirectory() as td:
            tmp_root = Path(td)
            shutil.copy2(src, tmp_root / src.name)
            archive = shutil.make_archive(str(base), "zip", root_dir=tmp_root)
    return Path(archive)

# ────────────────────────── core routines ──────────────────────────────

def _encrypt_stream(src_fp: BinaryIO, dst_fp: BinaryIO, password: str, *,
                    orig_name: str, chunk_size: int) -> int:
    """Encrypt *src_fp* → *dst_fp* writing our custom container format.
    Returns number of plaintext bytes encrypted (excluding metadata header).
    """
    # Header part 1: magic + salt (plaintext)
    salt = os.urandom(SALT_LEN)
    dst_fp.write(MAGIC)
    dst_fp.write(salt)

    # Derive key, set up cipher
    key = _derive_key(password.encode(), salt)
    aes = AESGCM(key)

    # Header part 2: encrypted metadata (original name)
    meta = orig_name.encode("utf‑8")
    meta_blob = struct.pack(">H", len(meta)) + meta  # 2‑byte length prefix
    nonce = os.urandom(NONCE_LEN)
    meta_ct = aes.encrypt(nonce, meta_blob, None)
    dst_fp.write(struct.pack(">I", len(meta_ct)))
    dst_fp.write(nonce)
    dst_fp.write(meta_ct)

    # Body: file stream in chunks
    total = 0
    for chunk in tqdm(_chunked(src_fp, chunk_size), desc=f"Encrypting {orig_name}", unit="chunk"):
        nonce = os.urandom(NONCE_LEN)
        ct = aes.encrypt(nonce, chunk, None)
        dst_fp.write(struct.pack(">I", len(ct)))
        dst_fp.write(nonce)
        dst_fp.write(ct)
        total += len(chunk)
    return total


def _decrypt_stream(src_fp: BinaryIO, password: str):
    """Generator that yields (orig_name: str, body_bytes_io: BytesIO)."""
    if src_fp.read(5) != MAGIC:
        raise ValueError("Bad magic — not a secure_pack blob")
    salt = src_fp.read(SALT_LEN)
    key = _derive_key(password.encode(), salt)
    aes = AESGCM(key)

    # --- first record must be metadata ---
    lenbuf = src_fp.read(4)
    if not lenbuf:
        raise ValueError("Truncated file: missing metadata record")
    (clen,) = struct.unpack(">I", lenbuf)
    nonce = src_fp.read(NONCE_LEN)
    meta_ct = src_fp.read(clen)
    meta_blob = aes.decrypt(nonce, meta_ct, None)
    name_len = struct.unpack(">H", meta_blob[:2])[0]
    orig_name = meta_blob[2:2 + name_len].decode("utf‑8")

    # Remaining records = body
    buf = io.BytesIO()
    while True:
        lenbuf = src_fp.read(4)
        if not lenbuf:
            break
        (clen,) = struct.unpack(">I", lenbuf)
        nonce = src_fp.read(NONCE_LEN)
        ct = src_fp.read(clen)
        pt = aes.decrypt(nonce, ct, None)
        buf.write(pt)
    buf.seek(0)
    return orig_name, buf

# ───────────────────── high‑level public API ───────────────────────────

def encrypt_folder_items(source_dir: str | Path, dest_dir: str | Path, password: str,
                         *, chunk_mb: int = DEFAULT_CHUNK_MB) -> None:
    """Encrypt every **first‑level item** of *source_dir* → numbered .enc files.

    Example output: 1.enc, 2.enc … (in alphabetical order of items)
    """
    src = Path(source_dir).resolve()
    dst = Path(dest_dir).resolve()
    dst.mkdir(parents=True, exist_ok=True)
    items = sorted(src.iterdir())  # one level
    chunk_bytes = chunk_mb * 1024 * 1024

    for idx, item in enumerate(items, 1):
        archive = _zip_path(item)
        enc_path = dst / f"{idx}.enc"
        with open(archive, "rb") as fin, open(enc_path, "wb") as fout:
            _encrypt_stream(fin, fout, password, orig_name=item.name, chunk_size=chunk_bytes)
        print(f"[✔] {item.name} → {enc_path.name}")
        archive.unlink(missing_ok=True)


def decrypt_enc_folder(enc_folder: str | Path, restore_dir: str | Path, password: str) -> None:
    """Decrypt **all** .enc files in *enc_folder* → original items under *restore_dir*.

    • If the blob came from a folder, the ZIP is now extracted into a new
      subdirectory named exactly like the original folder, preserving the
      layer‑2 names you missed before.
    """
    enc_folder = Path(enc_folder).resolve()
    restore_dir = Path(restore_dir).resolve()
    restore_dir.mkdir(parents=True, exist_ok=True)

    enc_files = sorted(p for p in enc_folder.iterdir() if p.suffix == ".enc")
    for enc in enc_files:
        with open(enc, "rb") as fin:
            orig_name, body = _decrypt_stream(fin, password)
        target_path = restore_dir / orig_name  # always restore into this path

        # Determine if body is zip or raw file
        if body.getbuffer()[:4] == b"PK":
            import zipfile
            print(f"[+] Extracting {orig_name} …")
            target_path.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(body) as zf:
                zf.extractall(target_path)
        else:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            with open(target_path, "wb") as fout:
                shutil.copyfileobj(body, fout)
            print(f"[✔] Restored {orig_name}")


# ─────────────────────────── demo area ─────────────────────────────────
# Edit these paths & password, then run in your IDE.

# <<< ENCODE EVERY ITEM >>>
# encrypt_folder_items(
#     source_dir = Path("./A"),        # first‑level items to pack
#     dest_dir   = Path("S:/temp/encs"),  # where 1.enc,2.enc… will go
#     password   = "",
# )

# <<< DECODE BACK >>>
decrypt_enc_folder(
    enc_folder  = Path("S:/temp/G"),
    restore_dir = Path("./G_restored"),
    password    = "",
)
