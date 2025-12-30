from __future__ import annotations

import io
import os
import tarfile
import gzip
import zipfile
import tempfile
from dataclasses import dataclass
from typing import Optional, Tuple, List, Any

import hashlib

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SophosBackupError(Exception):
    pass


@dataclass
class ExtractResult:
    work_dir: str
    extracted_files: List[str]
    decrypted: bool
    notes: str = ""


def _evp_bytes_to_key(password: bytes, salt: bytes, key_len: int, iv_len: int, md: str = "md5") -> Tuple[bytes, bytes]:
    """OpenSSL EVP_BytesToKey compatible KDF (legacy)."""
    if md.lower() == "md5":
        dig = hashlib.md5
    elif md.lower() in ("sha256", "sha-256"):
        dig = hashlib.sha256
    elif md.lower() in ("sha1", "sha-1"):
        dig = hashlib.sha1
    else:
        raise SophosBackupError(f"Unsupported digest for EVP_BytesToKey: {md}")

    out = b""
    prev = b""
    while len(out) < key_len + iv_len:
        prev = dig(prev + password + salt).digest()
        out += prev
    return out[:key_len], out[key_len:key_len + iv_len]


def _pbkdf2(password: bytes, salt: bytes, length: int, iterations: int, alg: str = "sha256") -> bytes:
    if alg.lower() == "sha256":
        h = hashes.SHA256()
    elif alg.lower() == "sha1":
        h = hashes.SHA1()
    else:
        raise SophosBackupError(f"Unsupported PBKDF2 hash: {alg}")

    kdf = PBKDF2HMAC(algorithm=h, length=length, salt=salt, iterations=iterations)
    return kdf.derive(password)


def _aes_cbc_decrypt(ct: bytes, key: bytes, iv: bytes) -> bytes:
    decryptor = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend()).decryptor()
    padded = decryptor.update(ct) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()


def _magic_kind(blob: bytes) -> str:
    b = blob.lstrip()
    if b.startswith(b"\x1f\x8b"):
        return "gzip"
    if b.startswith(b"PK\x03\x04") or b.startswith(b"PK\x05\x06") or b.startswith(b"PK\x07\x08"):
        return "zip"
    if len(blob) > 262 and blob[257:262] == b"ustar":
        return "tar"
    if b.startswith(b"<?xml") or b.startswith(b"<"):
        return "xml"
    if blob.startswith(b"SQLite format 3\x00"):
        return "sqlite"
    return "unknown"


def _maybe_gunzip(blob: bytes) -> bytes:
    if blob.lstrip().startswith(b"\x1f\x8b"):
        return gzip.decompress(blob)
    return blob


def _extract_tar_bytes(blob: bytes, work_dir: str) -> List[str]:
    out: List[str] = []
    with tarfile.open(fileobj=io.BytesIO(blob)) as tf:
        try:
            tf.extractall(path=work_dir)
        except PermissionError as e:
            raise SophosBackupError(
                f"Permission denied while extracting backup to '{work_dir}'. "
                "On Windows, pick a non-protected folder or allow python.exe through Controlled Folder Access. "
                f"Details: {e}"
            )
        for m in tf.getmembers():
            if m.isfile():
                out.append(m.name)
    return out


def _extract_zip_bytes(blob: bytes, work_dir: str) -> List[str]:
    out: List[str] = []
    with zipfile.ZipFile(io.BytesIO(blob)) as zf:
        try:
            zf.extractall(work_dir)
        except PermissionError as e:
            raise SophosBackupError(
                f"Permission denied while extracting backup to '{work_dir}'. "
                "On Windows, pick a non-protected folder or allow python.exe through Controlled Folder Access. "
                f"Details: {e}"
            )
        for n in zf.namelist():
            out.append(n)
    return out


def _clean_dir(path: str) -> None:
    if not os.path.isdir(path):
        return
    for r, ds, fs in os.walk(path, topdown=False):
        for fn in fs:
            try:
                os.remove(os.path.join(r, fn))
            except OSError:
                pass
        for d in ds:
            try:
                os.rmdir(os.path.join(r, d))
            except OSError:
                pass


def _try_decrypt_salted(blob: bytes, password: str) -> Tuple[bytes, str]:
    """Try multiple likely Sophos/OpenSSL variants. Returns (plaintext, note)."""
    if not blob.startswith(b"Salted__"):
        raise SophosBackupError("Backup does not start with OpenSSL Salted__ header.")
    if not password:
        raise SophosBackupError("Backup password is required for encrypted backups.")

    salt = blob[8:16]
    ct = blob[16:]
    pw = password.encode("utf-8")

    attempts: List[Tuple[str, Any]] = []

    # Legacy EVP_BytesToKey (commonly MD5)
    for md in ("md5", "sha256", "sha1"):
        for key_len in (32, 24, 16):
            attempts.append((f"EVP_BytesToKey({md}) AES-{key_len*8}-CBC", ("evp", md, key_len)))

    # PBKDF2 variants (OpenSSL -pbkdf2 often uses HMAC-SHA256, 10000 iterations by default)
    for alg in ("sha256", "sha1"):
        for iters in (10000, 200000):
            for key_len in (32, 16):
                attempts.append((f"PBKDF2({alg},{iters}) AES-{key_len*8}-CBC", ("pbkdf2", alg, iters, key_len)))

    last_err: Optional[Exception] = None
    for label, spec in attempts:
        try:
            if spec[0] == "evp":
                _, md, key_len = spec
                key, iv = _evp_bytes_to_key(pw, salt, key_len, 16, md=md)
            else:
                _, alg, iters, key_len = spec
                key_iv = _pbkdf2(pw, salt, key_len + 16, iterations=iters, alg=alg)
                key, iv = key_iv[:key_len], key_iv[key_len:key_len+16]

            pt = _aes_cbc_decrypt(ct, key, iv)

            # Validate by checking if plaintext looks like something we can handle
            kind = _magic_kind(pt)
            if kind != "unknown":
                return pt, f"Decrypted using {label} -> {kind}"

            # Sometimes it's gzip-wrapped tar; gzip header check on raw bytes:
            if _magic_kind(_maybe_gunzip(pt)) in ("tar", "zip", "xml", "sqlite"):
                kind0 = _magic_kind(pt)
                wrapper = "gzip" if kind0 == "gzip" else kind0
                return pt, f"Decrypted using {label} -> {wrapper}"

        except Exception as e:
            last_err = e
            continue

    raise SophosBackupError(
        "Unable to decrypt backup with supported settings. Verify the password or export type. "
        "This SFOS version may use a different encryption/KDF."
    ) from last_err


def extract_sophos_backup(path: str, password: Optional[str]) -> ExtractResult:
    """Extract Sophos Firewall backup into a working directory.

    Supports:
      - OpenSSL Salted__ encrypted backups (tries EVP_BytesToKey + PBKDF2 variants)
      - Decrypted payload types: tar, tar.gz, zip, xml, sqlite
    """
    with open(path, "rb") as f:
        blob = f.read()

        # Use OS temp directory on Windows to avoid Controlled Folder Access / Desktop write restrictions.
    # We create a fresh working directory per run.
    work_dir = tempfile.mkdtemp(prefix="sophos_audit_extract_")

    decrypted = False
    notes = ""

    if blob.startswith(b"Salted__"):
        pt, note = _try_decrypt_salted(blob, password or "")
        decrypted = True
        notes = note
        payload = pt
    else:
        payload = blob

    # handle gzip wrapper
    payload2 = _maybe_gunzip(payload)
    kind = _magic_kind(payload2)

    files: List[str] = []
    if kind == "tar":
        files = _extract_tar_bytes(payload2, work_dir)
    elif kind == "zip":
        files = _extract_zip_bytes(payload2, work_dir)
    elif kind == "xml":
        out = os.path.join(work_dir, "config.xml")
        try:
            with open(out, "wb") as wf:
                wf.write(payload2)
        except PermissionError as e:
            raise SophosBackupError(
                f"Permission denied while writing '{out}'. "
                "Choose an output location with write permission. "
                f"Details: {e}"
            )
        files = ["config.xml"]
        if notes:
            notes += " | "
        notes += "Parsed as XML payload"
    elif kind == "sqlite":
        out = os.path.join(work_dir, "config.sqlite")
        try:
            with open(out, "wb") as wf:
                wf.write(payload2)
        except PermissionError as e:
            raise SophosBackupError(
                f"Permission denied while writing '{out}'. "
                "Choose an output location with write permission. "
                f"Details: {e}"
            )
        files = ["config.sqlite"]
        if notes:
            notes += " | "
        notes += "Parsed as SQLite payload"
    else:
        head = payload2[:32]
        raise SophosBackupError(
            "Decrypted data is not a recognized archive or XML/SQLite payload. "
            f"Magic kind=unknown. First 32 bytes: {head!r} hex={head.hex()}"
        )

    return ExtractResult(work_dir=work_dir, extracted_files=files, decrypted=decrypted, notes=notes)