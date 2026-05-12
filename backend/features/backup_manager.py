# -*- coding: utf-8 -*-
"""
Backup Manager — Zero-Trust encrypted backup / restore with HMAC integrity.

Architecture
------------
* Backups are SQLite dump streams encrypted in-memory with AES-256-GCM.
* The resulting blob is written to a versioned ``.bin`` file on disk.
* Every backup carries an HMAC-SHA256 tag authenticated by the user's
  master key, preventing tampering even if the backup directory is breached.
* No plaintext SQL, passwords, or titles ever touch the filesystem.

Rotation policy
---------------
Default: keep the last 10 backups.  Older backups are deleted after a new one
is created successfully.

All transient key material lives in ``bytearray`` and is zeroised with
``zero_memory`` before return.
"""
from __future__ import annotations

import gzip
import io
import json
import os
import secrets
import shutil
import struct
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.core.crypto_bridge import LockedBuffer, bridge, zeroize_mutable_buffer
from backend.core.crypto_core import zero_memory
from backend.database.models import PasswordEntry, User

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_BACKUP_DIR = Path(os.getenv("BITNET_BACKUP_DIR", "./backups"))
_MAX_BACKUPS_DEFAULT = int(os.getenv("BITNET_MAX_BACKUPS", "10"))

# File format version (1 byte)
_BACKUP_FORMAT_VERSION = 2

# Header layout (all little-endian):
#   1 byte   format version
#   1 byte   nonce length (12)
#   12 bytes nonce
#   2 bytes  ciphertext length (uint16, max 65 KB chunks)
#   N bytes  ciphertext chunk
#   32 bytes HMAC-SHA256 tag

_NONCE_LEN = 12
_TAG_LEN = 32


class BackupError(RuntimeError):
    """Raised when any backup/restore operation fails."""

    pass


class _InvalidHMAC(BackupError):
    """HMAC verification failed — backup may have been tampered with."""

    pass


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ensure_backup_dir() -> None:
    _BACKUP_DIR.mkdir(parents=True, exist_ok=True)


def _derive_backup_key(master_key: LockedBuffer) -> bytearray:
    """Derive a dedicated backup AES key via HKDF-SHA256 from the master key."""
    from backend.core.crypto_core import CryptoCore, CryptoConfig

    buf = bridge.locked_buffer_to_bytearray(master_key)
    try:
        config = CryptoConfig()
        core = CryptoCore(config)
        derived = core.derive_subkey(buf, b"backup-v2")
        return bytearray(derived)
    finally:
        zeroize_mutable_buffer(buf)


def _derive_backup_key_v1(master_key: LockedBuffer) -> bytearray:
    """Legacy key derivation for format version 1 (SHA-256 hash)."""
    import hashlib
    h = hashlib.sha256()
    buf = bridge.locked_buffer_to_bytearray(master_key)
    try:
        h.update(buf)
        h.update(b"\x00backup-v1")
        return bytearray(h.digest())
    finally:
        zeroize_mutable_buffer(buf)


def _hmac_tag(key: bytearray, data: bytes) -> bytes:
    import hashlib
    import hmac
    return hmac.new(key, data, hashlib.sha256).digest()


def _pack_backup_blob(ciphertext: bytes, nonce: bytes, hmac_tag: bytes) -> bytes:
    """Pack encrypted payload into a self-describing binary blob."""
    # Simple concatenation with length prefixes for future parsing
    return struct.pack(
        "!BB",
        _BACKUP_FORMAT_VERSION,
        len(nonce),
    ) + nonce + struct.pack("!I", len(ciphertext)) + ciphertext + hmac_tag


def _unpack_backup_blob(blob: bytes) -> tuple[int, bytes, bytes, bytes]:
    """Unpack version, nonce, ciphertext, hmac from blob."""
    min_len = 1 + 1 + 4 + _TAG_LEN  # version + nonce_len + ct_len + hmac
    if len(blob) < min_len:
        raise BackupError(f"Backup blob too short: {len(blob)} bytes (minimum {min_len})")
    offset = 0
    version = struct.unpack_from("!B", blob, offset)[0]
    offset += 1
    nonce_len = struct.unpack_from("!B", blob, offset)[0]
    offset += 1
    nonce = blob[offset : offset + nonce_len]
    offset += nonce_len
    ct_len = struct.unpack_from("!I", blob, offset)[0]
    offset += 4
    ciphertext = blob[offset : offset + ct_len]
    offset += ct_len
    hmac_tag = blob[offset : offset + _TAG_LEN]
    return version, nonce, ciphertext, hmac_tag


async def _gather_entries(db: AsyncSession, user_id: int) -> list[dict[str, Any]]:
    """Export every active (non-deleted) entry for *user_id* as plain dicts."""
    stmt = select(PasswordEntry).where(
        PasswordEntry.user_id == user_id,
        PasswordEntry.is_deleted == False,
    )
    result = await db.execute(stmt)
    rows: list[dict[str, Any]] = []
    for entry in result.scalars().all():
        rows.append(
            {
                "id": entry.id,
                "title_search": entry.title_search,
                "title_cipher": entry.title_cipher,
                "title_nonce": entry.title_nonce,
                "username_cipher": entry.username_cipher,
                "username_nonce": entry.username_nonce,
                "password_cipher": entry.password_cipher,
                "password_nonce": entry.password_nonce,
                "url_cipher": entry.url_cipher,
                "url_nonce": entry.url_nonce,
                "notes_cipher": entry.notes_cipher,
                "notes_nonce": entry.notes_nonce,
                "ciphertext": entry.ciphertext,
                "iv": entry.iv,
                "auth_tag": entry.auth_tag,
                "key_metadata": entry.key_metadata,
                "created_at": entry.created_at.isoformat() if entry.created_at else None,
                "updated_at": entry.updated_at.isoformat() if entry.updated_at else None,
            }
        )
    return rows


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class BackupManager:
    """
    Zero-Trust backup manager.

    Usage::

        mgr = BackupManager(db_session)
        path = await mgr.create(user_id, master_key)
        info = await mgr.list(user_id)
        await mgr.restore(user_id, master_key, info[0].name, confirmed=True)
    """

    def __init__(self, db: AsyncSession) -> None:
        self._db = db

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------
    async def create(
        self,
        user_id: int,
        master_key: LockedBuffer,
        *,
        max_backups: int = _MAX_BACKUPS_DEFAULT,
    ) -> Path:
        """
        Encrypt every active entry for *user_id* and write a backup file.

        Returns the absolute path to the newly created backup file.
        """
        _ensure_backup_dir()

        entries = await _gather_entries(self._db, user_id)
        payload_json = json.dumps(
            {"meta": {"version": 1, "created_at": datetime.now(timezone.utc).isoformat()}, "entries": entries}
        ).encode("utf-8")

        # Compress in-memory (never touches disk as plaintext)
        gzipped = gzip.compress(payload_json, compresslevel=6)

        # Encrypt
        backup_key = _derive_backup_key(master_key)
        try:
            aesgcm = AESGCM(bytes(backup_key))
            nonce = secrets.token_bytes(_NONCE_LEN)
            ciphertext = aesgcm.encrypt(nonce, gzipped, None)
            # ciphertext = auth_tag (16 bytes) + actual ciphertext
            ct_body = ciphertext[:-_TAG_LEN]
            # For our format we keep AES-GCM auth tag inside the ciphertext;
            # we add outer HMAC over the full blob for extra tamper evidence.
            blob = _pack_backup_blob(ciphertext, nonce, _hmac_tag(backup_key, ciphertext))
        finally:
            zero_memory(backup_key)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        filename = f"backup_{user_id}_{timestamp}_{secrets.token_hex(4)}.bin"
        backup_path = _BACKUP_DIR / filename
        backup_path.write_bytes(blob)

        await self.rotate(user_id, max_backups=max_backups)
        return backup_path.resolve()

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------
    async def list(self, user_id: int) -> list[_BackupInfo]:
        """Return metadata for every backup belonging to *user_id*."""
        _ensure_backup_dir()
        prefix = f"backup_{user_id}_"
        infos: list[_BackupInfo] = []
        for path in sorted(_BACKUP_DIR.glob(f"{prefix}*.bin"), key=lambda p: p.stat().st_mtime):
            stat = path.stat()
            infos.append(
                _BackupInfo(
                    name=path.name,
                    size_bytes=stat.st_size,
                    created_at=datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc),
                )
            )
        return infos

    # ------------------------------------------------------------------
    # Restore
    # ------------------------------------------------------------------
    async def restore(
        self,
        user_id: int,
        master_key: LockedBuffer,
        backup_name: str,
        *,
        confirmed: bool = False,
    ) -> int:
        """
        Restore entries from a backup file.

        *confirmed* MUST be ``True`` or the operation is refused.
        Returns the number of entries restored.
        """
        if not confirmed:
            raise BackupError(
                "Restore refused: set confirmed=True to acknowledge "
                "that this will overwrite current data."
            )

        expected_prefix = f"backup_{user_id}_"
        if not backup_name.startswith(expected_prefix):
            raise BackupError("Invalid backup name: must belong to the requesting user")
        backup_path = (_BACKUP_DIR / backup_name).resolve()
        if not str(backup_path).startswith(str(_BACKUP_DIR.resolve())):
            raise BackupError("Invalid backup name: path traversal detected")
        if not backup_path.exists():
            raise BackupError(f"Backup not found: {backup_name}")

        blob = backup_path.read_bytes()
        version, nonce, ciphertext, expected_hmac = _unpack_backup_blob(blob)

        if version == 1:
            backup_key = _derive_backup_key_v1(master_key)
        elif version == _BACKUP_FORMAT_VERSION:
            backup_key = _derive_backup_key(master_key)
        else:
            raise BackupError(f"Unsupported backup format version: {version}")
        try:
            if not secrets.compare_digest(_hmac_tag(backup_key, ciphertext), expected_hmac):
                raise _InvalidHMAC("Backup HMAC verification failed — possible tampering.")

            aesgcm = AESGCM(bytes(backup_key))
            gzipped = aesgcm.decrypt(nonce, ciphertext, None)
        finally:
            zero_memory(backup_key)

        payload_json = gzip.decompress(gzipped)
        data = json.loads(payload_json)
        entries = data.get("entries", [])

        # Restore: overwrite existing rows or insert new ones
        restored = 0
        for raw in entries:
            stmt = select(PasswordEntry).where(
                PasswordEntry.id == raw["id"],
                PasswordEntry.user_id == user_id,
            )
            result = await self._db.execute(stmt)
            existing = result.scalar_one_or_none()
            if existing is not None:
                existing.title_search = raw["title_search"]
                existing.title_cipher = raw["title_cipher"]
                existing.title_nonce = raw["title_nonce"]
                existing.username_cipher = raw.get("username_cipher")
                existing.username_nonce = raw.get("username_nonce")
                existing.password_cipher = raw["password_cipher"]
                existing.password_nonce = raw["password_nonce"]
                existing.url_cipher = raw.get("url_cipher")
                existing.url_nonce = raw.get("url_nonce")
                existing.notes_cipher = raw.get("notes_cipher")
                existing.notes_nonce = raw.get("notes_nonce")
                existing.ciphertext = raw.get("ciphertext")
                existing.iv = raw.get("iv")
                existing.auth_tag = raw.get("auth_tag")
                existing.key_metadata = raw.get("key_metadata")
            else:
                entry = PasswordEntry(
                    user_id=user_id,
                    title_search=raw["title_search"],
                    title_cipher=raw["title_cipher"],
                    title_nonce=raw["title_nonce"],
                    username_cipher=raw.get("username_cipher"),
                    username_nonce=raw.get("username_nonce"),
                    password_cipher=raw["password_cipher"],
                    password_nonce=raw["password_nonce"],
                    url_cipher=raw.get("url_cipher"),
                    url_nonce=raw.get("url_nonce"),
                    notes_cipher=raw.get("notes_cipher"),
                    notes_nonce=raw.get("notes_nonce"),
                    ciphertext=raw.get("ciphertext"),
                    iv=raw.get("iv"),
                    auth_tag=raw.get("auth_tag"),
                    key_metadata=raw.get("key_metadata"),
                )
                self._db.add(entry)
            restored += 1

        await self._db.commit()
        return restored

    # ------------------------------------------------------------------
    # Rotate / delete old backups
    # ------------------------------------------------------------------
    async def rotate(self, user_id: int, *, max_backups: int = _MAX_BACKUPS_DEFAULT) -> int:
        """Delete oldest backups for *user_id* exceeding *max_backups*."""
        _ensure_backup_dir()
        prefix = f"backup_{user_id}_"
        paths = sorted(_BACKUP_DIR.glob(f"{prefix}*.bin"), key=lambda p: p.stat().st_mtime)
        removed = 0
        while len(paths) > max_backups:
            oldest = paths.pop(0)
            oldest.unlink()
            removed += 1
        return removed


class _BackupInfo:
    """Lightweight metadata wrapper for a backup file."""

    def __init__(self, name: str, size_bytes: int, created_at: datetime) -> None:
        self.name = name
        self.size_bytes = size_bytes
        self.created_at = created_at
