# -*- coding: utf-8 -*-
"""
Import/Export Feature - CSV and JSON import/export
Author: Alexey (BE2)
Fixed by: Nikita (BE1) - Week 9-10 Security Fixes

SECURITY FIXES:
- Encrypt exported data
- Validate imported data
- Fix path traversal vulnerability
- Add file size limits
"""

import json
import csv
import os
import pathlib
from datetime import datetime
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, ValidationError
from backend.core.crypto_core import CryptoCore


class ImportEntry(BaseModel):
    """Validated import entry schema."""
    title: str
    username: Optional[str] = None
    password: str
    url: Optional[str] = None
    notes: Optional[str] = None


class ImportExportService:
    """Service for importing and exporting password data."""
    
    # ✅ FIX: Add limits
    MAX_IMPORT_ENTRIES = 1000
    MAX_FILE_SIZE_MB = 10
    
    def __init__(
        self,
        db_session,
        crypto_key: bytes,
        export_dir: Optional[pathlib.Path] = None,
        import_dir: Optional[pathlib.Path] = None,
        temp_dir: Optional[pathlib.Path] = None,
    ):
        """
        Initialize import/export service.
        
        Args:
            db_session: SQLAlchemy session
            crypto_key: Encryption key for export
            export_dir: Optional base directory for export operations
            import_dir: Optional base directory for import operations
            temp_dir: Optional base directory for temporary files cleanup
        """
        self.db = db_session
        self.crypto = CryptoCore()
        self.crypto_key = crypto_key
        base_data_dir = pathlib.Path(
            os.getenv("BEZ_DATA_DIR", pathlib.Path.home() / ".bez")
        ).expanduser()
        self._export_dir = self._resolve_base_dir(
            explicit=export_dir,
            env_name="BEZ_EXPORT_DIR",
            default=base_data_dir / "exports",
        )
        self._import_dir = self._resolve_base_dir(
            explicit=import_dir,
            env_name="BEZ_IMPORT_DIR",
            default=base_data_dir / "imports",
        )
        self._temp_dir = self._resolve_base_dir(
            explicit=temp_dir,
            env_name="BEZ_TEMP_DIR",
            default=base_data_dir / "temp",
        )

    @staticmethod
    def _resolve_base_dir(
        explicit: Optional[pathlib.Path],
        env_name: str,
        default: pathlib.Path,
    ) -> pathlib.Path:
        """Resolve and create operation base directory."""
        if explicit is not None:
            base = pathlib.Path(explicit).expanduser()
        else:
            env_value = os.getenv(env_name)
            base = pathlib.Path(env_value).expanduser() if env_value else pathlib.Path(default)
        resolved = base.resolve()
        resolved.mkdir(parents=True, exist_ok=True)
        return resolved

    @staticmethod
    def _ensure_path_within_base(
        target_path: pathlib.Path,
        base_dir: pathlib.Path,
        error_message: str,
    ) -> pathlib.Path:
        """Resolve and validate that target path is inside allowed base dir."""
        resolved_base = base_dir.resolve()
        resolved_target = target_path.resolve()
        try:
            resolved_target.relative_to(resolved_base)
        except ValueError:
            raise ValueError(error_message)
        return resolved_target

    @staticmethod
    def _resolve_io_path(
        filepath: str,
        base_dir: pathlib.Path,
        error_message: str,
        allow_absolute: bool = True,
    ) -> pathlib.Path:
        """
        Resolve IO path in a cross-platform way.

        - Absolute path: allowed directly for usability (import/export UX).
        - Relative path: resolved under configured base dir with traversal checks.
        """
        requested = pathlib.Path(filepath).expanduser()
        if requested.is_absolute():
            if not allow_absolute:
                raise ValueError(error_message)
            return requested.resolve()
        return ImportExportService._ensure_path_within_base(
            base_dir / requested,
            base_dir,
            error_message,
        )

    def _resolve_export_path(self, filepath: str) -> pathlib.Path:
        """Resolve export destination and ensure parent directory exists."""
        export_path = self._resolve_io_path(
            filepath,
            self._export_dir,
            "Invalid export path",
            allow_absolute=True,
        )
        export_path.parent.mkdir(parents=True, exist_ok=True)
        return export_path

    def _resolve_import_path(self, filepath: str) -> pathlib.Path:
        """Resolve import source path and ensure file exists."""
        import_path = self._resolve_io_path(
            filepath,
            self._import_dir,
            "Invalid import path",
            allow_absolute=True,
        )
        if not import_path.exists() or not import_path.is_file():
            raise FileNotFoundError(f"Import file not found: {import_path}")
        return import_path

    def _derive_export_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive per-export encryption key from user master password."""
        if not master_password:
            raise ValueError("master_password is required for encrypted export/import")
        return self.crypto.derive_master_key(master_password, salt)
    
    def export_to_json(
        self,
        user_id: int,
        entries: List[Dict],
        filepath: str,
        master_password: str
    ) -> bool:
        """
        Export entries to encrypted JSON file.
        
        ✅ FIX: Encrypt exported data
        ✅ FIX: Validate filepath
        """
        export_path = self._resolve_export_path(filepath)
        
        # ✅ FIX: Encrypt data before export
        data = {
            'user_id': user_id,
            'exported_at': datetime.utcnow().isoformat(),
            'version': '2.0',  # Encrypted format version
        }
        export_salt = self.crypto.generate_salt()
        export_key = self._derive_export_key(master_password, export_salt)
        data['kdf'] = 'argon2id'
        data['kdf_salt'] = export_salt.hex()
        
        # Encrypt each entry
        encrypted_entries = []
        for entry in entries:
            # Convert to JSON and encrypt
            entry_json = json.dumps(entry).encode()
            encrypted = self.crypto.encrypt(entry_json, export_key)
            encrypted_entries.append(encrypted.hex())
        
        data['entries'] = encrypted_entries
        
        # Write encrypted data
        with open(export_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return True
    
    def export_to_csv(
        self,
        user_id: int,
        entries: List[Dict],
        filepath: str
    ) -> bool:
        """
        Export entries to CSV.
        
        ⚠️ WARNING: CSV cannot be encrypted, use JSON for secure export
        """
        export_path = self._resolve_export_path(filepath)
        
        with open(export_path, 'w', newline='') as f:
            writer = csv.writer(f)
            writer.writerow(['id', 'title', 'username', 'url', 'notes'])
            # ✅ FIX: Don't export passwords to CSV
            
            for entry in entries:
                writer.writerow([
                    entry.get('id'),
                    entry.get('title'),
                    entry.get('username'),
                    entry.get('url'),
                    entry.get('notes'),
                ])
        
        return True
    
    def import_from_json(
        self,
        user_id: int,
        filepath: str,
        master_password: str
    ) -> List[ImportEntry]:
        """
        Import entries from JSON file.
        
        ✅ FIX: Validate imported data
        ✅ FIX: Check file size
        ✅ FIX: Validate filepath
        """
        import_path = self._resolve_import_path(filepath)
        
        # ✅ FIX: Check file size
        file_size_mb = os.path.getsize(import_path) / (1024 * 1024)
        if file_size_mb > self.MAX_FILE_SIZE_MB:
            raise ValueError(f"File too large (max {self.MAX_FILE_SIZE_MB}MB)")
        
        with open(import_path, 'r') as f:
            data = json.load(f)
        
        # ✅ FIX: Validate data structure
        if not isinstance(data, dict):
            raise ValueError("Invalid import format")
        
        entries_data = data.get('entries', [])
        
        # ✅ FIX: Check entry count limit
        if len(entries_data) > self.MAX_IMPORT_ENTRIES:
            raise ValueError(
                f"Too many entries (max {self.MAX_IMPORT_ENTRIES})"
            )
        
        # ✅ FIX: Validate and parse each entry
        validated_entries = []
        file_version = data.get('version')
        kdf_salt_hex = data.get('kdf_salt')
        import_key = self.crypto_key
        if file_version == '2.0' and isinstance(kdf_salt_hex, str):
            import_salt = bytes.fromhex(kdf_salt_hex)
            import_key = self._derive_export_key(master_password, import_salt)
        for i, entry_data in enumerate(entries_data):
            try:
                # Decrypt if encrypted
                if isinstance(entry_data, str):
                    # Hex-encoded encrypted data
                    encrypted = bytes.fromhex(entry_data)
                    decrypted = self.crypto.decrypt(encrypted, import_key)
                    entry_data = json.loads(decrypted.decode())
                
                # Validate against schema
                entry = ImportEntry(**entry_data)
                validated_entries.append(entry)
                
            except ValidationError as e:
                raise ValueError(f"Invalid entry at index {i}: {e}")
            except Exception as e:
                raise ValueError(f"Failed to process entry {i}: {e}")
        
        return validated_entries
    
    def import_from_csv(
        self,
        user_id: int,
        filepath: str
    ) -> List[ImportEntry]:
        """
        Import entries from CSV file.
        
        ✅ FIX: Validate imported data
        ✅ FIX: Check file size
        """
        import_path = self._resolve_import_path(filepath)
        
        # ✅ FIX: Check file size
        file_size_mb = os.path.getsize(import_path) / (1024 * 1024)
        if file_size_mb > self.MAX_FILE_SIZE_MB:
            raise ValueError(f"File too large (max {self.MAX_FILE_SIZE_MB}MB)")
        
        entries = []
        with open(import_path, 'r') as f:
            reader = csv.DictReader(f)
            for i, row in enumerate(reader):
                # ✅ FIX: Validate each row
                if i >= self.MAX_IMPORT_ENTRIES:
                    raise ValueError(
                        f"Too many entries (max {self.MAX_IMPORT_ENTRIES})"
                    )
                
                try:
                    entry = ImportEntry(
                        title=row.get('title', ''),
                        username=row.get('username'),
                        password=row.get('password', ''),
                        url=row.get('url'),
                        notes=row.get('notes')
                    )
                    entries.append(entry)
                except ValidationError as e:
                    raise ValueError(f"Invalid row {i}: {e}")
        
        return entries
    
    def cleanup_temp_files(self, temp_dir: str) -> int:
        """
        Clean up temporary export files.
        
        ✅ FIX: Prevent path traversal
        ✅ FIX: Only delete specific file types
        """
        requested_temp = pathlib.Path(temp_dir).expanduser()
        if requested_temp.is_absolute():
            temp_candidate = requested_temp
        else:
            temp_candidate = self._temp_dir / requested_temp
        temp_path = self._ensure_path_within_base(
            temp_candidate,
            self._temp_dir,
            "Invalid temp directory",
        )
        if not temp_path.exists():
            return 0
        
        deleted_count = 0
        
        # ✅ FIX: Only delete specific file patterns
        for pattern in ['*.tmp', '*.export', '*.import']:
            for filepath in temp_path.glob(pattern):
                if filepath.is_file():
                    filepath.unlink()
                    deleted_count += 1
        
        return deleted_count

