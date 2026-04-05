# -*- coding: utf-8 -*-
"""
Entry Service - CRUD operations for password entries
"""

from typing import List, Optional, Callable
from datetime import datetime
from sqlalchemy.orm import Session
from sqlalchemy import select, and_, update

from backend.core.audit_logger import AuditLogger, EventType
from backend.core.encryption_helper import EncryptionHelper, EntryFieldsRaw
from .models import PasswordEntry

class EntryService:
    """Service for password entry CRUD operations."""
    
    def __init__(self, db_session: Session, key_provider: Callable[[], bytearray | bytes]):
        """
        Initialize entry service.
        
        Args:
            db_session: SQLAlchemy session
            key_provider: Callable that returns current master key material.
        """
        if not callable(key_provider):
            raise TypeError("key_provider must be callable and return bytes/bytearray")

        self.db = db_session
        self.enc_helper = EncryptionHelper(key_provider)
        self.audit = AuditLogger(self.db)

    @classmethod
    def from_auth_manager(cls, db_session: Session, auth_manager: object) -> "EntryService":
        """
        Build service from auth manager without storing master key in service/helper.

        `auth_manager` must expose callable `get_master_key() -> bytearray`.
        """
        get_key = getattr(auth_manager, "get_master_key", None)
        if not callable(get_key):
            raise TypeError("auth_manager must provide callable get_master_key()")
        return cls(db_session=db_session, key_provider=get_key)

    def close(self) -> None:
        """Reserved for lifecycle symmetry; no key material is stored in service."""
        return None
    
    def create_entry(
        self,
        user_id: int,
        title: str,
        password: str,
        username: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> PasswordEntry:
        """Create a new password entry."""
        
        raw_fields = EntryFieldsRaw(
            title=title,
            password=password,
            username=username,
            url=url,
            notes=notes
        )
        
        encrypted = self.enc_helper.encrypt_entry_fields(raw_fields)
        
        entry = PasswordEntry(
            user_id=user_id,
            title_cipher=encrypted.title_cipher,
            username_cipher=encrypted.username_cipher,
            password_cipher=encrypted.password_cipher,
            url_cipher=encrypted.url_cipher,
            notes_cipher=encrypted.notes_cipher,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        
        self.db.add(entry)
        self.db.commit()
        self.db.refresh(entry)
        
        self.audit.log_event(
            event_type=EventType.DATA_CREATED,
            user_id=str(user_id),
            details={"entry_id": entry.id, "action": "create"}
        )
        
        return entry
    
    def get_entries(self, user_id: int) -> List[PasswordEntry]:
        """Get all active (not deleted) entries for a user."""
        stmt = select(PasswordEntry).where(
            and_(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False
            )
        )
        results = self.db.execute(stmt).scalars().all()
        return list(results)
    
    def get_entry_by_id(self, entry_id: int, user_id: int) -> Optional[PasswordEntry]:
        """Get entry by ID with access control."""
        stmt = select(PasswordEntry).where(
            and_(
                PasswordEntry.id == entry_id,
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False
            )
        )
        result = self.db.execute(stmt).scalar()
        
        if result:
            self.audit.log_event(
                event_type=EventType.DATA_READ,
                user_id=str(user_id),
                details={"entry_id": entry_id, "action": "read"}
            )
        
        return result
    
    def search_entries(self, user_id: int, search_term: str) -> List[PasswordEntry]:
        """
        Search entries by title securely.
        Uses in-memory decryption to perform substring match without leaking data.
        """
        stmt = select(PasswordEntry).where(
            and_(
                PasswordEntry.user_id == user_id,
                PasswordEntry.is_deleted == False
            )
        )
        
        # In highly loaded apps, we should chunk the results (e.g., yield_per(100)).
        # But for normal vaults, reading all active elements is perfectly feasible.
        entries = self.db.execute(stmt).scalars().all()
        
        matched_entries = []
        search_lower = search_term.lower()
        
        for entry in entries:
            try:
                decrypted_title = self.enc_helper.decrypt_title_cipher(entry.title_cipher)
                if search_lower in decrypted_title.lower():
                    matched_entries.append(entry)
            except Exception:
                # If decryption fails, skip (e.g. tampered data)
                continue
                
        self.audit.log_event(
            event_type=EventType.DATA_READ,
            user_id=str(user_id),
            details={"action": "search", "search_term_length": len(search_term), "results_count": len(matched_entries)}
        )
        
        return matched_entries
    
    def delete_entry(self, entry_id: int, user_id: int) -> bool:
        """
        Soft-delete an entry.
        """
        entry = self.get_entry_by_id(entry_id, user_id)
        if not entry:
            return False
            
        entry.is_deleted = True
        entry.deleted_at = datetime.utcnow()
        entry.updated_at = datetime.utcnow()
        
        self.db.commit()
        
        self.audit.log_event(
            event_type=EventType.DATA_DELETED,
            user_id=str(user_id),
            details={"entry_id": entry_id, "action": "soft_delete"}
        )
        
        return True
    
    def update_entry(
        self,
        entry_id: int,
        user_id: int,
        title: Optional[str] = None,
        password: Optional[str] = None,
        username: Optional[str] = None,
        url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Optional[PasswordEntry]:
        """Update an entry."""
        entry = self.get_entry_by_id(entry_id, user_id)
        if not entry:
            return None
            
        # First, decrypt existing to merge
        existing = self.decrypt_entry(entry)
        
        # Merge changes
        merged = EntryFieldsRaw(
            title=title if title is not None else existing.title,
            password=password if password is not None else existing.password,
            username=username if username is not None else existing.username,
            url=url if url is not None else existing.url,
            notes=notes if notes is not None else existing.notes,
        )
        
        encrypted = self.enc_helper.encrypt_entry_fields(merged)
        
        entry.title_cipher = encrypted.title_cipher
        entry.password_cipher = encrypted.password_cipher
        entry.username_cipher = encrypted.username_cipher
        entry.url_cipher = encrypted.url_cipher
        entry.notes_cipher = encrypted.notes_cipher
        entry.updated_at = datetime.utcnow()
        
        self.db.commit()
        self.db.refresh(entry)
        
        self.audit.log_event(
            event_type=EventType.DATA_UPDATED,
            user_id=str(user_id),
            details={"entry_id": entry_id, "action": "update"}
        )
        
        return entry
    
    def decrypt_entry(self, entry: PasswordEntry) -> EntryFieldsRaw:
        """
        Decrypt entry fields.
        Returns a Pydantic model with plaintext data.
        """
        from backend.core.encryption_helper import EntryFieldsEncrypted
        
        encrypted = EntryFieldsEncrypted(
            title_cipher=entry.title_cipher,
            password_cipher=entry.password_cipher,
            username_cipher=entry.username_cipher,
            url_cipher=entry.url_cipher,
            notes_cipher=entry.notes_cipher
        )
        
        return self.enc_helper.decrypt_entry_fields(encrypted)
