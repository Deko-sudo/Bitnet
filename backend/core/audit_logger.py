# -*- coding: utf-8 -*-
"""
Audit Logger - Security Event Logging

Provides:
- SQLAlchemy model for audit log
- Pydantic schema with sensitive data validation
- Secure logging without leaking secrets

Author: Nikita (BE1)
Version: 1.0
"""

import re
import json
import logging
from datetime import datetime
from typing import Optional, List, Dict, Any, TYPE_CHECKING
from enum import IntEnum

from sqlalchemy import Column, Integer, String, DateTime, Boolean, Index, Text
from sqlalchemy.orm import Session, declarative_base

from pydantic import BaseModel, Field, field_validator, model_validator

if TYPE_CHECKING:
    from sqlalchemy.orm import Mapped


# =============================================================================
# SQLAlchemy Base
# =============================================================================

Base = declarative_base()


# =============================================================================
# Event Type Enum
# =============================================================================

class EventType(IntEnum):
    """Types of audit events."""
    # Authentication
    LOGIN_ATTEMPT = 1
    LOGIN_SUCCESS = 2
    LOGIN_FAILURE = 3
    LOGOUT = 4
    PASSWORD_CHANGE = 5
    
    # Session
    SESSION_CREATED = 10
    SESSION_DESTROYED = 11
    SESSION_EXPIRED = 12
    
    # Data Operations
    DATA_CREATED = 20
    DATA_READ = 21
    DATA_UPDATED = 22
    DATA_DELETED = 23
    
    # Security
    RATE_LIMIT_EXCEEDED = 30
    ACCOUNT_LOCKED = 31
    ACCOUNT_UNLOCKED = 32
    SUSPICIOUS_ACTIVITY = 33
    
    # System
    SYSTEM_START = 100
    SYSTEM_STOP = 101
    CONFIG_CHANGE = 102
    BACKUP_CREATED = 103


# =============================================================================
# SQLAlchemy Model
# =============================================================================

class AuditLog(Base):  # type: ignore[misc]
    """
    SQLAlchemy model for audit log entries.

    Table: audit_log

    Columns:
        id: Primary key
        timestamp: Event timestamp (UTC)
        event_type: Type of event (integer)
        event_type_name: Human-readable event type name
        user_id: User identifier (nullable)
        ip_address: IP address (nullable)
        success: Whether operation was successful
        details: JSON details (no sensitive data)
        created_at: Record creation timestamp
    """
    
    __tablename__ = 'audit_log'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, nullable=False, index=True)
    event_type = Column(Integer, nullable=False, index=True)
    event_type_name = Column(String(50), nullable=False)
    user_id = Column(String(255), nullable=True, index=True)
    ip_address = Column(String(45), nullable=True)  # IPv6 max length
    success = Column(Boolean, default=True)
    details = Column(Text, nullable=True)  # JSON string
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Indexes for common queries
    __table_args__ = (
        Index('ix_audit_log_timestamp_user', 'timestamp', 'user_id'),
        Index('ix_audit_log_event_success', 'event_type', 'success'),
    )
    
    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, event={self.event_type_name}, user={self.user_id})>"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'event_type': self.event_type,
            'event_type_name': self.event_type_name,
            'user_id': self.user_id,
            'ip_address': self.ip_address,
            'success': self.success,
            'details': json.loads(str(self.details)) if self.details else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# =============================================================================
# Pydantic Schemas
# =============================================================================

class AuditEvent(BaseModel):
    """
    Pydantic schema for audit events.
    
    Validates and sanitizes event data to prevent
    leaking sensitive information.
    
    Attributes:
        event_type: Type of event
        user_id: User identifier
        ip_address: IP address
        success: Whether operation succeeded
        details: Additional event details
    """
    
    event_type: EventType
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    success: bool = True
    details: Optional[Dict[str, Any]] = None
    
    # Patterns that indicate sensitive data (ClassVar to avoid Pydantic field detection)
    SENSITIVE_PATTERNS: list = [
        r'password',
        r'passwd',
        r'secret',
        r'key',
        r'token',
        r'auth',
        r'credential',
        r'private',
    ]
    
    @field_validator('ip_address')
    @classmethod
    def validate_ip(cls, v: Optional[str]) -> Optional[str]:
        """Validate IP address format."""
        if v is None:
            return None
        
        # Simple IPv4/IPv6 validation
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        ipv6_pattern = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$'
        
        if re.match(ipv4_pattern, v) or re.match(ipv6_pattern, v):
            return v
        
        # Allow localhost variations
        if v in ('localhost', '127.0.0.1', '::1'):
            return v
        
        raise ValueError(f"Invalid IP address format: {v}")
    
    @model_validator(mode='after')
    def sanitize_details(self) -> 'AuditEvent':
        """
        Sanitize details to remove sensitive data.

        This validator runs after all other validation.
        """
        if self.details is None:
            return self

        sanitized = self._sanitize_dict(self.details)
        self.details = sanitized  # type: ignore[assignment]
        return self
    
    def _sanitize_dict(self, data: Dict[str, Any], depth: int = 0) -> Dict[str, Any]:
        """
        Recursively sanitize dictionary to remove sensitive data.
        
        Args:
            data: Dictionary to sanitize
            depth: Current recursion depth (prevent infinite loops)
        
        Returns:
            Sanitized dictionary
        """
        if depth > 10:  # Prevent infinite recursion
            return {'_error': 'Max depth exceeded'}
        
        result = {}
        for key, value in data.items():
            # Check if key name suggests sensitive data
            if self._is_sensitive_key(key):
                result[key] = '[REDACTED]'
            elif isinstance(value, dict):
                result[key] = self._sanitize_dict(value, depth + 1)
            elif isinstance(value, str):
                # Check if value looks like a secret
                if self._is_sensitive_value(value):
                    result[key] = '[REDACTED]'
                else:
                    result[key] = value
            else:
                result[key] = value
        
        return result
    
    def _is_sensitive_key(self, key: str) -> bool:
        """Check if key name suggests sensitive data."""
        key_lower = key.lower()
        return any(pattern in key_lower for pattern in self.SENSITIVE_PATTERNS)
    
    def _is_sensitive_value(self, value: str) -> bool:
        """
        Check if value looks like a secret.
        
        Checks for:
        - Long random-looking strings (potential tokens/keys)
        - Base64-encoded data
        - Very long passwords
        """
        if len(value) < 16:
            return False
        
        # Check for base64-like patterns
        base64_pattern = r'^[A-Za-z0-9+/=]{20,}$'
        if re.match(base64_pattern, value):
            return True
        
        # Check for high entropy (random-looking) strings
        unique_chars = len(set(value))
        if unique_chars > 20 and len(value) > 30:
            return True
        
        return False
    
    def to_audit_log(self) -> AuditLog:
        """
        Convert to SQLAlchemy AuditLog model.
        
        Returns:
            AuditLog instance
        """
        return AuditLog(
            timestamp=datetime.utcnow(),
            event_type=self.event_type.value,
            event_type_name=self.event_type.name,
            user_id=self.user_id,
            ip_address=self.ip_address,
            success=self.success,
            details=json.dumps(self.details) if self.details else None,
        )


# =============================================================================
# AuditLogger Class
# =============================================================================

class AuditLogger:
    """
    Audit Logger - logs security events to database.
    
    Features:
    - Validates and sanitizes all event data
    - Blocks sensitive data from being logged
    - Thread-safe database operations
    - Isolated transactions (no rollback with main transaction)
    
    Example:
        >>> logger = AuditLogger(session)
        >>> logger.log_event(
        ...     event_type=EventType.LOGIN_ATTEMPT,
        ...     user_id="user123",
        ...     ip_address="192.168.1.1",
        ...     success=True
        ... )
    """
    
    def __init__(self, session: Session, logger: Optional[logging.Logger] = None):
        """
        Initialize AuditLogger.
        
        Args:
            session: SQLAlchemy session
            logger: Optional Python logger for console output
        """
        self._session = session
        self._logger = logger or logging.getLogger(__name__)
    
    def log_event(
        self,
        event_type: EventType,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        success: bool = True,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """
        Log a security event.
        
        Args:
            event_type: Type of event
            user_id: User identifier
            ip_address: IP address
            success: Whether operation succeeded
            details: Additional details (will be sanitized)
        
        Returns:
            Created AuditLog entry
        
        Raises:
            ValueError: If event data is invalid
        
        Example:
            >>> logger.log_event(
            ...     EventType.LOGIN_SUCCESS,
            ...     user_id="user123",
            ...     ip_address="192.168.1.1"
            ... )
        """
        try:
            # Create and validate event
            event = AuditEvent(
                event_type=event_type,
                user_id=user_id,
                ip_address=ip_address,
                success=success,
                details=details,
            )
            
            # Convert to model
            audit_log = event.to_audit_log()
            
            # Commit in isolated transaction using a dedicated session,
            # so audit failures never rollback business data in caller session.
            bind = self._session.get_bind()
            if bind is None:
                raise RuntimeError("Audit logger database bind is not available")
            try:
                with Session(bind=bind) as audit_session:
                    audit_session.add(audit_log)
                    audit_session.commit()
            except Exception as e:
                # Do not touch caller session state on audit write failures.
                self._logger.error(f"Failed to commit audit log: {e}")
            
            # Log to console/file
            self._log_to_console(audit_log)
            
            return audit_log
            
        except Exception as e:
            # Log error but don't propagate
            self._logger.error(f"Failed to log audit event: {e}")
            raise
    
    def get_log(
        self,
        limit: int = 100,
        event_type: Optional[EventType] = None,
        user_id: Optional[str] = None,
        success: Optional[bool] = None,
    ) -> List[AuditLog]:
        """
        Retrieve audit log entries.
        
        Args:
            limit: Maximum number of entries to return
            event_type: Filter by event type
            user_id: Filter by user ID
            success: Filter by success status
        
        Returns:
            List of AuditLog entries
        
        Example:
            >>> entries = logger.get_log(limit=50, user_id="user123")
            >>> for entry in entries:
            ...     print(f"{entry.timestamp}: {entry.event_type_name}")
        """
        query = self._session.query(AuditLog)
        
        if event_type is not None:
            query = query.filter(AuditLog.event_type == event_type.value)
        
        if user_id is not None:
            query = query.filter(AuditLog.user_id == user_id)
        
        if success is not None:
            query = query.filter(AuditLog.success == success)
        
        # Order by timestamp descending (newest first)
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Limit results
        return query.limit(limit).all()
    
    def _log_to_console(self, audit_log: AuditLog) -> None:
        """Log event to console/logger."""
        level = logging.INFO if audit_log.success else logging.WARNING
        
        message = (
            f"[AUDIT] {audit_log.event_type_name} | "
            f"user={audit_log.user_id or 'N/A'} | "
            f"ip={audit_log.ip_address or 'N/A'} | "
            f"success={audit_log.success}"
        )
        
        self._logger.log(level, message)
    
    def clear_old_entries(
        self,
        days_to_keep: int = 90,
    ) -> int:
        """
        Clear old audit log entries.
        
        Args:
            days_to_keep: Number of days to retain
        
        Returns:
            Number of entries deleted
        """
        from datetime import timedelta
        
        cutoff_date = datetime.utcnow() - timedelta(days=days_to_keep)
        
        deleted = self._session.query(AuditLog).filter(
            AuditLog.timestamp < cutoff_date
        ).delete(synchronize_session=False)
        
        self._session.commit()
        
        self._logger.info(f"Cleared {deleted} audit log entries older than {days_to_keep} days")
        
        return deleted


# =============================================================================
# Convenience Functions
# =============================================================================

def log_login_attempt(
    session: Session,
    user_id: str,
    ip_address: str,
    success: bool,
) -> AuditLog:
    """
    Log a login attempt.
    
    Args:
        session: SQLAlchemy session
        user_id: User identifier
        ip_address: IP address
        success: Whether login succeeded
    
    Returns:
        AuditLog entry
    """
    logger = AuditLogger(session)
    
    event_type = EventType.LOGIN_SUCCESS if success else EventType.LOGIN_FAILURE
    
    return logger.log_event(
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        success=success,
    )


def log_data_access(
    session: Session,
    user_id: str,
    action: str,  # 'create', 'read', 'update', 'delete'
    resource_type: str,
    resource_id: str,
    success: bool = True,
) -> AuditLog:
    """
    Log data access event.
    
    Args:
        session: SQLAlchemy session
        user_id: User identifier
        action: Action performed
        resource_type: Type of resource accessed
        resource_id: ID of accessed resource
        success: Whether operation succeeded
    
    Returns:
        AuditLog entry
    """
    logger = AuditLogger(session)
    
    action_map = {
        'create': EventType.DATA_CREATED,
        'read': EventType.DATA_READ,
        'update': EventType.DATA_UPDATED,
        'delete': EventType.DATA_DELETED,
    }
    
    event_type = action_map.get(action.lower(), EventType.DATA_READ)
    
    return logger.log_event(
        event_type=event_type,
        user_id=user_id,
        success=success,
        details={
            'resource_type': resource_type,
            'resource_id': resource_id,
            'action': action,
        },
    )


def log_security_event(
    session: Session,
    event_type: EventType,
    user_id: str,
    ip_address: str,
    details: Optional[Dict[str, Any]] = None,
) -> AuditLog:
    """
    Log a security-related event.
    
    Args:
        session: SQLAlchemy session
        event_type: Type of security event
        user_id: User identifier
        ip_address: IP address
        details: Additional details
    
    Returns:
        AuditLog entry
    """
    logger = AuditLogger(session)
    
    return logger.log_event(
        event_type=event_type,
        user_id=user_id,
        ip_address=ip_address,
        success=True,
        details=details,
    )


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # SQLAlchemy
    'Base',
    'AuditLog',
    
    # Enums
    'EventType',
    
    # Pydantic
    'AuditEvent',
    
    # Main class
    'AuditLogger',
    
    # Convenience functions
    'log_login_attempt',
    'log_data_access',
    'log_security_event',
]
