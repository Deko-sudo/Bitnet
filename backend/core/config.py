# -*- coding: utf-8 -*-
"""Security Configuration via Pydantic"""

from pydantic import BaseModel, Field, field_validator
from typing import Literal
from functools import lru_cache


class CryptoConfig(BaseModel):
    """Cryptographic parameters configuration."""

    key_size: int = Field(default=32, ge=16, le=64)
    nonce_size: int = Field(default=12, ge=12, le=16)
    tag_size: int = Field(default=16, ge=12, le=16)

    argon2_time_cost: int = Field(default=3, ge=1)
    argon2_memory_cost: int = Field(default=65536, ge=1024)
    argon2_parallelism: int = Field(default=4, ge=1)
    argon2_hash_len: int = Field(default=32, ge=16)
    argon2_salt_len: int = Field(default=16, ge=8)
    argon2_type: Literal["i", "d", "id"] = "id"

    hmac_algorithm: Literal["sha256", "sha384", "sha512"] = "sha256"

    auto_lock_timeout: int = Field(default=300, ge=60)
    max_login_attempts: int = Field(default=5, ge=3)
    rate_limit_window: int = Field(default=60, ge=30)

    @field_validator("argon2_memory_cost")
    @classmethod
    def validate_memory_cost(cls, v: int) -> int:
        if v < 65536:
            raise ValueError("argon2_memory_cost must be >= 65536 (64 MB)")
        return v

    @property
    def key_size_bits(self) -> int:
        return self.key_size * 8

    @property
    def memory_cost_mb(self) -> int:
        return self.argon2_memory_cost // 1024

    class Config:
        frozen = True
        extra = "forbid"


class RateLimitConfig(BaseModel):
    """Rate limiting configuration."""
    max_attempts: int = Field(default=5, ge=1)
    window_seconds: int = Field(default=60, ge=1)
    block_duration_seconds: int = Field(default=1800, ge=60)

    class Config:
        frozen = True


class PasswordStrengthConfig(BaseModel):
    """Password strength requirements."""
    min_length: int = Field(default=12, ge=8)
    min_entropy_bits: float = Field(default=60.0, ge=40.0)
    require_uppercase: bool = True
    require_lowercase: bool = True
    require_digits: bool = True

    class Config:
        frozen = True


@lru_cache()
def get_crypto_config() -> CryptoConfig:
    return CryptoConfig()


@lru_cache()
def get_rate_limit_config() -> RateLimitConfig:
    return RateLimitConfig()


@lru_cache()
def get_password_strength_config() -> PasswordStrengthConfig:
    return PasswordStrengthConfig()
