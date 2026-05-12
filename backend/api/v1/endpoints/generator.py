# -*- coding: utf-8 -*-
"""
Generator endpoints — Password, Passphrase, PIN generation (Zero-Trust).

No authentication required — this is a public utility endpoint.
All returned secrets are wrapped in ``SecretStr`` and never logged.
"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel

from backend.core.security_utils import PasswordStrength
from backend.features.password_generator import (
    PasswordGenerator,
    PasswordGeneratorConfig,
    PassphraseGeneratorConfig,
    PINGeneratorConfig,
    PasswordResult,
)

router = APIRouter()


class _PasswordResponse(BaseModel):
    """Public response schema with plain string value."""

    value: str
    strength: PasswordStrength
    entropy_bits: float


@router.post("/password", response_model=list[_PasswordResponse], tags=["Generator"])
def generate_password(config: PasswordGeneratorConfig) -> list[_PasswordResponse]:
    """Generate one or more cryptographically secure passwords."""
    try:
        gen = PasswordGenerator()
        results = gen.generate_password(config)
        return [
            _PasswordResponse(
                value=r.value.get_secret_value(),
                strength=r.strength,
                entropy_bits=r.entropy_bits,
            )
            for r in results
        ]
    except ValueError as exc:  # pragma: no cover — config validated by Pydantic
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post("/passphrase", response_model=list[_PasswordResponse], tags=["Generator"])
def generate_passphrase(config: PassphraseGeneratorConfig) -> list[_PasswordResponse]:
    """Generate one or more diceware-style passphrases."""
    try:
        gen = PasswordGenerator()
        results = gen.generate_passphrase(config)
        return [
            _PasswordResponse(
                value=r.value.get_secret_value(),
                strength=r.strength,
                entropy_bits=r.entropy_bits,
            )
            for r in results
        ]
    except ValueError as exc:  # pragma: no cover — config validated by Pydantic
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )


@router.post("/pin", response_model=list[_PasswordResponse], tags=["Generator"])
def generate_pin(config: PINGeneratorConfig) -> list[_PasswordResponse]:
    """Generate one or more numeric PINs."""
    try:
        gen = PasswordGenerator()
        results = gen.generate_pin(config)
        return [
            _PasswordResponse(
                value=r.value.get_secret_value(),
                strength=r.strength,
                entropy_bits=r.entropy_bits,
            )
            for r in results
        ]
    except ValueError as exc:  # pragma: no cover — config validated by Pydantic
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )
