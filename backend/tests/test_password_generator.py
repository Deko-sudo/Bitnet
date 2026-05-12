# -*- coding: utf-8 -*-
"""
Tests for backend.features.password_generator and backend.api.v1.endpoints.generator.

Coverage target: >90% of password_generator.py.
"""
from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import SecretStr
from unittest.mock import patch

from backend.api.v1.endpoints import generator as generator_router
from backend.core.security_utils import PasswordStrength
from backend.features.password_generator import (
    PasswordGenerator,
    PasswordGeneratorConfig,
    PassphraseGeneratorConfig,
    PINGeneratorConfig,
    PasswordResult,
    _build_charset,
    _generate_password,
    _generate_passphrase,
    _generate_pin,
    _GeneratorError,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_test_client() -> TestClient:
    app = FastAPI()
    app.include_router(generator_router.router, prefix="/api/v1/generator")
    return TestClient(app)


# ---------------------------------------------------------------------------
# _build_charset
# ---------------------------------------------------------------------------

class TestBuildCharset:
    def test_default_charset(self) -> None:
        cfg = PasswordGeneratorConfig()
        charset = _build_charset(cfg)
        assert b"a" in charset
        assert b"A" in charset
        assert b"0" in charset
        assert b"!" in charset
        assert b"z" in charset

    def test_lowercase_only(self) -> None:
        cfg = PasswordGeneratorConfig(
            use_uppercase=False, use_numbers=False, use_special=False
        )
        charset = _build_charset(cfg)
        assert charset == bytearray(b"abcdefghijklmnopqrstuvwxyz")

    def test_exclude_similar(self) -> None:
        cfg = PasswordGeneratorConfig(exclude_similar=True)
        charset = _build_charset(cfg)
        for bad in b"il1Lo0O":
            assert bad not in charset

    def test_empty_charset_after_exclusion(self) -> None:
        """
        exclude_similar=True never empties the base charset (26 lowercase
        letters) so this verifies the function does NOT raise when only
        lowercase is present.
        """
        cfg = PasswordGeneratorConfig(
            use_uppercase=False, use_numbers=False, use_special=False, exclude_similar=True,
        )
        charset = _build_charset(cfg)
        # Similar set (il1Lo0O) intersects with lowercase, but still leaves many chars
        assert len(charset) > 0


# ---------------------------------------------------------------------------
# _generate_password
# ---------------------------------------------------------------------------

class TestGeneratePassword:
    def test_length_and_charset(self) -> None:
        cfg = PasswordGeneratorConfig(length=24)
        result = _generate_password(cfg)
        raw = result.value.get_secret_value()
        assert len(raw) == 24

    def test_minimum_length(self) -> None:
        cfg = PasswordGeneratorConfig(length=8)
        result = _generate_password(cfg)
        raw = result.value.get_secret_value()
        assert len(raw) == 8

    def test_ensure_strength_good(self) -> None:
        """When ensure_strength=True and min_strength=GOOD, result must meet it."""
        cfg = PasswordGeneratorConfig(
            length=24,
            ensure_strength=True,
            min_strength=PasswordStrength.GOOD,
        )
        result = _generate_password(cfg)
        assert result.strength >= PasswordStrength.GOOD

    def test_ensure_strength_fair(self) -> None:
        cfg = PasswordGeneratorConfig(
            length=12,
            ensure_strength=True,
            min_strength=PasswordStrength.FAIR,
        )
        result = _generate_password(cfg)
        assert result.strength >= PasswordStrength.FAIR

    def test_returns_secretstr(self) -> None:
        cfg = PasswordGeneratorConfig()
        result = _generate_password(cfg)
        assert isinstance(result.value, SecretStr)
        assert isinstance(result.strength, PasswordStrength)
        assert isinstance(result.entropy_bits, float)
        assert result.entropy_bits > 0.0

    def test_zero_memory_called(self) -> None:
        with patch("backend.features.password_generator.zero_memory") as mock_zero:
            cfg = PasswordGeneratorConfig(length=12)
            _generate_password(cfg)
            assert mock_zero.call_count >= 2  # buf + charset


# ---------------------------------------------------------------------------
# _generate_passphrase
# ---------------------------------------------------------------------------

class TestGeneratePassphrase:
    def test_default_word_count(self) -> None:
        cfg = PassphraseGeneratorConfig()
        result = _generate_passphrase(cfg)
        raw = result.value.get_secret_value()
        parts = raw.split("-")
        # Default word_count=6 + include_number=True adds one numeric token
        assert len(parts) == 7

    def test_no_number(self) -> None:
        cfg = PassphraseGeneratorConfig(include_number=False)
        result = _generate_passphrase(cfg)
        raw = result.value.get_secret_value()
        parts = raw.split("-")
        assert len(parts) == 6
        assert all(not p.isdigit() for p in parts)

    def test_custom_separator(self) -> None:
        cfg = PassphraseGeneratorConfig(word_separator=" ", include_number=False)
        result = _generate_passphrase(cfg)
        raw = result.value.get_secret_value()
        parts = raw.split(" ")
        assert len(parts) == 6

    def test_strength_assessment_present(self) -> None:
        cfg = PassphraseGeneratorConfig()
        result = _generate_passphrase(cfg)
        assert isinstance(result.strength, PasswordStrength)
        assert result.entropy_bits > 0.0


# ---------------------------------------------------------------------------
# _generate_pin
# ---------------------------------------------------------------------------

class TestGeneratePIN:
    def test_default_length(self) -> None:
        cfg = PINGeneratorConfig()
        result = _generate_pin(cfg)
        raw = result.value.get_secret_value()
        assert len(raw) == 6
        assert raw.isdigit()

    def test_custom_length(self) -> None:
        cfg = PINGeneratorConfig(length=4)
        result = _generate_pin(cfg)
        raw = result.value.get_secret_value()
        assert len(raw) == 4
        assert raw.isdigit()

    def test_always_weak(self) -> None:
        cfg = PINGeneratorConfig(length=12)
        result = _generate_pin(cfg)
        assert result.strength == PasswordStrength.WEAK
        assert result.entropy_bits > 0.0

    def test_zero_memory_called(self) -> None:
        with patch("backend.features.password_generator.zero_memory") as mock_zero:
            cfg = PINGeneratorConfig(length=4)
            _generate_pin(cfg)
            assert mock_zero.call_count >= 1


# ---------------------------------------------------------------------------
# PasswordGenerator (public entry point)
# ---------------------------------------------------------------------------

class TestPasswordGeneratorEntryPoint:
    def test_generate_password_count(self) -> None:
        gen = PasswordGenerator()
        cfg = PasswordGeneratorConfig(count=3)
        results = gen.generate_password(cfg)
        assert len(results) == 3
        for r in results:
            assert isinstance(r, PasswordResult)
            assert len(r.value.get_secret_value()) == 16

    def test_generate_passphrase_count(self) -> None:
        gen = PasswordGenerator()
        cfg = PassphraseGeneratorConfig(count=2)
        results = gen.generate_passphrase(cfg)
        assert len(results) == 2
        for r in results:
            assert isinstance(r, PasswordResult)

    def test_generate_pin_count(self) -> None:
        gen = PasswordGenerator()
        cfg = PINGeneratorConfig(count=5)
        results = gen.generate_pin(cfg)
        assert len(results) == 5
        for r in results:
            assert isinstance(r, PasswordResult)
            assert len(r.value.get_secret_value()) == 6
            assert r.strength == PasswordStrength.WEAK


# ---------------------------------------------------------------------------
# API endpoints
# ---------------------------------------------------------------------------

class TestGeneratorAPI:
    @pytest.fixture(scope="class")
    def client(self) -> TestClient:
        return _make_test_client()

    def test_post_password(self, client: TestClient) -> None:
        payload = {
            "length": 12,
            "count": 2,
            "use_uppercase": True,
            "use_numbers": True,
            "use_special": True,
            "exclude_similar": False,
            "ensure_strength": False,
        }
        resp = client.post("/api/v1/generator/password", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        for item in data:
            assert "value" in item
            assert "strength" in item
            assert "entropy_bits" in item
            # SecretStr serialises as plain string in Pydantic v2 by default
            assert isinstance(item["value"], str)
            assert len(item["value"]) == 12

    def test_post_password_with_min_strength(self, client: TestClient) -> None:
        payload = {
            "length": 24,
            "min_strength": "FAIR",
            "ensure_strength": True,
        }
        resp = client.post("/api/v1/generator/password", json=payload)
        assert resp.status_code == 200, resp.text
        data = resp.json()
        assert len(data) == 1
        assert data[0]["strength"] >= PasswordStrength.FAIR

    def test_post_passphrase(self, client: TestClient) -> None:
        payload = {
            "word_count": 5,
            "word_separator": "-",
            "include_number": True,
            "count": 1,
        }
        resp = client.post("/api/v1/generator/passphrase", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        parts = data[0]["value"].split("-")
        assert len(parts) == 6  # 5 words + number

    def test_post_pin(self, client: TestClient) -> None:
        payload = {"length": 4, "count": 3}
        resp = client.post("/api/v1/generator/pin", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        for item in data:
            assert item["value"].isdigit()
            assert len(item["value"]) == 4
            assert item["strength"] == PasswordStrength.WEAK


    def test_password_invalid_length(self, client: TestClient) -> None:
        payload = {"length": 3}  # below ge=8
        resp = client.post("/api/v1/generator/password", json=payload)
        assert resp.status_code == 422

    def test_passphrase_invalid_word_count(self, client: TestClient) -> None:
        payload = {"word_count": 2}  # below ge=4
        resp = client.post("/api/v1/generator/passphrase", json=payload)
        assert resp.status_code == 422

    def test_pin_invalid_length(self, client: TestClient) -> None:
        payload = {"length": 2}  # below ge=4
        resp = client.post("/api/v1/generator/pin", json=payload)
        assert resp.status_code == 422

    def test_password_empty_charset_returns_ok(self, client: TestClient) -> None:
        """
        exclude_similar=True with only lowercase does not raise; the charset
    
        exclude_similar=True with only lowercase does not raise; the charset
        still contains many non-similar characters.  The endpoint returns 200.
        """
        payload = {
            "length": 12,
            "use_uppercase": False,
            "use_numbers": False,
            "use_special": False,
            "exclude_similar": True,
        }
        resp = client.post("/api/v1/generator/password", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert len(data[0]["value"]) == 12

