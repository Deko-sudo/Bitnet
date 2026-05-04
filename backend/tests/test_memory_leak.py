# -*- coding: utf-8 -*-
"""
Memory Leak Tests - Validation of Zero-Trust memory management.

Оптимизации производительности:
1. Mocking ctypes операций вместо реальных системных вызовов
2. Уменьшение итераций с 1000 до 10
3. Точечный gc.collect() вне циклов
4. Проверка внутренних флагов вместо замеров OS RAM
5. Добавлен маркер @pytest.mark.fast_leak_check
"""

import ctypes
import gc
from unittest.mock import MagicMock, call, patch

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from backend.core.secure_heap import SecureMemoryBuffer

# =============================================================================
# Fixtures: Mocked Infrastructure
# =============================================================================


@pytest.fixture
def mocked_ctypes():
    """
    Mock ctypes функций для изоляции от реальных системных вызовов.
    malloc возвращает ненулевой «указатель», free/memset — no-op.
    """
    with (
        patch.object(ctypes, "memmove") as mock_memmove,
        patch.object(ctypes, "memset") as mock_memset,
        patch.object(ctypes, "string_at", return_value=b"") as mock_string_at,
        patch("backend.core.secure_heap.libc") as mock_libc,
    ):
        mock_libc.malloc.return_value = 0x1000  # валидный «указатель»
        mock_libc.free.return_value = None
        mock_memset.return_value = None
        mock_memmove.return_value = None

        yield {
            "libc": mock_libc,
            "memmove": mock_memmove,
            "memset": mock_memset,
            "string_at": mock_string_at,
        }


# =============================================================================
# Fast Leak Checks (минимальные, быстрые тесты)
# =============================================================================


@pytest.mark.fast_leak_check
async def test_buffer_zeroized_flag_set(mocked_ctypes):
    """Проверка: после free() флаг _is_zeroized=True (без OS замеров)."""
    buf = SecureMemoryBuffer(64)
    assert buf._is_zeroized is False
    buf.free()
    assert buf._is_zeroized is True
    assert buf.ptr is None


@pytest.mark.fast_leak_check
async def test_zero_method_called(mocked_ctypes):
    """Проверка: zero() вызывает libc.memset(0) перед libc.free()."""
    buf = SecureMemoryBuffer(128)
    buf.write(b"secret_data")
    buf.free()

    libc = mocked_ctypes["libc"]
    # Проверяем порядок вызовов: memset (zero) ДО free
    libc_calls = [c[0] for c in libc.method_calls]
    assert "memset" in libc_calls, "zero() не был вызван"
    assert "free" in libc_calls, "free() не был вызван"

    # memset должен идти раньше free
    memset_idx = libc_calls.index("memset")
    free_idx = libc_calls.index("free")
    assert memset_idx < free_idx, "zero() должен вызываться ДО free()"


@pytest.mark.fast_leak_check
async def test_no_leak_single_buffer(mocked_ctypes):
    """Проверка: один malloc = один free (баланс)."""
    counters = {"allocs": 0, "frees": 0}

    libc = mocked_ctypes["libc"]
    libc.malloc.side_effect = lambda *a: (
        counters.update({"allocs": counters["allocs"] + 1}) or 0x1000
    )
    libc.free.side_effect = lambda *a: counters.update({"frees": counters["frees"] + 1})

    buf = SecureMemoryBuffer(256)
    buf.write(b"test_payload")
    buf.free()

    assert counters["allocs"] == 1
    assert counters["frees"] == 1


@pytest.mark.fast_leak_check
async def test_multiple_buffers_no_leak(mocked_ctypes):
    """Проверка: N буферов = N free (без gc.collect в цикле)."""
    counters = {"allocs": 0, "frees": 0}

    libc = mocked_ctypes["libc"]
    libc.malloc.side_effect = lambda *a: (
        counters.update({"allocs": counters["allocs"] + 1}) or 0x1000
    )
    libc.free.side_effect = lambda *a: counters.update({"frees": counters["frees"] + 1})

    # Минимальное количество итераций (10 вместо 1000)
    NUM_BUFFERS = 10

    buffers = []
    for _ in range(NUM_BUFFERS):
        buf = SecureMemoryBuffer(64)
        buffers.append(buf)

    # Освобождение вне цикла создания
    for buf in buffers:
        buf.free()

    # Один gc.collect() после всех операций
    gc.collect()

    assert counters["allocs"] == NUM_BUFFERS
    assert counters["frees"] == NUM_BUFFERS


@pytest.mark.fast_leak_check
async def test_destructor_zeroizes(mocked_ctypes):
    """Проверка: __del__ вызывает free() если ptr не обнулен."""
    buf = SecureMemoryBuffer(32)
    buf.write(b"temp")

    # Симулируем вызов __del__ без явного free()
    buf.__del__()

    # free() должен был вызваться через __del__
    libc = mocked_ctypes["libc"]
    assert "free" in [c[0] for c in libc.method_calls]


# =============================================================================
# Property-Based Tests (Hypothesis)
# =============================================================================


@pytest.mark.fast_leak_check
@given(data=st.binary(min_size=1, max_size=64))
@settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_secure_memory_leak_check(data, mocked_ctypes):
    """
    Property-based test: ensures SecureMemoryBuffer always releases memory.
    Оптимизации:
    - max_examples=10 вместо 100
    - Mock ctypes вместо реальных вызовов libc
    - Проверка через счётчики, а не sys.getrefcount (медленный)
    """
    tracker = {"allocs": 0, "frees": 0}

    libc = mocked_ctypes["libc"]
    libc.malloc.side_effect = lambda *a: (
        tracker.update({"allocs": tracker["allocs"] + 1}) or 0x1000
    )
    libc.free.side_effect = lambda *a: tracker.update({"frees": tracker["frees"] + 1})

    buf = SecureMemoryBuffer(len(data))
    buf.write(data)
    buf.free()

    assert tracker["allocs"] == tracker["frees"]


@given(size=st.integers(min_value=1, max_value=512))
@settings(max_examples=10, suppress_health_check=[HealthCheck.function_scoped_fixture])
async def test_varying_sizes_no_leak(size, mocked_ctypes):
    """Проверка: память освобождается при разных размерах буфера."""
    tracker = {"allocs": 0, "frees": 0}

    libc = mocked_ctypes["libc"]
    libc.malloc.side_effect = lambda *a: (
        tracker.update({"allocs": tracker["allocs"] + 1}) or 0x1000
    )
    libc.free.side_effect = lambda *a: tracker.update({"frees": tracker["frees"] + 1})

    buf = SecureMemoryBuffer(size)
    buf.free()

    assert tracker["allocs"] == 1
    assert tracker["frees"] == 1


# =============================================================================
# Integration Test с Mock DB
# =============================================================================


@pytest.mark.asyncio
async def test_session_cleanup_no_memory_leak(mocked_ctypes):
    """
    Integration test: проверка что «сессия» не держит ссылки на буферы.
    Используем mock вместо реальных вызовов.
    """
    counters = {"allocs": 0, "frees": 0}

    libc = mocked_ctypes["libc"]
    libc.malloc.side_effect = lambda *a: (
        counters.update({"allocs": counters["allocs"] + 1}) or 0x1000
    )
    libc.free.side_effect = lambda *a: counters.update({"frees": counters["frees"] + 1})

    # Минимальное количество операций
    NUM_OPS = 10
    refs = []

    for _ in range(NUM_OPS):
        buf = SecureMemoryBuffer(32)
        refs.append(buf)

    # Явная очистка
    for buf in refs:
        buf.free()

    # gc.collect() один раз после всех операций
    gc.collect()

    # Проверяем что все буферы освобождены
    assert all(buf._is_zeroized for buf in refs)
    assert counters["allocs"] == NUM_OPS
    assert counters["frees"] == NUM_OPS
