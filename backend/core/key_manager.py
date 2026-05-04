# -*- coding: utf-8 -*-
"""
Key Manager — Key splitting and lifecycle management.
Strict adherence to zero-leak principles.
"""

import ctypes

from .secure_heap import SecureMemoryBuffer


def xor_inplace(dst: SecureMemoryBuffer, a: SecureMemoryBuffer, b: SecureMemoryBuffer):
    size = a.size
    pa = ctypes.cast(a.ptr, ctypes.POINTER(ctypes.c_uint8))
    pb = ctypes.cast(b.ptr, ctypes.POINTER(ctypes.c_uint8))
    pd = ctypes.cast(dst.ptr, ctypes.POINTER(ctypes.c_uint8))
    for i in range(size):
        pd[i] = pa[i] ^ pb[i]


class KeySplitter:
    def __init__(self, buf_a: SecureMemoryBuffer, buf_b: SecureMemoryBuffer):
        assert buf_a.size == buf_b.size
        self.buf_a = buf_a
        self.buf_b = buf_b
        self._combined = None
        self._freed = False

    def __enter__(self) -> SecureMemoryBuffer:
        if self._freed:
            raise RuntimeError("KeySplitter already used and freed")
        self._combined = SecureMemoryBuffer(self.buf_a.size)
        xor_inplace(self._combined, self.buf_a, self.buf_b)
        return self._combined

    def __exit__(self, exc_type, exc, tb):
        if self._combined and not self._freed:
            self._combined.zero()
            self._combined.free()
            self._combined = None
            self._freed = True
