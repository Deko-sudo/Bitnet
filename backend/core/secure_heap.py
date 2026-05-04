# -*- coding: utf-8 -*-
"""
Secure Heap — Managed memory allocation via libc (ctypes).

Provides low-level memory allocation for sensitive data that needs to be
explicitly wiped and protected from CPython Garbage Collector artifacts.
"""

import ctypes
import os
import platform

# Identify libc
if platform.system() == "Windows":
    libc = ctypes.cdll.msvcrt
else:
    libc = ctypes.cdll.LoadLibrary("libc.so.6")


class SecureMemoryBuffer:
    """Buffer managed via libc malloc, guaranteed to be zeroed on free."""

    def __init__(self, size: int):
        self.size = size
        self.ptr = libc.malloc(ctypes.c_size_t(size))
        if not self.ptr:
            raise MemoryError("Failed to allocate secure memory")
        self._is_zeroized = False

    def write(self, data: bytes):
        if len(data) > self.size:
            raise ValueError("Data exceeds buffer size")
        ctypes.memmove(self.ptr, data, len(data))

    def read(self) -> bytes:
        return ctypes.string_at(self.ptr, self.size)

    def zero(self):
        libc.memset(self.ptr, 0, ctypes.c_size_t(self.size))

    def free(self):
        self.zero()
        libc.free(self.ptr)
        self._is_zeroized = True
        self.ptr = None

    def __del__(self):
        if self.ptr:
            self.free()
