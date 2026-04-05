# -*- coding: utf-8 -*-
"""
PyPy Optimization Module - Оптимизация для PyPy

Provides:
- JIT warmup routines
- Performance optimizations for PyPy
- CPython/PyPy compatibility checks

Author: Nikita (BE1)
Version: 1.2.0
"""

import sys
import time
from typing import Dict, Any, Optional, Tuple

# Try to import crypto libraries
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False


# =============================================================================
# Platform Detection
# =============================================================================

def is_pypy() -> bool:
    """Check if running on PyPy."""
    return hasattr(sys, 'pypy_version_info')


def is_cpython() -> bool:
    """Check if running on CPython."""
    return not is_pypy()


def get_python_implementation() -> str:
    """
    Get Python implementation name and version.
    
    Returns:
        Implementation string (e.g., "CPython 3.11.9" or "PyPy 7.3.11")
    """
    if is_pypy():
        version = sys.pypy_version_info
        return f"PyPy {version.major}.{version.minor}.{version.micro}"
    else:
        return f"CPython {sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"


def get_platform_info() -> Dict[str, Any]:
    """
    Get detailed platform information.
    
    Returns:
        Dictionary with platform details
    """
    info = {
        'implementation': get_python_implementation(),
        'version': sys.version,
        'platform': sys.platform,
        'pypy': is_pypy(),
        'cpython': is_cpython(),
    }
    
    if is_pypy():
        info['pypy_version'] = sys.pypy_version_info
        info['pypy_revision'] = getattr(sys, 'pypy_revision', 'unknown')
    
    return info


# =============================================================================
# JIT Warmup
# =============================================================================

class JITWarmup:
    """
    JIT warmup manager for PyPy.
    
    Pre-compiles hot paths to improve runtime performance.
    
    Example:
        >>> warmup = JITWarmup()
        >>> warmup.run_full_warmup()
        >>> # Now crypto operations are optimized
    """
    
    def __init__(self):
        """Initialize JIT warmup manager."""
        self._warmup_count = 100
        self._warmup_done = False
        self._results: Dict[str, float] = {}
    
    def run_full_warmup(self, count: Optional[int] = None) -> Dict[str, float]:
        """
        Run full JIT warmup for all crypto operations.
        
        Args:
            count: Number of warmup iterations (default: 100)
        
        Returns:
            Dictionary with warmup times for each operation
        """
        if count is not None:
            self._warmup_count = count
        
        if not CRYPTO_AVAILABLE:
            return {'error': 'Crypto libraries not available'}
        
        results = {}
        
        # Warmup AES-GCM
        results['aes_gcm'] = self._warmup_aes_gcm()
        
        # Warmup Argon2
        results['argon2'] = self._warmup_argon2()
        
        # Warmup HMAC
        results['hmac'] = self._warmup_hmac()
        
        # Warmup hashing
        results['hashing'] = self._warmup_hashing()
        
        self._warmup_done = True
        self._results = results
        
        return results
    
    def _warmup_aes_gcm(self) -> float:
        """Warmup AES-GCM operations."""
        import secrets
        
        start = time.perf_counter()
        
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        
        for i in range(self._warmup_count):
            nonce = secrets.token_bytes(12)
            data = f"test data {i}".encode()
            encrypted = aesgcm.encrypt(nonce, data, None)
            _ = aesgcm.decrypt(nonce, encrypted, None)
        
        elapsed = time.perf_counter() - start
        return elapsed
    
    def _warmup_argon2(self) -> float:
        """Warmup Argon2 operations."""
        import secrets
        
        start = time.perf_counter()
        
        salt = secrets.token_bytes(16)
        
        # Use reduced parameters for warmup
        for i in range(10):  # Fewer iterations for Argon2
            _ = hash_secret_raw(
                secret=f"password{i}".encode(),
                salt=salt,
                time_cost=1,  # Reduced for warmup
                memory_cost=8192,
                parallelism=1,
                hash_len=32,
                type=Type.ID,
            )
        
        elapsed = time.perf_counter() - start
        return elapsed
    
    def _warmup_hmac(self) -> float:
        """Warmup HMAC operations."""
        import hmac
        import hashlib
        import secrets
        
        start = time.perf_counter()
        
        key = secrets.token_bytes(32)
        
        for i in range(self._warmup_count):
            data = f"test data {i}".encode()
            signature = hmac.new(key, data, hashlib.sha256).digest()
            _ = hmac.compare_digest(signature, hmac.new(key, data, hashlib.sha256).digest())
        
        elapsed = time.perf_counter() - start
        return elapsed
    
    def _warmup_hashing(self) -> float:
        """Warmup hashing operations."""
        import hashlib
        import secrets
        
        start = time.perf_counter()
        
        for i in range(self._warmup_count):
            data = f"test data {i}".encode()
            _ = hashlib.sha256(data).digest()
            _ = hashlib.sha512(data).digest()
        
        elapsed = time.perf_counter() - start
        return elapsed
    
    def is_warmed_up(self) -> bool:
        """Check if warmup has been performed."""
        return self._warmup_done
    
    def get_warmup_results(self) -> Dict[str, float]:
        """Get warmup timing results."""
        return self._results.copy()


# =============================================================================
# Performance Comparison
# =============================================================================

class PerformanceComparator:
    """
    Compare performance between CPython and PyPy.
    
    Example:
        >>> comparator = PerformanceComparator()
        >>> results = comparator.compare_crypto_operations()
        >>> print(f"PyPy is {results['speedup']}x faster")
    """
    
    def __init__(self, iterations: int = 1000):
        """
        Initialize comparator.
        
        Args:
            iterations: Number of iterations for each test
        """
        self._iterations = iterations
    
    def compare_crypto_operations(self) -> Dict[str, Any]:
        """
        Compare crypto operation performance.
        
        Returns:
            Dictionary with comparison results
        """
        if not CRYPTO_AVAILABLE:
            return {'error': 'Crypto libraries not available'}
        
        results = {
            'implementation': get_python_implementation(),
            'is_pypy': is_pypy(),
            'tests': {}
        }
        
        # AES-GCM benchmark
        results['tests']['aes_gcm'] = self._benchmark_aes_gcm()
        
        # Argon2 benchmark
        results['tests']['argon2'] = self._benchmark_argon2()
        
        # HMAC benchmark
        results['tests']['hmac'] = self._benchmark_hmac()
        
        # Calculate speedup
        results['summary'] = self._calculate_summary(results['tests'])
        
        return results
    
    def _benchmark_aes_gcm(self) -> Dict[str, float]:
        """Benchmark AES-GCM operations."""
        import secrets
        
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        data = b"test data for benchmark"
        
        start = time.perf_counter()
        
        for _ in range(self._iterations):
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, data, None)
            _ = aesgcm.decrypt(nonce, encrypted, None)
        
        elapsed = time.perf_counter() - start
        
        return {
            'total_time': elapsed,
            'avg_time': elapsed / self._iterations,
            'ops_per_second': self._iterations / elapsed,
        }
    
    def _benchmark_argon2(self) -> Dict[str, float]:
        """Benchmark Argon2 operations."""
        import secrets
        
        salt = secrets.token_bytes(16)
        
        start = time.perf_counter()
        
        for _ in range(10):  # Fewer iterations for Argon2
            _ = hash_secret_raw(
                secret=b"benchmark_password",
                salt=salt,
                time_cost=3,
                memory_cost=65536,
                parallelism=4,
                hash_len=32,
                type=Type.ID,
            )
        
        elapsed = time.perf_counter() - start
        
        return {
            'total_time': elapsed,
            'avg_time': elapsed / 10,
            'ops_per_second': 10 / elapsed,
        }
    
    def _benchmark_hmac(self) -> Dict[str, float]:
        """Benchmark HMAC operations."""
        import hmac
        import hashlib
        import secrets
        
        key = secrets.token_bytes(32)
        data = b"test data for benchmark"
        
        start = time.perf_counter()
        
        for _ in range(self._iterations):
            signature = hmac.new(key, data, hashlib.sha256).digest()
            _ = hmac.compare_digest(signature, signature)
        
        elapsed = time.perf_counter() - start
        
        return {
            'total_time': elapsed,
            'avg_time': elapsed / self._iterations,
            'ops_per_second': self._iterations / elapsed,
        }
    
    def _calculate_summary(self, tests: Dict[str, Dict]) -> Dict[str, Any]:
        """Calculate summary statistics."""
        total_ops = sum(
            test['ops_per_second']
            for test in tests.values()
            if 'ops_per_second' in test
        )
        
        return {
            'total_operations_per_second': total_ops,
            'implementation': get_python_implementation(),
            'is_pypy': is_pypy(),
        }


# =============================================================================
# Optimization Recommendations
# =============================================================================

def get_optimization_recommendations() -> Dict[str, Any]:
    """
    Get optimization recommendations based on current platform.
    
    Returns:
        Dictionary with recommendations
    """
    recommendations = {
        'platform': get_python_implementation(),
        'is_pypy': is_pypy(),
        'recommendations': [],
        'warnings': [],
    }
    
    if is_pypy():
        recommendations['recommendations'].extend([
            "Use JIT warmup at startup for better initial performance",
            "Avoid excessive object creation in hot loops",
            "Use simple data types where possible",
            "Consider using __slots__ for frequently instantiated classes",
        ])
    else:
        recommendations['recommendations'].extend([
            "Consider using PyPy for CPU-bound crypto operations",
            "Use C extensions (cryptography library) for best performance",
            "Enable profile-guided optimization if available",
        ])
    
    # Check crypto library compatibility
    if not CRYPTO_AVAILABLE:
        recommendations['warnings'].append(
            "Crypto libraries not available - install cryptography and argon2-cffi"
        )
    
    return recommendations


# =============================================================================
# Startup Warmup Function
# =============================================================================

def warmup_on_startup() -> Tuple[bool, Dict[str, Any]]:
    """
    Convenience function for warming up JIT at application startup.
    
    Returns:
        Tuple of (success, results)
    
    Example:
        >>> success, results = warmup_on_startup()
        >>> if success:
        ...     print(f"Warmup completed in {sum(results.values()):.3f}s")
    """
    if not CRYPTO_AVAILABLE:
        return False, {'error': 'Crypto libraries not available'}
    
    warmup = JITWarmup()
    results = warmup.run_full_warmup(count=50)  # Reduced for faster startup
    
    if 'error' in results:
        return False, results
    
    total_time = sum(v for v in results.values() if isinstance(v, (int, float)))
    
    return True, {
        'individual_times': results,
        'total_time': total_time,
        'warmed_up': warmup.is_warmed_up(),
    }


# =============================================================================
# Module Exports
# =============================================================================

__all__ = [
    # Platform detection
    'is_pypy',
    'is_cpython',
    'get_python_implementation',
    'get_platform_info',
    
    # JIT warmup
    'JITWarmup',
    'warmup_on_startup',
    
    # Performance comparison
    'PerformanceComparator',
    
    # Recommendations
    'get_optimization_recommendations',
]
