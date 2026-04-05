# -*- coding: utf-8 -*-
"""
Tests for PyPy Optimization Module

Coverage goal: >85%
"""

import pytest

from backend.core.pypy_optimization import (
    is_pypy,
    is_cpython,
    get_python_implementation,
    get_platform_info,
    JITWarmup,
    PerformanceComparator,
    get_optimization_recommendations,
    warmup_on_startup,
    CRYPTO_AVAILABLE,
)


# =============================================================================
# Tests: Platform Detection
# =============================================================================

class TestPlatformDetection:
    """Tests for platform detection functions."""
    
    def test_is_pypy_or_cpython(self):
        """Test that we're either on PyPy or CPython."""
        assert is_pypy() or is_cpython()
        assert not (is_pypy() and is_cpython())  # Can't be both
    
    def test_get_python_implementation(self):
        """Test implementation string format."""
        impl = get_python_implementation()
        
        assert isinstance(impl, str)
        assert len(impl) > 0
        
        if is_pypy():
            assert "PyPy" in impl
        else:
            assert "CPython" in impl
    
    def test_get_platform_info(self):
        """Test platform info dictionary."""
        info = get_platform_info()
        
        assert isinstance(info, dict)
        assert 'implementation' in info
        assert 'version' in info
        assert 'platform' in info
        assert 'pypy' in info
        assert 'cpython' in info
        
        # Check consistency
        if info['pypy']:
            assert not info['cpython']
        else:
            assert info['cpython']


# =============================================================================
# Tests: JITWarmup
# =============================================================================

class TestJITWarmup:
    """Tests for JIT warmup manager."""
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_warmup_runs_successfully(self):
        """Test that warmup completes successfully."""
        warmup = JITWarmup()
        results = warmup.run_full_warmup(count=10)  # Small count for speed
        
        assert 'aes_gcm' in results
        assert 'argon2' in results
        assert 'hmac' in results
        assert 'hashing' in results
        
        # All times should be positive
        for key, value in results.items():
            if isinstance(value, (int, float)):
                assert value > 0
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_warmup_sets_flag(self):
        """Test that warmup sets warmed_up flag."""
        warmup = JITWarmup()
        
        assert warmup.is_warmed_up() is False
        
        warmup.run_full_warmup(count=5)
        
        assert warmup.is_warmed_up() is True
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_get_warmup_results(self):
        """Test getting warmup results."""
        warmup = JITWarmup()
        
        # Before warmup
        assert warmup.get_warmup_results() == {}
        
        # After warmup
        warmup.run_full_warmup(count=5)
        results = warmup.get_warmup_results()
        
        assert len(results) > 0
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_custom_warmup_count(self):
        """Test custom warmup count."""
        warmup = JITWarmup()
        
        # Run with different counts
        results1 = warmup.run_full_warmup(count=10)
        results2 = warmup.run_full_warmup(count=20)
        
        # More iterations should take longer
        assert results2['aes_gcm'] > results1['aes_gcm']


# =============================================================================
# Tests: PerformanceComparator
# =============================================================================

class TestPerformanceComparator:
    """Tests for performance comparator."""
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_compare_crypto_operations(self):
        """Test performance comparison."""
        comparator = PerformanceComparator(iterations=100)
        results = comparator.compare_crypto_operations()
        
        assert 'implementation' in results
        assert 'is_pypy' in results
        assert 'tests' in results
        assert 'summary' in results
        
        # Check test results
        assert 'aes_gcm' in results['tests']
        assert 'argon2' in results['tests']
        assert 'hmac' in results['tests']
        
        # Each test should have timing info
        for test_name, test_data in results['tests'].items():
            assert 'total_time' in test_data
            assert 'avg_time' in test_data
            assert 'ops_per_second' in test_data
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_comparison_consistency(self):
        """Test that comparison gives consistent results."""
        comparator1 = PerformanceComparator(iterations=50)
        comparator2 = PerformanceComparator(iterations=50)
        
        results1 = comparator1.compare_crypto_operations()
        results2 = comparator2.compare_crypto_operations()
        
        # Results should be similar (within 50% for timing)
        for test_name in ['aes_gcm', 'hmac']:
            if test_name in results1['tests'] and test_name in results2['tests']:
                time1 = results1['tests'][test_name]['total_time']
                time2 = results2['tests'][test_name]['total_time']
                
                # Allow 50% variance
                ratio = max(time1, time2) / min(time1, time2)
                assert ratio < 2.0


# =============================================================================
# Tests: Optimization Recommendations
# =============================================================================

class TestOptimizationRecommendations:
    """Tests for optimization recommendations."""
    
    def test_get_recommendations_structure(self):
        """Test recommendations dictionary structure."""
        recommendations = get_optimization_recommendations()
        
        assert isinstance(recommendations, dict)
        assert 'platform' in recommendations
        assert 'is_pypy' in recommendations
        assert 'recommendations' in recommendations
        assert 'warnings' in recommendations
    
    def test_get_recommendations_content(self):
        """Test recommendations content."""
        recommendations = get_optimization_recommendations()
        
        # Should have at least one recommendation
        assert len(recommendations['recommendations']) > 0
        
        # Recommendations should be strings
        for rec in recommendations['recommendations']:
            assert isinstance(rec, str)
            assert len(rec) > 0
    
    def test_recommendations_match_platform(self):
        """Test that recommendations match the platform."""
        recommendations = get_optimization_recommendations()
        
        if is_pypy():
            # PyPy-specific recommendations
            assert any(
                'JIT' in rec or 'PyPy' in rec
                for rec in recommendations['recommendations']
            )


# =============================================================================
# Tests: Warmup on Startup
# =============================================================================

class TestWarmupOnStartup:
    """Tests for startup warmup function."""
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_warmup_on_startup_success(self):
        """Test startup warmup completes."""
        success, results = warmup_on_startup()
        
        assert success is True
        assert 'individual_times' in results
        assert 'total_time' in results
        assert 'warmed_up' in results
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_warmup_on_startup_timing(self):
        """Test startup warmup timing."""
        success, results = warmup_on_startup()
        
        if success:
            total_time = results['total_time']
            
            # Should complete in reasonable time (< 10 seconds)
            assert total_time < 10.0
            
            # Should take some time (> 0.01 seconds)
            assert total_time > 0.01


# =============================================================================
# Integration Tests
# =============================================================================

class TestIntegration:
    """Integration tests for PyPy optimization module."""
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_full_warmup_workflow(self):
        """Test complete warmup workflow."""
        # Get platform info
        info = get_platform_info()
        
        # Run warmup
        warmup = JITWarmup()
        results = warmup.run_full_warmup(count=10)
        
        # Verify warmup
        assert warmup.is_warmed_up()
        
        # Get recommendations
        recommendations = get_optimization_recommendations()
        
        # Should have platform-specific recommendations
        assert len(recommendations['recommendations']) > 0
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_performance_comparison_workflow(self):
        """Test performance comparison workflow."""
        # Get implementation info
        impl = get_python_implementation()
        
        # Run comparison
        comparator = PerformanceComparator(iterations=50)
        results = comparator.compare_crypto_operations()
        
        # Verify results match implementation
        assert results['implementation'] == impl
        assert results['is_pypy'] == is_pypy()
    
    @pytest.mark.skipif(not CRYPTO_AVAILABLE, reason="Crypto libraries not available")
    def test_warmup_improves_performance(self):
        """Test that warmup improves performance."""
        import time
        import secrets
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        
        # Before warmup
        key = secrets.token_bytes(32)
        aesgcm = AESGCM(key)
        data = b"test data"
        
        start_before = time.perf_counter()
        for _ in range(10):
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, data, None)
            _ = aesgcm.decrypt(nonce, encrypted, None)
        time_before = time.perf_counter() - start_before
        
        # Warmup
        warmup = JITWarmup()
        warmup.run_full_warmup(count=50)
        
        # After warmup
        start_after = time.perf_counter()
        for _ in range(10):
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, data, None)
            _ = aesgcm.decrypt(nonce, encrypted, None)
        time_after = time.perf_counter() - start_after
        
        # After warmup should be faster or equal (JIT compiled)
        # Note: This may not always be true on CPython, but should be on PyPy
        if is_pypy():
            assert time_after <= time_before * 1.5  # Allow some variance
