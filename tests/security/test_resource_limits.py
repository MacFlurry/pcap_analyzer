"""
Security tests for resource limits (CWE-770, NIST SC-5).

Tests:
- Memory limit enforcement (RLIMIT_AS)
- CPU time limit enforcement (RLIMIT_CPU)
- File size limit enforcement (RLIMIT_FSIZE)
- Open file descriptor limit (RLIMIT_NOFILE)
- DoS protection
"""

import os
import sys
import pytest
import resource
import tempfile
from pathlib import Path

from src.utils.resource_limits import (
    set_resource_limits,
    ResourceLimitConfig,
    get_current_limits,
    restore_default_limits,
)


@pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
class TestMemoryLimits:
    """Test memory limit enforcement (CWE-770)."""

    def test_memory_limit_set_correctly(self):
        """Memory limit (RLIMIT_AS) is set correctly."""
        config = ResourceLimitConfig(memory_limit_gb=2.0)
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        expected_bytes = int(2.0 * 1024 * 1024 * 1024)

        assert soft == expected_bytes
        assert hard == expected_bytes

    def test_default_memory_limit_4gb(self):
        """Default memory limit is 4 GB."""
        config = ResourceLimitConfig()  # Use defaults
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_AS)
        expected_bytes = int(4.0 * 1024 * 1024 * 1024)

        assert soft == expected_bytes

    def test_memory_allocation_beyond_limit_fails(self):
        """Memory allocation beyond limit raises MemoryError."""
        # Set very low limit for testing (100 MB)
        config = ResourceLimitConfig(memory_limit_gb=0.1)
        set_resource_limits(config)

        # Try to allocate 200 MB (should fail)
        with pytest.raises(MemoryError):
            large_list = [0] * (200 * 1024 * 1024)  # 200 MB of integers

    def test_memory_limit_prevents_decompression_bomb(self):
        """Memory limit prevents decompression bomb from exhausting RAM."""
        config = ResourceLimitConfig(memory_limit_gb=1.0)
        set_resource_limits(config)

        # Simulate decompression bomb (would expand to >1 GB)
        # In real scenario, this would be caught by decompression monitor first
        with pytest.raises(MemoryError):
            bomb = bytearray(2 * 1024 * 1024 * 1024)  # 2 GB allocation


@pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
class TestCPUTimeLimits:
    """Test CPU time limit enforcement (NIST SC-5)."""

    def test_cpu_time_limit_set_correctly(self):
        """CPU time limit (RLIMIT_CPU) is set correctly."""
        config = ResourceLimitConfig(cpu_time_limit_seconds=1800)  # 30 minutes
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_CPU)

        assert soft == 1800
        assert hard == 1800

    def test_default_cpu_limit_1hour(self):
        """Default CPU limit is 3600 seconds (1 hour)."""
        config = ResourceLimitConfig()
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_CPU)

        assert soft == 3600

    def test_infinite_loop_terminated_by_cpu_limit(self):
        """Infinite loop is terminated by CPU limit."""
        # This test is slow (waits for timeout), skip in normal runs
        pytest.skip("CPU limit test is slow (requires actual CPU time exhaustion)")

        # Set very short CPU limit (1 second)
        config = ResourceLimitConfig(cpu_time_limit_seconds=1)
        set_resource_limits(config)

        # This should be killed after 1 second of CPU time
        with pytest.raises(SystemExit):  # SIGXCPU kills process
            while True:
                pass  # Infinite loop


@pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
class TestFileSizeLimits:
    """Test file size limit enforcement (CWE-770)."""

    def test_file_size_limit_set_correctly(self):
        """File size limit (RLIMIT_FSIZE) is set correctly."""
        config = ResourceLimitConfig(max_file_size_gb=5)
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        expected_bytes = int(5 * 1024 * 1024 * 1024)

        assert soft == expected_bytes
        assert hard == expected_bytes

    def test_default_file_size_limit_10gb(self):
        """Default file size limit is 10 GB."""
        config = ResourceLimitConfig()
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_FSIZE)
        expected_bytes = int(10 * 1024 * 1024 * 1024)

        assert soft == expected_bytes

    def test_writing_beyond_file_limit_fails(self):
        """Writing beyond file size limit raises IOError."""
        # Set very low limit for testing (10 MB)
        config = ResourceLimitConfig(max_file_size_gb=0.01)
        set_resource_limits(config)

        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Try to write 20 MB (should fail at 10 MB)
            with pytest.raises(IOError):
                with open(tmp_path, 'wb') as f:
                    # Write 20 MB in chunks
                    for _ in range(20):
                        f.write(b'0' * (1024 * 1024))  # 1 MB per iteration
        finally:
            os.unlink(tmp_path)


@pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
class TestFileDescriptorLimits:
    """Test open file descriptor limit (CWE-770)."""

    def test_file_descriptor_limit_set_correctly(self):
        """File descriptor limit (RLIMIT_NOFILE) is set correctly."""
        config = ResourceLimitConfig(max_open_files=512)
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        assert soft == 512
        # Hard limit may be higher (system-dependent)
        assert hard >= 512

    def test_default_file_descriptor_limit_1024(self):
        """Default file descriptor limit is 1024."""
        config = ResourceLimitConfig()
        set_resource_limits(config)

        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)

        assert soft == 1024

    def test_opening_too_many_files_fails(self):
        """Opening more files than limit raises OSError."""
        # Set very low limit for testing (50 files)
        config = ResourceLimitConfig(max_open_files=50)
        set_resource_limits(config)

        open_files = []
        try:
            # Try to open 60 files (should fail after 50)
            with pytest.raises(OSError):
                for i in range(60):
                    f = tempfile.TemporaryFile()
                    open_files.append(f)
        finally:
            # Clean up
            for f in open_files:
                try:
                    f.close()
                except:
                    pass


class TestResourceLimitConfiguration:
    """Test resource limit configuration and management."""

    def test_resource_limit_config_defaults(self):
        """ResourceLimitConfig has correct default values."""
        config = ResourceLimitConfig()

        assert config.memory_limit_gb == 4.0
        assert config.cpu_time_limit_seconds == 3600
        assert config.max_file_size_gb == 10
        assert config.max_open_files == 1024

    def test_custom_resource_limits(self):
        """Custom resource limits can be set."""
        config = ResourceLimitConfig(
            memory_limit_gb=8.0,
            cpu_time_limit_seconds=7200,
            max_file_size_gb=20,
            max_open_files=2048,
        )

        assert config.memory_limit_gb == 8.0
        assert config.cpu_time_limit_seconds == 7200
        assert config.max_file_size_gb == 20
        assert config.max_open_files == 2048

    @pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
    def test_get_current_limits(self):
        """get_current_limits returns current resource limits."""
        config = ResourceLimitConfig(memory_limit_gb=2.0)
        set_resource_limits(config)

        current = get_current_limits()

        assert "RLIMIT_AS" in current
        assert "RLIMIT_CPU" in current
        assert "RLIMIT_FSIZE" in current
        assert "RLIMIT_NOFILE" in current

    @pytest.mark.skipif(sys.platform == "win32", reason="resource module limited on Windows")
    def test_restore_default_limits(self):
        """restore_default_limits resets to system defaults."""
        # Set custom limits
        config = ResourceLimitConfig(memory_limit_gb=1.0)
        set_resource_limits(config)

        before_restore = resource.getrlimit(resource.RLIMIT_AS)

        # Restore defaults
        restore_default_limits()

        after_restore = resource.getrlimit(resource.RLIMIT_AS)

        # Limits should be different (or unlimited)
        assert before_restore != after_restore or after_restore == (resource.RLIM_INFINITY, resource.RLIM_INFINITY)


class TestDoSProtection:
    """Test Denial of Service protection (NIST SC-5)."""

    def test_multiple_resource_limits_enforced_simultaneously(self):
        """Multiple resource limits are enforced together."""
        config = ResourceLimitConfig(
            memory_limit_gb=2.0,
            cpu_time_limit_seconds=600,
            max_file_size_gb=5,
            max_open_files=256,
        )

        set_resource_limits(config)

        # All limits should be active
        if sys.platform != "win32":
            mem_soft, _ = resource.getrlimit(resource.RLIMIT_AS)
            cpu_soft, _ = resource.getrlimit(resource.RLIMIT_CPU)
            file_soft, _ = resource.getrlimit(resource.RLIMIT_FSIZE)
            fd_soft, _ = resource.getrlimit(resource.RLIMIT_NOFILE)

            assert mem_soft == int(2.0 * 1024 * 1024 * 1024)
            assert cpu_soft == 600
            assert file_soft == int(5 * 1024 * 1024 * 1024)
            assert fd_soft == 256

    def test_resource_limits_protect_against_fork_bomb(self):
        """Resource limits mitigate fork bomb attacks."""
        # Fork bombs are prevented by RLIMIT_NPROC (not implemented here)
        # This test documents the limitation
        pytest.skip("RLIMIT_NPROC not implemented (requires OS-level configuration)")

    def test_resource_limits_applied_at_startup(self):
        """Resource limits should be applied during application startup."""
        # This is an integration test
        # In production, limits are set in src/cli.py or main entry point

        from src.cli import main
        # Check that main() calls set_resource_limits()
        # This test verifies integration (may require code inspection)

        pytest.skip("Integration test - verify set_resource_limits() called in src/cli.py")


class TestWindowsPlatformHandling:
    """Test graceful degradation on Windows (limited resource module)."""

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_resource_limits_log_warning(self):
        """On Windows, resource limits log warning about limited support."""
        config = ResourceLimitConfig()

        # Should not crash, may log warning
        try:
            set_resource_limits(config)
        except NotImplementedError:
            # Expected on Windows
            pass

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific test")
    def test_windows_file_size_validation_still_works(self):
        """On Windows, file size pre-validation still works (no resource module needed)."""
        from src.utils.file_validator import validate_file_size

        # File size validation uses os.path.getsize(), not resource module
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'0' * (11 * 1024 * 1024))  # 11 MB
            tmp_path = tmp.name

        try:
            from src.utils.file_validator import FileValidationError

            with pytest.raises(FileValidationError):
                validate_file_size(tmp_path, max_size_bytes=10 * 1024 * 1024)
        finally:
            os.unlink(tmp_path)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
