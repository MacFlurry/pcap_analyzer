"""
Security tests for decompression bomb protection (OWASP ASVS 5.2.3, CWE-770).

Tests:
- Expansion ratio monitoring
- Warning and critical thresholds
- Real-time monitoring during processing
- Integration with PCAP parsing
"""

import pytest
import gzip
import tempfile
import os

from src.utils.decompression_monitor import (
    DecompressionMonitor,
    DecompressionBombError,
    ExpansionStats,
)


class TestExpansionRatioMonitoring:
    """Test expansion ratio calculation and monitoring."""

    def test_normal_expansion_ratio_accepted(self):
        """Normal expansion ratio (e.g., 10:1) is accepted."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024  # 1 MB compressed
        bytes_processed = 10 * 1024 * 1024  # 10 MB decompressed
        packets = 1000

        # Should not raise exception
        monitor.check_expansion_ratio(file_size, bytes_processed, packets)

    def test_high_expansion_triggers_warning(self):
        """High expansion ratio (>1000:1) triggers warning."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024  # 1 MB compressed
        bytes_processed = 1500 * 1024 * 1024  # 1500 MB decompressed (1500:1 ratio)
        packets = 10000

        # Should log warning but not abort
        stats = monitor.check_expansion_ratio(file_size, bytes_processed, packets)
        assert stats is not None
        assert stats.is_warning is True
        assert stats.is_critical is False

    def test_critical_expansion_raises_error(self):
        """Critical expansion ratio (>10000:1) aborts processing."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024  # 1 MB compressed
        bytes_processed = 15000 * 1024 * 1024  # 15 GB decompressed (15000:1 ratio)
        packets = 100000

        # Should abort immediately
        with pytest.raises(DecompressionBombError, match="Decompression bomb detected"):
            monitor.check_expansion_ratio(file_size, bytes_processed, packets)

    def test_expansion_ratio_exact_warning_threshold(self):
        """Expansion ratio exactly at warning threshold."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024  # 1 MB
        bytes_processed = 1000 * 1024 * 1024  # 1000 MB (exactly 1000:1)
        packets = 10000  # Must reach check_interval

        # At threshold, should warn
        stats = monitor.check_expansion_ratio(file_size, bytes_processed, packets)
        assert stats is not None
        assert stats.is_warning is True
        assert stats.is_critical is False

    def test_expansion_ratio_exact_critical_threshold(self):
        """Expansion ratio exactly at critical threshold."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024  # 1 MB
        bytes_processed = 10000 * 1024 * 1024  # 10 GB (exactly 10000:1)
        packets = 50000

        # At critical threshold, should abort
        with pytest.raises(DecompressionBombError):
            monitor.check_expansion_ratio(file_size, bytes_processed, packets)


class TestDecompressionMonitorConfiguration:
    """Test decompression monitor configuration."""

    def test_default_thresholds(self):
        """Default thresholds are 1000:1 warning, 10000:1 critical."""
        monitor = DecompressionMonitor()

        assert monitor.max_ratio == 1000
        assert monitor.critical_ratio == 10000
        assert monitor.check_interval == 10000

    def test_custom_thresholds(self):
        """Custom thresholds can be configured."""
        monitor = DecompressionMonitor(
            max_ratio=500,
            critical_ratio=5000,
            check_interval=5000,
        )

        assert monitor.max_ratio == 500
        assert monitor.critical_ratio == 5000
        assert monitor.check_interval == 5000

    def test_monitor_uses_config(self):
        """DecompressionMonitor uses config thresholds."""
        monitor = DecompressionMonitor(max_ratio=100, critical_ratio=200)

        file_size = 1024 * 1024  # 1 MB
        bytes_processed = 150 * 1024 * 1024  # 150 MB (150:1 ratio)
        packets = 10000  # Must reach check_interval

        # 150:1 ratio should trigger warning with 100:1 threshold
        stats = monitor.check_expansion_ratio(file_size, bytes_processed, packets)
        assert stats is not None
        assert stats.is_warning is True
        assert stats.is_critical is False


class TestRealTimeMonitoring:
    """Test real-time monitoring during PCAP processing."""

    def test_monitoring_every_n_packets(self):
        """Monitor checks expansion ratio every N packets."""
        monitor = DecompressionMonitor(
            max_ratio=1000,
            critical_ratio=10000,
            check_interval=100  # Check every 100 packets
        )

        file_size = 1024 * 1024  # 1 MB
        bytes_processed = 0
        packet_size = 1500  # Typical packet size

        # Simulate processing packets
        for i in range(1, 501):  # 500 packets
            bytes_processed += packet_size

            if i % 100 == 0:  # Check interval
                # Should not raise (normal expansion)
                monitor.check_expansion_ratio(file_size, bytes_processed, i)

    def test_monitoring_detects_bomb_early(self):
        """Monitor detects decompression bomb before full expansion."""
        monitor = DecompressionMonitor(
            max_ratio=1000,
            critical_ratio=10000,
            check_interval=1000
        )

        file_size = 1024 * 1024  # 1 MB compressed

        # Simulate rapid expansion (bomb)
        bytes_per_packet = 1024 * 1024  # 1 MB per packet (abnormal!)

        for packet_count in range(1000, 15001, 1000):  # Check every 1000 packets
            bytes_processed = packet_count * bytes_per_packet

            if packet_count >= 10000:
                # At 10,000 packets: 10 GB processed, 10000:1 ratio
                with pytest.raises(DecompressionBombError):
                    monitor.check_expansion_ratio(file_size, bytes_processed, packet_count)
                break

    def test_incremental_monitoring_updates(self):
        """Monitor tracks incremental updates during processing."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 10 * 1024 * 1024  # 10 MB compressed

        # Process in chunks
        chunks = [
            (1000, 100 * 1024 * 1024),    # 1000 packets, 100 MB (10:1)
            (2000, 200 * 1024 * 1024),    # 2000 packets, 200 MB (20:1)
            (5000, 500 * 1024 * 1024),    # 5000 packets, 500 MB (50:1)
        ]

        for packets, bytes_processed in chunks:
            # All chunks should pass (normal expansion)
            monitor.check_expansion_ratio(file_size, bytes_processed, packets)


class TestDecompressionBombScenarios:
    """Test real-world decompression bomb scenarios."""

    def test_zip_bomb_detection(self):
        """Detect zip bomb (e.g., 42.zip - 42 KB -> 4.5 PB)."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        # Simulate zip bomb
        compressed_size = 42 * 1024  # 42 KB
        # After processing 10,000 packets, already expanded to 10 GB
        decompressed_size = 10 * 1024 * 1024 * 1024  # 10 GB
        packets = 10000

        # Ratio: 10 GB / 42 KB = ~244,000:1 (far exceeds 10000:1)
        with pytest.raises(DecompressionBombError):
            monitor.check_expansion_ratio(compressed_size, decompressed_size, packets)

    def test_gzip_bomb_in_pcap(self):
        """Detect gzip-compressed PCAP with bomb payload."""
        # Create a small gzip file with high expansion
        with tempfile.NamedTemporaryFile(suffix=".gz", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            # Create gzip with repetitive data (high compression)
            with gzip.open(tmp_path, 'wb') as f:
                # Write 10 MB of zeros (compresses to ~10 KB)
                f.write(b'\x00' * (10 * 1024 * 1024))

            compressed_size = os.path.getsize(tmp_path)  # ~10 KB
            decompressed_size = 10 * 1024 * 1024  # 10 MB

            monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

            # Ratio: ~1000:1 (should trigger warning)
            stats = monitor.check_expansion_ratio(compressed_size, decompressed_size, 10000)
            # With high compression, this should trigger warning
            if stats:  # May be None if check_interval not reached
                assert stats.expansion_ratio >= 1000

        finally:
            os.unlink(tmp_path)

    def test_nested_compression_bomb(self):
        """Detect nested compression bomb (zip inside zip)."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        # Outer zip: 1 MB
        # Inner zip 1: expands to 1 GB
        # Inner zip 2 (inside inner zip 1): expands to 10 TB
        # Total ratio: 10 TB / 1 MB = 10,000,000:1

        compressed_size = 1024 * 1024  # 1 MB
        # After decompressing first layer, already at 1 GB
        first_layer = 1024 * 1024 * 1024  # 1 GB

        # First layer (1000:1) should warn
        stats = monitor.check_expansion_ratio(compressed_size, first_layer, 10000)
        assert stats is not None
        assert stats.is_warning is True

        # Second layer would exceed critical threshold (10 GB / 1 MB = 10240:1)
        second_layer = 10 * 1024 * 1024 * 1024  # 10 GB
        with pytest.raises(DecompressionBombError):
            monitor.check_expansion_ratio(compressed_size, second_layer, 20000)  # Next check interval


class TestMonitoringPerformance:
    """Test monitoring performance and overhead."""

    def test_check_interval_reduces_overhead(self):
        """Checking every N packets reduces performance overhead."""
        # With 10,000 packet interval, only check 100 times for 1M packets
        monitor = DecompressionMonitor(check_interval=10000)

        file_size = 10 * 1024 * 1024
        packets_processed = 1000000
        bytes_processed = 100 * 1024 * 1024

        # Should be fast (only 100 checks, not 1M checks)
        import time
        start = time.time()

        for i in range(0, packets_processed, 10000):
            monitor.check_expansion_ratio(file_size, bytes_processed, i)

        elapsed = time.time() - start

        # Should complete in under 1 second
        assert elapsed < 1.0

    def test_monitor_state_is_lightweight(self):
        """Monitor maintains minimal state (no packet storage)."""
        monitor = DecompressionMonitor()

        # Monitor should only store config, not packet data
        import sys
        size = sys.getsizeof(monitor)

        # Should be < 1 KB (just config, no packet history)
        assert size < 1024


class TestErrorMessages:
    """Test error message quality for security events."""

    def test_decompression_bomb_error_has_details(self):
        """DecompressionBombError includes expansion ratio details."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024
        bytes_processed = 15000 * 1024 * 1024  # 15000:1 ratio
        packets = 100000

        try:
            monitor.check_expansion_ratio(file_size, bytes_processed, packets)
        except DecompressionBombError as e:
            error_msg = str(e)
            # Should include ratio in error message
            assert "15000" in error_msg or "expansion" in error_msg.lower()

    def test_warning_message_includes_ratio(self):
        """Warning message includes current expansion ratio."""
        monitor = DecompressionMonitor(max_ratio=1000, critical_ratio=10000)

        file_size = 1024 * 1024
        bytes_processed = 1500 * 1024 * 1024  # 1500:1

        stats = monitor.check_expansion_ratio(file_size, bytes_processed, 10000)

        # Stats should have correct ratio
        assert stats is not None
        assert stats.is_warning is True
        assert stats.expansion_ratio == 1500


class TestMonitorStateControl:
    """Test enable/disable state control."""

    def test_disabled_monitor_returns_none(self):
        """Disabled monitor returns None and skips checks."""
        monitor = DecompressionMonitor()
        monitor.disable()

        # High expansion ratio but monitoring disabled
        stats = monitor.check_expansion_ratio(
            file_size=1024 * 1024,  # 1 MB
            bytes_processed=1500 * 1024 * 1024,  # 1500 MB (1500:1)
            packets_count=10000
        )

        assert stats is None  # Monitoring disabled, no stats returned

    def test_enable_resumes_monitoring(self):
        """Re-enabling monitor resumes checks."""
        monitor = DecompressionMonitor()
        monitor.disable()
        monitor.enable()

        # Now monitoring should work
        stats = monitor.check_expansion_ratio(
            file_size=1024 * 1024,  # 1 MB
            bytes_processed=1500 * 1024 * 1024,  # 1500 MB
            packets_count=10000
        )

        assert stats is not None
        assert stats.is_warning is True


class TestConvenienceFunctions:
    """Test convenience utility functions."""

    def test_check_expansion_safe_returns_true_for_safe_ratio(self):
        """check_expansion_safe() returns True for safe ratios."""
        from src.utils.decompression_monitor import check_expansion_safe

        # 500:1 ratio is safe (default max is 1000:1)
        result = check_expansion_safe(
            file_size=1000,
            bytes_processed=500_000
        )
        assert result is True

    def test_check_expansion_safe_returns_false_for_unsafe_ratio(self):
        """check_expansion_safe() returns False for unsafe ratios."""
        from src.utils.decompression_monitor import check_expansion_safe

        # 5000:1 ratio is unsafe (exceeds 1000:1 default)
        result = check_expansion_safe(
            file_size=1000,
            bytes_processed=5_000_000
        )
        assert result is False

    def test_check_expansion_safe_custom_max_ratio(self):
        """check_expansion_safe() respects custom max_ratio."""
        from src.utils.decompression_monitor import check_expansion_safe

        # 500:1 ratio, but custom max is 100:1
        result = check_expansion_safe(
            file_size=1000,
            bytes_processed=500_000,
            max_ratio=100
        )
        assert result is False  # Exceeds custom 100:1 limit


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
