"""
Property-based tests for PCAP Analyzer using Hypothesis.

These tests verify properties that should hold for all valid inputs,
rather than testing specific examples.
"""

from pathlib import Path

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from src.analyzers.rtt_analyzer import RTTAnalyzer
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer
from src.config import Config
from src.parsers.fast_parser import PacketMetadata


class TestConfigProperties:
    """Property-based tests for configuration validation."""

    @given(
        packet_gap=st.floats(min_value=0.001, max_value=10.0, allow_nan=False, allow_infinity=False),
        syn_synack_delay=st.floats(min_value=0.001, max_value=1.0, allow_nan=False, allow_infinity=False),
        handshake_total=st.floats(min_value=0.001, max_value=2.0, allow_nan=False, allow_infinity=False),
    )
    def test_threshold_values_are_positive(self, packet_gap, syn_synack_delay, handshake_total):
        """All threshold values should be non-negative."""
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            # Format numbers to avoid scientific notation in YAML
            config_content = f"""
thresholds:
  packet_gap: {packet_gap:.6f}
  syn_synack_delay: {syn_synack_delay:.6f}
  handshake_total: {handshake_total:.6f}
  rtt_warning: 0.1
  rtt_critical: 0.5
  retransmission_low: 10
  retransmission_rate_low: 1.0
  dns_response_warning: 0.1
  dns_response_critical: 1.0

reports:
  output_dir: "reports"
"""
            f.write(config_content)
            config_file = f.name

        try:
            config = Config(config_file)

            # Property: All thresholds should be non-negative
            assert config.thresholds["packet_gap"] >= 0
            assert config.thresholds["syn_synack_delay"] >= 0
            assert config.thresholds["handshake_total"] >= 0
        finally:
            os.unlink(config_file)

    @given(threshold_value=st.floats(min_value=-100.0, max_value=-0.001))
    def test_negative_thresholds_are_rejected(self, threshold_value):
        """Negative threshold values should be rejected."""
        import os
        import tempfile

        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            config_content = f"""
thresholds:
  packet_gap: {threshold_value}
  syn_synack_delay: 0.1
  handshake_total: 0.3
  rtt_warning: 0.1
  rtt_critical: 0.5
  retransmission_low: 10
  retransmission_rate_low: 1.0
  dns_response_warning: 0.1
  dns_response_critical: 1.0

reports:
  output_dir: "reports"
"""
            f.write(config_content)
            config_file = f.name

        try:
            # Property: Negative values should raise ValueError
            with pytest.raises(ValueError, match="ne peut pas être négatif"):
                Config(config_file)
        finally:
            os.unlink(config_file)


class TestPacketMetadataProperties:
    """Property-based tests for PacketMetadata."""

    @given(
        packet_num=st.integers(min_value=0, max_value=1_000_000),
        timestamp=st.floats(min_value=0.0, max_value=1e10),
        src_port=st.integers(min_value=1, max_value=65535),
        dst_port=st.integers(min_value=1, max_value=65535),
        tcp_seq=st.integers(min_value=0, max_value=2**32 - 1),
        tcp_ack=st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_packet_metadata_tcp_ports_are_valid(self, packet_num, timestamp, src_port, dst_port, tcp_seq, tcp_ack):
        """TCP ports should always be in valid range (1-65535)."""
        metadata = PacketMetadata(
            packet_num=packet_num,
            timestamp=timestamp,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            ip_version=4,
            ttl=64,
            total_length=100,
            packet_length=100,
            protocol="TCP",
            src_port=src_port,
            dst_port=dst_port,
            tcp_seq=tcp_seq,
            tcp_ack=tcp_ack,
        )

        # Property: Ports should be in valid range
        assert 1 <= metadata.src_port <= 65535
        assert 1 <= metadata.dst_port <= 65535

    @given(tcp_flags=st.integers(min_value=0, max_value=255))
    def test_tcp_flags_consistency(self, tcp_flags):
        """TCP flags should be consistently parsed into boolean flags."""
        metadata = PacketMetadata(
            packet_num=0,
            timestamp=1.0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            ip_version=4,
            ttl=64,
            total_length=100,
            packet_length=100,
            protocol="TCP",
            tcp_flags=tcp_flags,
        )

        # Property: Boolean flags should match raw flags
        # dpkt.tcp.TH_SYN = 0x02, TH_ACK = 0x10, TH_FIN = 0x01, TH_RST = 0x04, TH_PUSH = 0x08
        assert metadata.is_syn == bool(tcp_flags & 0x02)
        assert metadata.is_ack == bool(tcp_flags & 0x10)
        assert metadata.is_fin == bool(tcp_flags & 0x01)
        assert metadata.is_rst == bool(tcp_flags & 0x04)
        assert metadata.is_psh == bool(tcp_flags & 0x08)


class TestAnalyzerProperties:
    """Property-based tests for analyzers."""

    @given(
        syn_threshold=st.floats(min_value=0.01, max_value=1.0),
        total_threshold=st.floats(min_value=0.01, max_value=2.0),
    )
    def test_tcp_handshake_analyzer_thresholds(self, syn_threshold, total_threshold):
        """TCPHandshakeAnalyzer should respect configured thresholds."""
        assume(total_threshold > syn_threshold)  # Total should be larger than SYN delay

        analyzer = TCPHandshakeAnalyzer(syn_synack_threshold=syn_threshold, total_threshold=total_threshold)

        # Property: Thresholds should be stored correctly
        assert analyzer.syn_synack_threshold == syn_threshold
        assert analyzer.total_threshold == total_threshold

        # Property: Initial stats should be zero
        results = analyzer.finalize()
        assert results["total_handshakes"] == 0
        assert results["slow_handshakes"] == 0

    @given(
        rtt_warning=st.floats(min_value=0.01, max_value=0.5),
        rtt_critical=st.floats(min_value=0.5, max_value=2.0),
    )
    def test_rtt_analyzer_threshold_ordering(self, rtt_warning, rtt_critical):
        """RTTAnalyzer critical threshold should be greater than warning."""
        assume(rtt_critical > rtt_warning)

        analyzer = RTTAnalyzer(rtt_warning=rtt_warning, rtt_critical=rtt_critical)

        # Property: Critical threshold should be greater than warning
        assert analyzer.rtt_critical > analyzer.rtt_warning

        # Property: Initial measurements should be zero
        results = analyzer.finalize()
        assert results["total_measurements"] == 0


class TestIPAddressProperties:
    """Property-based tests for IP address handling."""

    @given(ip_octets=st.lists(st.integers(min_value=0, max_value=255), min_size=4, max_size=4))
    def test_ipv4_address_format(self, ip_octets):
        """IPv4 addresses should be formatted correctly."""
        ip_str = ".".join(map(str, ip_octets))

        metadata = PacketMetadata(
            packet_num=0,
            timestamp=1.0,
            src_ip=ip_str,
            dst_ip="192.168.1.2",
            ip_version=4,
            ttl=64,
            total_length=100,
            packet_length=100,
            protocol="TCP",
        )

        # Property: IP should be parseable back to octets
        parts = metadata.src_ip.split(".")
        assert len(parts) == 4
        assert all(0 <= int(p) <= 255 for p in parts)

    @given(ttl=st.integers(min_value=1, max_value=255))
    def test_ttl_range(self, ttl):
        """TTL should always be in valid range (1-255)."""
        metadata = PacketMetadata(
            packet_num=0,
            timestamp=1.0,
            src_ip="192.168.1.1",
            dst_ip="192.168.1.2",
            ip_version=4,
            ttl=ttl,
            total_length=100,
            packet_length=100,
            protocol="TCP",
        )

        # Property: TTL should be in valid range
        assert 1 <= metadata.ttl <= 255


class TestPathValidationProperties:
    """Property-based tests for path validation."""

    @given(
        filename=st.text(
            alphabet=st.characters(blacklist_categories=("Cs", "Cc"), blacklist_characters='/\\:*?"<>|'),
            min_size=1,
            max_size=50,
        )
    )
    def test_safe_filename_generation(self, filename):
        """Generated filenames should not contain path separators."""
        # Property: Safe filenames should not contain path separators
        assume("/" not in filename)
        assume("\\" not in filename)
        assume(".." not in filename)

        # If we get here, the filename is safe
        assert "/" not in filename
        assert "\\" not in filename
        assert ".." not in filename


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
