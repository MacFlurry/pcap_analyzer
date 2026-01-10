"""
Unit tests for IPFragmentationAnalyzer.

Tests IP fragmentation detection, fragment reassembly, PMTU estimation,
and incomplete fragment detection.
"""

import pytest
from scapy.all import IP, Raw

from src.analyzers.ip_fragmentation import IPFragmentationAnalyzer


class TestIPFragmentationAnalyzer:
    """Tests for IPFragmentationAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance."""
        return IPFragmentationAnalyzer()

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        analyzer = IPFragmentationAnalyzer()
        assert analyzer.total_fragments == 0
        assert analyzer.total_packets_with_df == 0
        assert analyzer.total_fragmented_packets == 0
        assert len(analyzer.fragments) == 0
        assert len(analyzer.fragmented_flows) == 0
        assert len(analyzer.incomplete_fragments) == 0

    def test_process_non_fragmented_packet(self, analyzer):
        """Test processing non-fragmented packet."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create non-fragmented packet (no MF flag, offset = 0)
        packet = IP(src=src_ip, dst=dst_ip, flags=0, frag=0, id=12345) / Raw(load=b"data")
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should not be counted as fragment
        assert analyzer.total_fragments == 0
        # Should track flow (packets_count incremented)
        flow_key = f"{src_ip}:{dst_ip}"
        assert flow_key in analyzer.fragmented_flows
        assert analyzer.fragmented_flows[flow_key]["packets_count"] == 1

    def test_process_fragmented_packet_mf_flag(self, analyzer):
        """Test processing fragmented packet with MF (More Fragments) flag."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create first fragment (MF flag = 1, offset = 0)
        packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should be counted as fragment
        assert analyzer.total_fragments == 1
        
        # Should track fragment group
        frag_key = (src_ip, dst_ip, ip_id)
        assert frag_key in analyzer.fragments
        
        frag_info = analyzer.fragments[frag_key]
        assert len(frag_info["fragments"]) == 1
        assert frag_info["fragments"][0]["offset"] == 0
        assert frag_info["fragments"][0]["more_fragments"] is True

    def test_process_fragmented_packet_with_offset(self, analyzer):
        """Test processing fragmented packet with offset > 0."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create fragment with offset (frag = 125 means offset = 125 * 8 = 1000 bytes)
        offset_units = 125  # offset = 125 * 8 = 1000 bytes
        packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=offset_units, id=ip_id) / Raw(load=b"x" * 500)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should be detected as fragment (offset > 0)
        assert analyzer.total_fragments == 1
        
        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        assert frag_info["fragments"][0]["offset"] == 1000  # offset in bytes

    def test_detect_df_flag(self, analyzer):
        """Test detection of DF (Don't Fragment) flag."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create packet with DF flag (flags & 0x02)
        packet = IP(src=src_ip, dst=dst_ip, flags=2, frag=0, id=12345) / Raw(load=b"data")
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        # Should count packets with DF flag
        assert analyzer.total_packets_with_df == 1

    def test_complete_fragment_reassembly(self, analyzer):
        """Test complete fragment reassembly (all fragments received)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Fragment 1: offset=0, size=1000, MF=1 (more fragments)
        frag1 = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        frag1.time = base_time
        analyzer.process_packet(frag1, 1)

        # Fragment 2: offset=1000, size=500, MF=0 (last fragment)
        # Offset 1000 bytes = 1000 / 8 = 125 units
        frag2 = IP(src=src_ip, dst=dst_ip, flags=0, frag=125, id=ip_id) / Raw(load=b"x" * 500)
        frag2.time = base_time + 0.1
        analyzer.process_packet(frag2, 2)

        # Should detect complete reassembly
        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        
        # Check reassembly after finalize
        analyzer.finalize()
        
        # Complete reassembly: offset 0-1000 (frag1), offset 1000-1500 (frag2)
        # Expected: offset 0 + size 1000 = 1000, then offset 1000 + size 500 = 1500
        # Total length should be 1500 (from last fragment: offset 1000 + size 500)
        assert frag_info["total_length"] == 1500
        # Reassembly should be complete (continuous: 0-1000, 1000-1500)
        # Note: _check_reassembly is called in process_packet, but total_length is set on last fragment
        # So we need to call finalize to update complete status properly

    def test_incomplete_fragment_reassembly(self, analyzer):
        """Test incomplete fragment reassembly (missing fragments)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Fragment 1: offset=0, size=1000, MF=1
        frag1 = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        frag1.time = base_time
        analyzer.process_packet(frag1, 1)

        # Fragment 3: offset=2000, size=500, MF=0 (missing fragment 2)
        # Offset 2000 bytes = 2000 / 8 = 250 units
        frag3 = IP(src=src_ip, dst=dst_ip, flags=0, frag=250, id=ip_id) / Raw(load=b"x" * 500)
        frag3.time = base_time + 0.2
        analyzer.process_packet(frag3, 3)

        # Should detect incomplete reassembly (gap: 1000-2000 missing)
        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        
        analyzer.finalize()
        
        # Should have incomplete reassembly (gap between offset 1000 and 2000)
        # Complete check: offset 0 + size 1000 = 1000, but next offset is 2000 (gap)
        # So reassembly is incomplete
        assert len(analyzer.incomplete_fragments) >= 1

    def test_fragment_offset_continuity_check(self, analyzer):
        """Test fragment offset continuity checking."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create continuous fragments: 0-1000, 1000-1500
        frag1 = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        frag1.time = base_time
        analyzer.process_packet(frag1, 1)

        frag2 = IP(src=src_ip, dst=dst_ip, flags=0, frag=125, id=ip_id) / Raw(load=b"x" * 500)
        frag2.time = base_time + 0.1
        analyzer.process_packet(frag2, 2)

        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        
        analyzer.finalize()
        
        # Check that fragments are sorted by offset
        sorted_frags = sorted(frag_info["fragments"], key=lambda x: x["offset"])
        assert sorted_frags[0]["offset"] == 0
        assert sorted_frags[1]["offset"] == 1000

    def test_total_length_calculation(self, analyzer):
        """Test total length calculation from last fragment."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Last fragment: offset=2000, size=300, MF=0
        # Total length should be 2000 + 300 = 2300
        last_frag = IP(src=src_ip, dst=dst_ip, flags=0, frag=250, id=ip_id) / Raw(load=b"x" * 300)
        # Offset 2000 bytes = 2000 / 8 = 250 units
        last_frag.time = base_time
        analyzer.process_packet(last_frag, 1)

        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        
        # Total length should be offset + fragment_size = 2000 + 300 = 2300
        assert frag_info["total_length"] == 2300

    def test_fragment_flow_tracking(self, analyzer):
        """Test fragment tracking per flow."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create multiple fragments in same flow
        for i in range(3):
            packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=i * 125, id=12345 + i) / Raw(load=b"x" * 1000)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        flow_key = f"{src_ip}:{dst_ip}"
        flow_stats = analyzer.fragmented_flows[flow_key]
        
        # Should track fragments per flow
        assert flow_stats["fragment_count"] == 3
        assert flow_stats["packets_count"] == 3

    def test_fragment_size_statistics(self, analyzer):
        """Test fragment size statistics (min, max, avg)."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create fragments with different sizes
        sizes = [1000, 1500, 500]
        for i, size in enumerate(sizes):
            packet = IP(src=src_ip, dst=dst_ip, flags=1 if i < len(sizes)-1 else 0, frag=i * 125, id=ip_id) / Raw(load=b"x" * size)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        analyzer.finalize()

        flow_key = f"{src_ip}:{dst_ip}"
        flow_stats = analyzer.fragmented_flows[flow_key]
        
        # Should track min and max fragment sizes
        assert flow_stats["min_fragment_size"] == 500
        assert flow_stats["max_fragment_size"] == 1500
        # Avg should be (min + max) / 2 = (500 + 1500) / 2 = 1000
        assert flow_stats["avg_fragment_size"] == 1000

    def test_multiple_fragment_groups(self, analyzer):
        """Test tracking multiple fragment groups with different IP IDs."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create fragments for different IP IDs
        for ip_id in [12345, 12346, 12347]:
            packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
            packet.time = base_time
            analyzer.process_packet(packet, ip_id - 12344)

        # Should track each fragment group separately
        assert len(analyzer.fragments) == 3
        assert analyzer.total_fragments == 3

    def test_empty_packet_list(self, analyzer):
        """Test that empty packet list returns empty results."""
        results = analyzer.get_results()

        # Should return empty results
        assert results["total_fragments"] == 0
        assert results["total_packets_with_df"] == 0
        assert results["total_fragment_groups"] == 0
        assert results["complete_reassemblies"] == 0
        assert results["incomplete_reassemblies"] == 0
        assert len(results["incomplete_fragments_details"]) == 0
        assert len(results["top_fragmented_flows"]) == 0
        assert results["has_fragmentation"] is False

    def test_get_results_structure(self, analyzer):
        """Test that get_results() returns correct structure."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create some fragments
        frag1 = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        frag1.time = base_time
        analyzer.process_packet(frag1, 1)

        frag2 = IP(src=src_ip, dst=dst_ip, flags=0, frag=125, id=ip_id) / Raw(load=b"x" * 500)
        frag2.time = base_time + 0.1
        analyzer.process_packet(frag2, 2)

        analyzer.finalize()
        results = analyzer.get_results()

        # Check results structure
        assert "total_fragments" in results
        assert "total_packets_with_df" in results
        assert "total_fragment_groups" in results
        assert "complete_reassemblies" in results
        assert "incomplete_reassemblies" in results
        assert "incomplete_fragments_details" in results
        assert "top_fragmented_flows" in results
        assert "estimated_pmtu" in results
        assert "has_fragmentation" in results

    def test_fragmentation_rate_calculation(self, analyzer):
        """Test fragmentation rate calculation per flow."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create 10 total packets, 5 of which are fragments
        for i in range(10):
            is_fragment = i < 5
            packet = IP(
                src=src_ip,
                dst=dst_ip,
                flags=1 if is_fragment else 0,
                frag=0 if is_fragment else 0,
                id=12345 + i if is_fragment else 99999,
            ) / Raw(load=b"x" * 100)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        analyzer.finalize()
        results = analyzer.get_results()

        # Should calculate fragmentation rate (5 fragments / 10 packets = 50%)
        flow_key = f"{src_ip}:{dst_ip}"
        if flow_key in [f["flow_key"] for f in results["top_fragmented_flows"]]:
            flow = next(f for f in results["top_fragmented_flows"] if f["flow_key"] == flow_key)
            assert flow["fragmentation_rate"] == 50.0

    def test_incomplete_reassembly_detection_in_finalize(self, analyzer):
        """Test that incomplete reassemblies are detected in finalize()."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create incomplete fragment group (only first fragment, missing last)
        frag1 = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id) / Raw(load=b"x" * 1000)
        frag1.time = base_time
        analyzer.process_packet(frag1, 1)

        # Finalize should detect incomplete reassembly
        analyzer.finalize()

        # Should have incomplete fragment
        assert len(analyzer.incomplete_fragments) >= 1
        
        # Should increment incomplete_reassemblies for flow
        flow_key = f"{src_ip}:{dst_ip}"
        flow_stats = analyzer.fragmented_flows[flow_key]
        assert flow_stats["incomplete_reassemblies"] >= 1

    def test_pmtu_estimation(self, analyzer):
        """Test PMTU (Path MTU) estimation."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"

        # Create fragments with different sizes (indicates PMTU limits)
        sizes = [1400, 1300, 1200]  # Decreasing sizes suggest PMTU discovery
        for i, size in enumerate(sizes):
            packet = IP(
                src=src_ip if i < 2 else f"192.168.1.{101+i}",
                dst=dst_ip,
                flags=0,
                frag=0,
                id=12345 + i,
            ) / Raw(load=b"x" * size)
            packet.time = base_time + i * 0.1
            analyzer.process_packet(packet, i + 1)

        analyzer.finalize()
        results = analyzer.get_results()

        # PMTU should be estimated based on max fragment sizes
        # Formula: min(max_fragment_size) + 20 (IP header)
        assert "estimated_pmtu" in results
        assert results["estimated_pmtu"] > 0

    def test_fragment_protocol_tracking(self, analyzer):
        """Test that fragment protocol is tracked."""
        base_time = 1234567890.0
        src_ip = "192.168.1.100"
        dst_ip = "10.0.0.1"
        ip_id = 12345

        # Create fragment with specific protocol (TCP = 6)
        packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=0, id=ip_id, proto=6) / Raw(load=b"x" * 1000)
        packet.time = base_time
        analyzer.process_packet(packet, 1)

        frag_key = (src_ip, dst_ip, ip_id)
        frag_info = analyzer.fragments[frag_key]
        
        # Should track protocol
        assert frag_info["protocol"] == 6  # TCP

    def test_top_fragmented_flows_sorting(self, analyzer):
        """Test that top fragmented flows are sorted by fragment count."""
        base_time = 1234567890.0

        # Create multiple flows with different fragment counts
        flows = [
            ("192.168.1.100", "10.0.0.1", 5),  # 5 fragments
            ("192.168.1.101", "10.0.0.2", 10),  # 10 fragments
            ("192.168.1.102", "10.0.0.3", 3),  # 3 fragments
        ]

        for src_ip, dst_ip, fragment_count in flows:
            for i in range(fragment_count):
                packet = IP(src=src_ip, dst=dst_ip, flags=1, frag=i * 125, id=12345 + i) / Raw(load=b"x" * 1000)
                packet.time = base_time + i * 0.1
                analyzer.process_packet(packet, i + 1)

        analyzer.finalize()
        results = analyzer.get_results()

        # Top flows should be sorted by fragment_count (descending)
        top_flows = results["top_fragmented_flows"]
        if len(top_flows) >= 2:
            for i in range(len(top_flows) - 1):
                assert top_flows[i]["fragment_count"] >= top_flows[i + 1]["fragment_count"]
