"""
Unit tests for RetransmissionAnalyzer using PacketMetadata.
This improves coverage for the performance-optimized _process_metadata() path.
"""

import pytest
from src.analyzers.retransmission import RetransmissionAnalyzer
from src.parsers.fast_parser import PacketMetadata
import dpkt
from dataclasses import asdict

@pytest.fixture
def analyzer():
    return RetransmissionAnalyzer()

def create_tcp_metadata(
    packet_num: int,
    timestamp: float,
    src_ip: str = "1.1.1.1",
    dst_ip: str = "2.2.2.2",
    src_port: int = 12345,
    dst_port: int = 80,
    seq: int = 1000,
    ack: int = 0,
    flags: int = dpkt.tcp.TH_ACK,
    payload_len: int = 100
):
    metadata = PacketMetadata(
        packet_num=packet_num,
        timestamp=timestamp,
        src_ip=src_ip,
        dst_ip=dst_ip,
        ip_version=4,
        ttl=64,
        total_length=40 + payload_len,
        packet_length=54 + payload_len,
        protocol="TCP",
        src_port=src_port,
        dst_port=dst_port,
        tcp_seq=seq,
        tcp_ack=ack,
        tcp_flags=flags,
        tcp_window=8192,
        tcp_payload_len=payload_len
    )
    # Trigger __post_init__ to set convenience flags
    metadata.__post_init__()
    return metadata

class TestRetransmissionMetadata:
    """Test retransmission detection using PacketMetadata."""

    def test_basic_retransmission_metadata(self, analyzer):
        """Test detection of a simple retransmission using metadata."""
        # 1. First transmission
        m1 = create_tcp_metadata(1, 100.0, seq=1000, payload_len=100)
        analyzer._process_metadata(m1, 1)
        
        # 2. Retransmission
        m2 = create_tcp_metadata(2, 100.2, seq=1000, payload_len=100)
        analyzer._process_metadata(m2, 2)
        
        results = analyzer.finalize()
        assert results["total_retransmissions"] == 1
        assert len(results["retransmissions"]) == 1
        assert results["retransmissions"][0]["packet_num"] == 2
        assert results["retransmissions"][0]["original_packet_num"] == 1

    def test_spurious_retransmission_metadata(self, analyzer):
        """Test detection of spurious retransmission (already ACKed)."""
        # 1. A -> B: Data (seq=1000, len=100)
        m1 = create_tcp_metadata(1, 100.0, src_ip="A", dst_ip="B", src_port=12345, dst_port=80, seq=1000, payload_len=100)
        analyzer._process_metadata(m1, 1)
        
        # 2. B -> A: ACK 1100 (Acknowledge the data)
        m2 = create_tcp_metadata(2, 100.1, src_ip="B", dst_ip="A", src_port=80, dst_port=12345, seq=5000, ack=1100, flags=dpkt.tcp.TH_ACK, payload_len=0)
        analyzer._process_metadata(m2, 2)
        
        # 3. A -> B: Data (seq=1000, len=100) - SPURIOUS (already ACKed)
        m3 = create_tcp_metadata(3, 100.2, src_ip="A", dst_ip="B", src_port=12345, dst_port=80, seq=1000, payload_len=100)
        analyzer._process_metadata(m3, 3)
        
        results = analyzer.finalize()
        assert results["total_retransmissions"] == 1
        # Check diagnosis fields
        retrans = results["retransmissions"][0]
        assert retrans["confidence"] == "high"
        assert retrans["retrans_type"] == "Spurious Retransmission"

    def test_non_tcp_metadata_ignored(self, analyzer):
        """Test that non-TCP metadata is correctly ignored."""
        m1 = create_tcp_metadata(1, 100.0)
        m1.protocol = "UDP"
        analyzer._process_metadata(m1, 1)
        
        results = analyzer.finalize()
        assert results["total_retransmissions"] == 0

    def test_cleanup_old_segments_metadata(self, analyzer):
        """Test that old segments are cleaned up periodically."""
        # Force cleanup interval to 10 for testing
        analyzer._cleanup_interval = 10
        analyzer._max_segments_per_flow = 4  # Keep only 2 newest on cleanup
        
        # Start with a SYN to establish ISN
        isn = 10000
        m_syn = create_tcp_metadata(0, 99.0, seq=isn, payload_len=0, flags=dpkt.tcp.TH_SYN)
        analyzer._process_metadata(m_syn, 0)

        # 1. Send 10 unique segments to trigger cleanup
        # Segments: (isn+1, 100), (isn+101, 100), ..., (isn+901, 100)
        for i in range(10):
            m = create_tcp_metadata(i+1, 100.0 + i, seq=isn + i*100 + 1, payload_len=100)
            analyzer._process_metadata(m, i+1)
            
        # Cleanup triggered on packet 10 (10th packet overall, excluding SYN if SYN was not counted)
        # Wait, _packet_counter increments for every TCP packet.
        # Packet 0 (SYN): counter=1
        # Packets 1-9: counter=2-10 -> Cleanup triggers at packet 9!
        # Packets 10: counter=11
        
        # Cleanup keeps 2 newest unique segments.
        
        # 2. Retransmit packet 1 (seq=isn+1) - Should be cleaned up
        m_old = create_tcp_metadata(11, 110.0, seq=isn+1, payload_len=100)
        analyzer._process_metadata(m_old, 11)
        
        # 3. Retransmit packet 9 (seq=isn+801) - SHOULD be detected (was kept)
        m_new = create_tcp_metadata(12, 110.1, seq=isn + 801, payload_len=100)
        analyzer._process_metadata(m_new, 12)
        
        results = analyzer.finalize()
        
        # Find packet 12 retransmission
        retrans_12 = next(r for r in results["retransmissions"] if r["packet_num"] == 12)
        assert retrans_12["original_packet_num"] == 9
        
        # Packet 11 retransmission should NOT be linked to original_packet_num 1
        retrans_11 = next(r for r in results["retransmissions"] if r["packet_num"] == 11)
        assert retrans_11["original_packet_num"] != 1

    def test_syn_retransmission_metadata(self, analyzer):
        """Test detection of SYN retransmissions."""
        # 1. First SYN
        m1 = create_tcp_metadata(1, 100.0, seq=1000, payload_len=0, flags=dpkt.tcp.TH_SYN)
        analyzer._process_metadata(m1, 1)
        
        # 2. SYN Retransmission (1s later)
        m2 = create_tcp_metadata(2, 101.0, seq=1000, payload_len=0, flags=dpkt.tcp.TH_SYN)
        analyzer._process_metadata(m2, 2)
        
        results = analyzer.finalize()
        assert results["total_retransmissions"] == 1
        assert results["retransmissions"][0]["is_syn_retrans"] is True
        assert results["retransmissions"][0]["retrans_type"] == "RTO"

    def test_fast_retransmission_metadata(self, analyzer):
        """Test detection of Fast Retransmissions (triggered by 3+ DUP ACKs)."""
        rev_key = "2.2.2.2:80->1.1.1.1:12345"
        
        # 1. A -> B: Data 1 (seq=1000, len=100)
        m1 = create_tcp_metadata(1, 100.0, src_ip="1.1.1.1", dst_ip="2.2.2.2", seq=1000, payload_len=100)
        analyzer._process_metadata(m1, 1)
        
        # 2. A -> B: Data 2 (seq=1100, len=100) - LOST
        
        # 3. A -> B: Data 3 (seq=1200, len=100)
        m3 = create_tcp_metadata(3, 100.1, src_ip="1.1.1.1", dst_ip="2.2.2.2", seq=1200, payload_len=100)
        analyzer._process_metadata(m3, 3)
        
        # 4. B -> A: Initial ACK (ack=1100)
        m4 = create_tcp_metadata(4, 100.2, src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=12345, seq=5000, ack=1100)
        analyzer._process_metadata(m4, 4)
        
        # 5. B -> A: DUP ACK 1 (ack=1100)
        m5 = create_tcp_metadata(5, 100.3, src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=12345, seq=5001, ack=1100, payload_len=0)
        analyzer._process_metadata(m5, 5)
        
        # 6. B -> A: DUP ACK 2 (ack=1100)
        m6 = create_tcp_metadata(6, 100.4, src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=12345, seq=5002, ack=1100, payload_len=0)
        analyzer._process_metadata(m6, 6)
        
        # 7. B -> A: DUP ACK 3 (ack=1100)
        m7 = create_tcp_metadata(7, 100.5, src_ip="2.2.2.2", dst_ip="1.1.1.1", src_port=80, dst_port=12345, seq=5003, ack=1100, payload_len=0)
        analyzer._process_metadata(m7, 7)
        
        # 8. A -> B: Data 2 (seq=1100, len=100) - FAST RETRANSMISSION
        m8 = create_tcp_metadata(8, 100.6, src_ip="1.1.1.1", dst_ip="2.2.2.2", seq=1100, payload_len=100)
        analyzer._process_metadata(m8, 8)
        
        results = analyzer.finalize()
        retrans = next(r for r in results["retransmissions"] if r["seq_num"] == 1100)
        
        assert retrans["retrans_type"] == "Fast Retransmission"
        assert retrans["confidence"] == "medium"
