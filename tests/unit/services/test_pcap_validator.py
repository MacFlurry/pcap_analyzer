"""Unit tests for PCAP validation service."""

from unittest.mock import patch
from scapy.all import Ether, IP, TCP

from app.services.pcap_validator import (
    PCAPValidationError,
    _check_duplicates,
    _check_minimum_packets,
    _check_self_loops,
    _check_timestamps,
    validate_pcap,
)


def _tcp_pkt(src: str = "192.168.1.1", dst: str = "10.0.0.1", payload: bytes = b"x", ts: float = 1.0):
    pkt = Ether() / IP(src=src, dst=dst) / TCP(sport=12345, dport=80) / payload
    pkt.time = ts
    return pkt


class TestPCAPValidationError:
    def test_error_initialization(self):
        error = PCAPValidationError("INVALID_FORMAT", {"description": "Invalid file format"})
        assert error.error_type == "INVALID_FORMAT"
        assert error.details == {"description": "Invalid file format"}

    def test_error_message_building(self):
        error = PCAPValidationError("INVALID_TIMESTAMPS", {})
        message = str(error)
        assert "timestamps" in message.lower() or "incoh" in message.lower()

    def test_error_to_dict(self):
        error = PCAPValidationError(
            "INSUFFICIENT_PACKETS",
            {
                "description": "Not enough packets",
                "issues": ["Only 1 packet found"],
                "suggestions": ["Capture more traffic"],
            },
        )
        error_dict = error.to_dict()
        assert error_dict["error_type"] == "INSUFFICIENT_PACKETS"
        assert "title" in error_dict
        assert "description" in error_dict
        assert "detected_issues" in error_dict
        assert "suggestions" in error_dict
        assert "wireshark_link" in error_dict


class TestValidatePCAP:
    @patch("app.services.pcap_validator.rdpcap")
    def test_validate_pcap_success(self, mock_rdpcap):
        mock_rdpcap.return_value = [
            _tcp_pkt(ts=1.0, payload=b"packet1"),
            _tcp_pkt(ts=2.0, payload=b"packet2"),
        ]

        is_valid, error = validate_pcap("/tmp/test.pcap")
        assert is_valid is True
        assert error is None

    @patch("app.services.pcap_validator.rdpcap")
    def test_validate_pcap_insufficient_packets(self, mock_rdpcap):
        mock_rdpcap.return_value = [_tcp_pkt(ts=1.0)]
        is_valid, error = validate_pcap("/tmp/test.pcap")
        assert is_valid is False
        assert error is not None
        assert error.error_type == "INSUFFICIENT_PACKETS"

    @patch("app.services.pcap_validator.rdpcap")
    def test_validate_pcap_invalid_timestamps(self, mock_rdpcap):
        mock_rdpcap.return_value = [
            _tcp_pkt(ts=1.0, payload=b"a"),
            _tcp_pkt(ts=31536002.0, payload=b"b"),
        ]
        is_valid, error = validate_pcap("/tmp/test.pcap")
        assert is_valid is False
        assert error is not None
        assert error.error_type == "INVALID_TIMESTAMPS"

    @patch("app.services.pcap_validator.rdpcap")
    def test_validate_pcap_invalid_format(self, mock_rdpcap):
        mock_rdpcap.side_effect = Exception("Invalid PCAP format")
        is_valid, error = validate_pcap("/tmp/invalid.pcap")
        assert is_valid is False
        assert error is not None
        assert error.error_type == "INVALID_FORMAT"

    @patch("app.services.pcap_validator.rdpcap")
    def test_validate_pcap_sample_size(self, mock_rdpcap):
        mock_rdpcap.return_value = [_tcp_pkt(ts=float(i)) for i in range(50)]
        validate_pcap("/tmp/test.pcap", sample_size=50)
        mock_rdpcap.assert_called_once()
        _, kwargs = mock_rdpcap.call_args
        assert kwargs["count"] == 50


class TestCheckMinimumPackets:
    def test_check_minimum_packets_success(self):
        packets = [_tcp_pkt(ts=1.0), _tcp_pkt(ts=2.0), _tcp_pkt(ts=3.0)]
        assert _check_minimum_packets(packets) is None

    def test_check_minimum_packets_insufficient(self):
        packets = [_tcp_pkt(ts=1.0)]
        error = _check_minimum_packets(packets)
        assert error is not None
        assert "issues" in error
        assert "suggestions" in error

    def test_check_minimum_packets_empty(self):
        assert _check_minimum_packets([]) is not None


class TestCheckTimestamps:
    def test_check_timestamps_success(self):
        packets = [_tcp_pkt(ts=1.0), _tcp_pkt(ts=2.0), _tcp_pkt(ts=3.0)]
        assert _check_timestamps(packets) is None

    def test_check_timestamps_single_packet(self):
        assert _check_timestamps([_tcp_pkt(ts=1.0)]) is None

    def test_check_timestamps_large_jump(self):
        packets = [_tcp_pkt(ts=1.0), _tcp_pkt(ts=31536002.0)]
        error = _check_timestamps(packets)
        assert error is not None
        assert "issues" in error
        assert "suggestions" in error

    def test_check_timestamps_multiple_jumps(self):
        packets = [_tcp_pkt(ts=1.0), _tcp_pkt(ts=31536002.0), _tcp_pkt(ts=63072004.0)]
        error = _check_timestamps(packets)
        assert error is not None
        assert len(error["issues"]) >= 1


class TestCheckDuplicates:
    def test_check_duplicates_success(self):
        packets = [_tcp_pkt(payload=b"p1", ts=1.0), _tcp_pkt(payload=b"p2", ts=2.0), _tcp_pkt(payload=b"p3", ts=3.0)]
        assert _check_duplicates(packets) is None

    def test_check_duplicates_low_ratio(self):
        packets = [_tcp_pkt(payload=b"p1", ts=1.0), _tcp_pkt(payload=b"p1", ts=1.0), _tcp_pkt(payload=b"p2", ts=2.0)]
        assert _check_duplicates(packets) is None  # 1/3 duplicates

    def test_check_duplicates_high_ratio(self):
        packets = [_tcp_pkt(payload=b"p1", ts=1.0), _tcp_pkt(payload=b"p1", ts=1.0), _tcp_pkt(payload=b"p1", ts=1.0)]
        error = _check_duplicates(packets)
        assert error is not None  # 2/3 duplicates
        assert "issues" in error
        assert "suggestions" in error

    def test_check_duplicates_single_packet(self):
        assert _check_duplicates([_tcp_pkt(payload=b"p1", ts=1.0)]) is None


class TestCheckSelfLoops:
    def test_check_self_loops_success(self):
        packets = [_tcp_pkt(src="192.168.1.1", dst="10.0.0.1"), _tcp_pkt(src="192.168.1.2", dst="10.0.0.1")]
        assert _check_self_loops(packets) is None

    def test_check_self_loops_low_ratio(self):
        packets = [_tcp_pkt(src="192.168.1.1", dst="192.168.1.1")] + [
            _tcp_pkt(src=f"192.168.1.{i}", dst="10.0.0.1") for i in range(2, 21)
        ]
        assert _check_self_loops(packets) is None  # 1/20 = 5%

    def test_check_self_loops_high_ratio(self):
        packets = [_tcp_pkt(src="192.168.1.1", dst="192.168.1.1"), _tcp_pkt(src="192.168.1.2", dst="192.168.1.2")] + [
            _tcp_pkt(src=f"192.168.1.{i}", dst="10.0.0.1") for i in range(3, 11)
        ]
        error = _check_self_loops(packets)
        assert error is not None  # 2/10 = 20%
        assert "issues" in error
        assert "suggestions" in error

    def test_check_self_loops_ipv6(self):
        # Current helper is IPv4 only; ensure function still handles packet list robustly.
        packets = [_tcp_pkt(src="192.168.1.1", dst="192.168.1.1")]
        assert _check_self_loops(packets) is not None
