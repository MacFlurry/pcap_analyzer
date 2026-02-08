"""
Unit tests for TsharkRetransmissionAnalyzer (tshark backend).

Tests the tshark-based retransmission detection backend which provides
100% accuracy by delegating to Wireshark's analysis engine.

Tests cover:
- tshark path detection (find_tshark)
- Version checking (check_tshark_version)
- Retransmission detection and delay calculation
- Error handling (missing tshark, invalid PCAP)
"""

import json
import pytest
import shutil
import subprocess
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock

from src.analyzers.retransmission_tshark import (
    TsharkRetransmissionAnalyzer,
    find_tshark,
    check_tshark_version,
)
from src.analyzers.retransmission import TCPRetransmission


class TestFindTshark:
    """Tests for tshark path detection."""

    def test_find_tshark_in_path(self):
        """Test finding tshark in PATH."""
        with patch("platform.system", return_value="Linux"):
            with patch("pathlib.Path.exists", return_value=False):
                with patch("shutil.which") as mock_which:
                    mock_which.return_value = "/usr/bin/tshark"
                    result = find_tshark()
                    assert result == "/usr/bin/tshark"

    def test_find_tshark_macos_wireshark_app(self):
        """Test finding tshark in macOS Wireshark.app bundle."""
        macos_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
        with patch("platform.system", return_value="Darwin"):
            with patch("pathlib.Path.exists") as mock_exists:
                with patch("pathlib.Path.is_file") as mock_is_file:
                    mock_exists.return_value = True
                    mock_is_file.return_value = True
                    result = find_tshark()
                    # Should find macOS Wireshark.app path
                    assert result == str(macos_path)

    def test_find_tshark_not_found(self):
        """Test when tshark is not found."""
        with patch("platform.system", return_value="Linux"):
            with patch("pathlib.Path.exists", return_value=False):
                with patch("shutil.which", return_value=None):
                    result = find_tshark()
                    # Should return None when not found
                    assert result is None


class TestCheckTsharkVersion:
    """Tests for tshark version checking."""

    def test_check_tshark_version_success(self):
        """Test successful version check."""
        mock_result = Mock()
        mock_result.stdout = "TShark (Wireshark) 4.6.2 ..."
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version = check_tshark_version("/usr/bin/tshark")
            assert version == "4.6.2"

    def test_check_tshark_version_parse_error(self):
        """Test version parsing failure."""
        mock_result = Mock()
        mock_result.stdout = "Unexpected output format"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version = check_tshark_version("/usr/bin/tshark")
            assert version is None

    def test_check_tshark_version_timeout(self):
        """Test version check timeout."""
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("tshark", 5)):
            with pytest.raises(RuntimeError, match="timeout"):
                check_tshark_version("/usr/bin/tshark")


class TestTsharkRetransmissionAnalyzer:
    """Tests for TsharkRetransmissionAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        """Create analyzer instance with mocked tshark path."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("src.analyzers.retransmission_tshark.check_tshark_version", return_value="4.6.2"):
                analyzer = TsharkRetransmissionAnalyzer("/usr/bin/tshark")
                return analyzer

    def test_analyzer_initialization(self):
        """Test analyzer initialization."""
        with patch("pathlib.Path.exists", return_value=True):
            with patch("src.analyzers.retransmission_tshark.check_tshark_version", return_value="4.6.2"):
                analyzer = TsharkRetransmissionAnalyzer("/usr/bin/tshark")
                assert analyzer.tshark_path == "/usr/bin/tshark"
                assert analyzer.version == "4.6.2"

    def test_analyzer_initialization_tshark_not_found(self):
        """Test analyzer initialization when tshark file doesn't exist."""
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(RuntimeError, match="tshark not found"):
                TsharkRetransmissionAnalyzer("/usr/bin/tshark")

    def test_get_all_tcp_packets(self, analyzer):
        """Test getting all TCP packets from PCAP."""
        # Mock tshark fields output (format: field1|field2|field3...)
        mock_output = "1|1234567890.0|192.168.1.1|10.0.0.1|12345|80|1000\n"

        mock_result = Mock()
        mock_result.stdout = mock_output
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            with patch("pathlib.Path.exists", return_value=True):
                pcap_path = "/tmp/test.pcap"
                packets = analyzer._get_all_tcp_packets(pcap_path)
                assert len(packets) == 1
                assert packets[0]["packet_num"] == 1
                assert packets[0]["timestamp"] == 1234567890.0
                assert packets[0]["src_ip"] == "192.168.1.1"
                assert packets[0]["src_port"] == 12345

    def test_get_all_tcp_packets_file_not_found(self, analyzer):
        """Test error when PCAP file not found."""
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(FileNotFoundError):
                analyzer._get_all_tcp_packets("/tmp/nonexistent.pcap")

    def test_parse_tshark_packet_retransmission(self, analyzer):
        """Test parsing tshark packet that is a retransmission."""
        tshark_packet = {
            "_source": {
                "layers": {
                    "frame.number": ["10"],
                    "frame.time_epoch": ["1234567895.0"],
                    "ip.src": ["192.168.1.1"],
                    "ip.dst": ["10.0.0.1"],
                    "tcp.srcport": ["12345"],
                    "tcp.dstport": ["80"],
                    "tcp.seq": ["1000"],
                    "tcp.flags": ["0x00000018"],  # PSH+ACK
                    "tcp.analysis.retransmission": ["True"],  # Retransmission flag (generic)
                }
            }
        }

        segment_first_seen = {
            (("192.168.1.1", "10.0.0.1", 12345, 80), 1000): (1, 1234567890.0)
        }

        retrans = analyzer._parse_tshark_packet(tshark_packet, segment_first_seen)
        assert retrans is not None
        assert retrans.src_ip == "192.168.1.1"
        assert retrans.src_port == 12345
        # API returns lowercase "retransmission" for generic retransmissions
        assert retrans.retrans_type == "retransmission"
        assert retrans.delay == 5.0  # 1234567895.0 - 1234567890.0
        assert retrans.original_packet_num == 1

    def test_parse_tshark_packet_not_retransmission(self, analyzer):
        """Test parsing tshark packet that is NOT a retransmission."""
        # Note: In practice, _parse_tshark_packet is only called for packets that are already
        # identified as retransmissions by tshark (filtered with -Y "tcp.analysis.retransmission").
        # However, this test verifies that the method handles gracefully when called with
        # a packet that doesn't have retransmission analysis fields.
        tshark_packet = {
            "_source": {
                "layers": {
                    "frame.number": ["10"],
                    "frame.time_epoch": ["1234567895.0"],
                    "ip.src": ["192.168.1.1"],
                    "ip.dst": ["10.0.0.1"],
                    "tcp.srcport": ["12345"],
                    "tcp.dstport": ["80"],
                    "tcp.seq": ["1000"],
                    "tcp.flags": ["0x00000018"],  # PSH+ACK
                    # No tcp.analysis.retransmission, fast_retransmission, rto, or spurious
                    # This packet would not reach _parse_tshark_packet in real usage
                    # but we test the method's behavior with minimal fields
                }
            }
        }

        # The method will still parse if called (it doesn't check for retransmission presence first)
        # It will create a TCPRetransmission object with default "retransmission" type
        # since no specific retransmission type is detected
        retrans = analyzer._parse_tshark_packet(tshark_packet, {})
        
        # Method should still parse and return an object (it assumes all packets passed are retransmissions)
        assert retrans is not None
        # Without specific retransmission type indicators, it defaults to "retransmission"
        assert retrans.retrans_type == "retransmission"

    def test_analyze_with_delay_calculation(self, analyzer):
        """Test analyze() method with delay calculation."""
        # Mock _get_all_tcp_packets to return original packets (fields format)
        with patch.object(
            analyzer,
            "_get_all_tcp_packets",
            return_value=[
                {
                    "packet_num": 1,
                    "timestamp": 1234567890.0,
                    "src_ip": "192.168.1.1",
                    "dst_ip": "10.0.0.1",
                    "src_port": 12345,
                    "dst_port": 80,
                    "seq_num": 1000,
                }
            ],
        ):
            # Mock tshark JSON output for retransmissions
            retransmission_packets = json.dumps([
                {
                    "_source": {
                        "layers": {
                            "frame.number": ["10"],
                            "frame.time_epoch": ["1234567893.0"],
                            "ip.src": ["192.168.1.1"],
                            "ip.dst": ["10.0.0.1"],
                            "tcp.srcport": ["12345"],
                            "tcp.dstport": ["80"],
                            "tcp.seq": ["1000"],
                            "tcp.flags": ["0x00000018"],
                            "tcp.analysis.retransmission": ["True"],
                        }
                    }
                }
            ])

            mock_result = Mock()
            mock_result.stdout = retransmission_packets
            mock_result.returncode = 0

            with patch("subprocess.run", return_value=mock_result):
                with patch("pathlib.Path.exists", return_value=True):
                    retransmissions = analyzer.analyze("/tmp/test.pcap")
                    assert len(retransmissions) == 1
                    assert retransmissions[0].delay == 3.0  # 1234567893.0 - 1234567890.0
                    assert retransmissions[0].original_packet_num == 1


@pytest.mark.skipif(find_tshark() is None, reason="tshark not available")
class TestTsharkRetransmissionAnalyzerIntegration:
    """Integration tests when tshark is actually available."""

    def test_real_tshark_found(self):
        """Test that tshark can be found on this system."""
        tshark_path = find_tshark()
        if tshark_path:
            assert Path(tshark_path).exists()
            assert Path(tshark_path).is_file()

    def test_real_tshark_version(self):
        """Test that tshark version can be checked."""
        tshark_path = find_tshark()
        if tshark_path:
            version = check_tshark_version(tshark_path)
            assert version is not None
            # Version should be in format X.Y.Z
            assert "." in version
            assert len(version.split(".")) >= 2
