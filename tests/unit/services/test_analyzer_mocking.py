"""
Tests unitaires pour AnalyzerService avec mocking de tshark et des appels système.
"""

import pytest
from unittest.mock import patch, MagicMock, mock_open
from app.services.analyzer import AnalyzerService, ProgressCallback
from pathlib import Path

@pytest.fixture
def analyzer_service(tmp_path):
    """Create AnalyzerService with a temporary data directory."""
    data_dir = tmp_path / "data"
    return AnalyzerService(data_dir=str(data_dir))

@pytest.mark.asyncio
async def test_analyze_pcap_mocked_success(analyzer_service):
    """
    Establish a mocking strategy for full PCAP analysis.
    Mocks:
    - cli_analyze_pcap_hybrid (to avoid real parsing)
    - _generate_reports (to avoid filesystem/Jinja2 overhead)
    """
    task_id = "test-task-id"
    pcap_path = "/tmp/test.pcap"
    
    mock_results = {
        "metadata": {"total_packets": 100},
        "health_score": {"overall_score": 95.0}
    }
    mock_reports = {
        "html": "/data/reports/test-task-id.html",
        "json": "/data/reports/test-task-id.json"
    }

    # Mock the internal sync analysis method which calls the CLI
    with patch.object(AnalyzerService, "_run_analysis_sync", return_value=mock_results) as mock_run:
        # Mock the report generation
        with patch.object(AnalyzerService, "_generate_reports", return_value=mock_reports) as mock_gen:
            
            result = await analyzer_service.analyze_pcap(task_id, pcap_path)
            
            assert result["results"] == mock_results
            assert result["reports"] == mock_reports
            mock_run.assert_called_once()
            mock_gen.assert_called_once()

@pytest.mark.asyncio
async def test_run_analysis_sync_mocking_tshark(analyzer_service, tmp_path):
    """
    Test mocking of tcpdump/tshark calls within the CLI logic.
    Note: Since AnalyzerService calls cli_analyze_pcap_hybrid,
    we mock the subprocess.run inside that call stack.
    """
    pcap_path = tmp_path / "test.pcap"
    # Minimal valid PCAP header (little-endian)
    pcap_header = bytes.fromhex(
        "d4c3b2a1"  # Magic
        "0200"      # Major version
        "0400"      # Minor version
        "00000000"  # Timezone
        "00000000"  # Sigfigs
        "ffff0000"  # Snaplen
        "01000000"  # Network (Ethernet)
    )
    pcap_path.write_bytes(pcap_header)
    pcap_path = str(pcap_path)
    config = MagicMock()
    
    # Mock subprocess.run to simulate successful tcpdump format detection
    with patch("subprocess.run") as mock_subprocess:
        mock_subprocess.return_value = MagicMock(
            stderr="standard pcap",
            returncode=0
        )
        
        # We also need to mock the analyzers and parser to avoid real work
        with patch("src.cli.FastPacketParser") as mock_parser:
            # Mock both parser instances used in cli.py
            mock_parser.return_value.parse.return_value = []
            
            # Create more robust mocks for analyzers
            mock_analyzers = {}
            analyzer_names = [
                "timestamp", "handshake", "retransmission", "rtt", "window",
                "tcp_reset", "top_talkers", "throughput", "syn_retransmissions",
                "tcp_timeout", "burst", "temporal", "dns", "icmp",
                "protocol_distribution", "jitter", "service_classification"
            ]
            
            for name in analyzer_names:
                m = MagicMock()
                # Default return for any report generation
                m._generate_report.return_value = {"total_packets": 0}
                if name == "protocol_distribution":
                    m._generate_report.return_value = {
                        "total_packets": 100, "layer4_distribution": {}, 
                        "layer4_percentages": {}, "top_tcp_ports": []
                    }
                elif name == "retransmission":
                    m._generate_report.return_value = {"total_retransmissions": 0, "retransmissions": []}
                elif name == "jitter":
                    m._generate_report.return_value = {"total_flows": 0, "high_jitter_flows": [], "global_statistics": {}}
                elif name == "syn_retransmissions":
                    m._generate_report.return_value = {"total_syn_retransmissions": 0}
                elif name == "dns":
                    m._generate_report.return_value = {"total_queries": 0, "timeouts": 0, "errors": 0}
                elif name == "tcp_timeout":
                    m.get_results.return_value = {}
                elif name == "temporal":
                    m._generate_report.return_value = {"gaps": []}
                mock_analyzers[name] = m

            with patch("src.cli.AnalyzerFactory.create_analyzers") as mock_factory:
                mock_factory.return_value = (mock_analyzers, list(mock_analyzers.values()))
                
                # Mock remaining detector initializations in analyze_pcap_hybrid
                with patch("src.cli.ProtocolDistributionAnalyzer") as mock_proto_class, \
                     patch("src.cli.JitterAnalyzer") as mock_jitter_class, \
                     patch("src.cli.ServiceClassifier") as mock_service_class, \
                     patch("src.cli.HealthScoreCalculator") as mock_health_calc:
                    
                    # Mock the .analyze() returns for the instances
                    mock_proto_class.return_value.analyze.return_value = {
                        "total_packets": 100, "layer4_distribution": {}, 
                        "layer4_percentages": {}, "top_tcp_ports": []
                    }
                    mock_jitter_class.return_value.analyze.return_value = {
                        "total_flows": 0, "high_jitter_flows": [], "global_statistics": {}
                    }
                    mock_service_class.return_value.analyze.return_value = {
                        "total_flows": 0, "classification_summary": {"total_flows": 0, "classified_count": 0, "classification_rate": 0.0}
                    }
                    
                    # Also mock the security detectors that are instantiated inside analyze_pcap_hybrid
                    with patch("src.cli.PortScanDetector") as ps, \
                         patch("src.cli.BruteForceDetector") as bf, \
                         patch("src.cli.DDoSDetector") as dd, \
                         patch("src.cli.DNSTunnelingDetector") as dt, \
                         patch("src.cli.DataExfiltrationDetector") as de, \
                         patch("src.cli.C2BeaconingDetector") as c2, \
                         patch("src.cli.LateralMovementDetector") as lm:
                        
                        for d in [ps, bf, dd, dt, de, c2, lm]:
                            d.return_value.analyze.return_value = {}
                    
                        # Mock health score calculation result
                        mock_health_result = MagicMock()
                        mock_health_result.overall_score = 100.0
                        mock_health_result.severity_badge = "✅"
                        mock_health_result.metric_scores = []
                        mock_health_result.recommendations = []
                        mock_health_calc.return_value.calculate.return_value = mock_health_result
                        
                        results = analyzer_service._run_analysis_sync(pcap_path, config)
                    
                    # Verify tcpdump was called for format detection
                    # Find the call that uses tcpdump
                    tcpdump_calls = [call for call in mock_subprocess.call_args_list if "tcpdump" in call.args[0]]
                    assert len(tcpdump_calls) > 0
                    assert any("test.pcap" in arg for arg in tcpdump_calls[0].args[0])

@pytest.mark.asyncio
async def test_translate_error_to_human():
    """Test error translation for various system/parsing errors."""
    from app.services.analyzer import translate_error_to_human
    
    # Test corruption error
    err = Exception("got 10 bytes, needed at least 24")
    assert "corrompu" in translate_error_to_human(err)
    
    # Test permission error
    err = PermissionError("Permission denied")
    assert "permissions" in translate_error_to_human(err)
    
    # Test file not found
    err = FileNotFoundError("No such file or directory")
    assert "pas été trouvé" in translate_error_to_human(err)
