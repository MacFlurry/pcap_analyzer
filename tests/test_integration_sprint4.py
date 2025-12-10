"""
Sprint 4 Integration Tests

Tests end-to-end functionality of Sprint 4 features:
- HTML Report Generation
- CSV Export
- CLI Integration with export options
- Combined export workflows

Ensures all Sprint 4 components work together correctly.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest
from scapy.all import IP, TCP, UDP, Ether

from src.analyzers.health_score import HealthScoreCalculator
from src.analyzers.jitter_analyzer import JitterAnalyzer
from src.analyzers.protocol_distribution import ProtocolDistributionAnalyzer
from src.analyzers.service_classifier import ServiceClassifier
from src.exporters.csv_export import CSVExporter
from src.exporters.html_report import HTMLReportGenerator


@pytest.mark.integration
class TestHTMLReportIntegration:
    """Integration tests for HTML report generation."""

    def test_html_report_with_complete_results(self):
        """Test HTML report generation with all Sprint 1-4 data."""
        # Generate packets
        packets = []
        # VoIP
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=10000, dport=5004) / (b"V" * 160)
            pkt.time = 1.0 + i * 0.02
            packets.append(pkt)

        # Streaming
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=50000, dport=443) / (b"S" * 1400)
            pkt.time = 1.0 + i * 0.01
            packets.append(pkt)

        # Analyze with all analyzers
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()
        health_calculator = HealthScoreCalculator()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Combine results
        combined_results = {
            "metadata": {
                "pcap_file": "test.pcap",
                "total_packets": len(packets),
                "capture_duration": 2.0,
            },
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "service_classification": service_results,
            "retransmission": {"total_retransmissions": 0},
            "rtt": {"global_statistics": {"mean_rtt": 0.02}},
            "timestamps": {"total_packets": len(packets), "gaps_detected": 0},
            "handshake": {"total_handshakes": 1, "failed_handshakes": 0},
        }

        # Calculate health score
        health_score = health_calculator.calculate(combined_results)
        combined_results["health_score"] = health_score

        # Generate HTML report
        html_gen = HTMLReportGenerator()
        html = html_gen.generate(combined_results)

        # Verify report contains all sections
        assert "<!DOCTYPE html>" in html
        assert "Health Score" in html or "health" in html.lower()
        assert "Protocol" in html or "protocol" in html.lower()
        assert "Jitter" in html or "jitter" in html.lower()
        assert "Service" in html or "service" in html.lower()

    def test_html_report_saves_to_file(self):
        """Test HTML report can be saved to file."""
        results = {
            "metadata": {"pcap_file": "test.pcap", "total_packets": 100},
            "health_score": {"overall_score": 95.0, "severity": "excellent"},
        }

        html_gen = HTMLReportGenerator()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            html_gen.save(results, output_path)
            assert os.path.exists(output_path)

            # Should be valid HTML
            with open(output_path) as f:
                content = f.read()
                assert "<!DOCTYPE html>" in content
                assert "test.pcap" in content
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


@pytest.mark.integration
class TestCSVExportIntegration:
    """Integration tests for CSV export."""

    def test_csv_export_all_with_complete_results(self):
        """Test CSV export with all Sprint 1-4 data."""
        # Generate packets
        packets = []
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=10000, dport=5004) / (b"V" * 160)
            pkt.time = 1.0 + i * 0.02
            packets.append(pkt)

        # Analyze
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Combine results
        combined_results = {
            "metadata": {
                "pcap_file": "test.pcap",
                "total_packets": len(packets),
                "capture_duration": 1.0,
            },
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "service_classification": service_results,
            "health_score": {"overall_score": 90.0, "severity": "good"},
        }

        # Export to directory
        csv_exporter = CSVExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_exporter.export_all(combined_results, tmpdir)

            # Should create multiple CSV files
            files = os.listdir(tmpdir)
            assert len(files) > 0

            # Check for expected files
            assert "summary.csv" in files
            assert "protocol_distribution.csv" in files
            assert "service_classification.csv" in files

    def test_csv_files_are_valid(self):
        """Test exported CSV files are valid and parseable."""
        import csv

        results = {
            "metadata": {"pcap_file": "test.pcap", "total_packets": 100},
            "protocol_distribution": {
                "layer4_distribution": {"TCP": 80, "UDP": 20},
                "layer4_percentages": {"TCP": 80.0, "UDP": 20.0},
            },
        }

        csv_exporter = CSVExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_exporter.export_all(results, tmpdir)

            # Read protocol_distribution.csv
            csv_file = os.path.join(tmpdir, "protocol_distribution.csv")
            assert os.path.exists(csv_file)

            with open(csv_file) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 2
                assert rows[0]["Protocol"] in ["TCP", "UDP"]


@pytest.mark.integration
class TestCombinedExport:
    """Test combined HTML + CSV export workflows."""

    def test_export_both_formats(self):
        """Test exporting both HTML and CSV simultaneously."""
        # Generate complete results
        packets = []
        for i in range(20):
            pkt = Ether() / IP() / TCP(sport=12345, dport=80)
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        protocol_analyzer = ProtocolDistributionAnalyzer()
        protocol_results = protocol_analyzer.analyze(packets)

        results = {
            "metadata": {"pcap_file": "test.pcap", "total_packets": 20},
            "protocol_distribution": protocol_results,
            "health_score": {"overall_score": 88.0, "severity": "good"},
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            # Export HTML
            html_path = os.path.join(tmpdir, "report.html")
            html_gen = HTMLReportGenerator()
            html_gen.save(results, html_path)

            # Export CSV
            csv_dir = os.path.join(tmpdir, "csv")
            csv_exporter = CSVExporter()
            csv_exporter.export_all(results, csv_dir)

            # Verify both exist
            assert os.path.exists(html_path)
            assert os.path.exists(csv_dir)
            assert len(os.listdir(csv_dir)) > 0


@pytest.mark.integration
class TestExportWithAllSprints:
    """Test exports with data from all Sprints 1-4."""

    def test_complete_pipeline_all_sprints(self):
        """Test complete pipeline with all Sprint 1-4 features and export."""
        # Create diverse traffic
        packets = []

        # VoIP
        for i in range(50):
            pkt = Ether() / IP(src="192.168.1.1", dst="10.0.0.1") / UDP(sport=10000, dport=5004) / (b"V" * 160)
            pkt.time = 1.0 + i * 0.02
            packets.append(pkt)

        # HTTP
        for i in range(30):
            pkt = Ether() / IP(src="192.168.1.2", dst="10.0.0.2") / TCP(sport=50000 + i, dport=80) / (b"H" * 600)
            pkt.time = 1.0 + i * 0.1
            packets.append(pkt)

        # Run all analyzers (Sprints 1-3)
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()
        health_calculator = HealthScoreCalculator()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Combine
        combined_results = {
            "metadata": {
                "pcap_file": "complete_test.pcap",
                "total_packets": len(packets),
                "capture_duration": 3.0,
            },
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "service_classification": service_results,
            "retransmission": {"total_retransmissions": 0, "unique_retransmitted_segments": 0, "total_flows": 2},
            "rtt": {"global_statistics": {"mean_rtt": 0.02, "median_rtt": 0.02}},
            "timestamps": {"total_packets": len(packets), "gaps_detected": 0},
            "handshake": {"total_handshakes": 2, "failed_handshakes": 0},
        }

        health_score = health_calculator.calculate(combined_results)
        combined_results["health_score"] = health_score

        # Sprint 4: Export both formats
        with tempfile.TemporaryDirectory() as tmpdir:
            # Export HTML (Sprint 4)
            html_path = os.path.join(tmpdir, "complete_report.html")
            html_gen = HTMLReportGenerator()
            html_gen.save(combined_results, html_path)

            # Export CSV (Sprint 4)
            csv_dir = os.path.join(tmpdir, "csv_data")
            csv_exporter = CSVExporter()
            csv_exporter.export_all(combined_results, csv_dir)

            # Verify exports
            assert os.path.exists(html_path)
            assert os.path.exists(csv_dir)

            # Verify HTML contains all data
            with open(html_path) as f:
                html_content = f.read()
                assert "complete_test.pcap" in html_content
                assert health_score.severity in html_content

            # Verify CSV files exist
            csv_files = os.listdir(csv_dir)
            assert "summary.csv" in csv_files
            assert "protocol_distribution.csv" in csv_files


@pytest.mark.integration
class TestBackwardsCompatibilitySprint4:
    """Test Sprint 4 doesn't break existing functionality."""

    def test_sprints_1_2_3_still_work(self):
        """Test that Sprints 1-3 analyzers work alongside Sprint 4 exports."""
        packets = [
            Ether() / IP() / TCP(sport=12345, dport=80),
            Ether() / IP() / UDP(sport=10000, dport=5004) / (b"V" * 160),
        ]
        for i, pkt in enumerate(packets):
            pkt.time = 1.0 + i * 0.1

        # Sprints 1-3 analyzers
        protocol_analyzer = ProtocolDistributionAnalyzer()
        jitter_analyzer = JitterAnalyzer()
        service_classifier = ServiceClassifier()

        protocol_results = protocol_analyzer.analyze(packets)
        jitter_results = jitter_analyzer.analyze(packets)
        service_results = service_classifier.analyze(packets)

        # Should all work
        assert protocol_results["total_packets"] == 2
        assert jitter_results["total_flows"] >= 0
        assert service_results["total_flows"] >= 0

        # Sprint 4 exports should also work
        results = {
            "protocol_distribution": protocol_results,
            "jitter": jitter_results,
            "service_classification": service_results,
        }

        with tempfile.TemporaryDirectory() as tmpdir:
            html_gen = HTMLReportGenerator()
            html_gen.save(results, os.path.join(tmpdir, "test.html"))

            csv_exporter = CSVExporter()
            csv_exporter.export_all(results, tmpdir)

            # Should create files
            assert os.path.exists(os.path.join(tmpdir, "test.html"))


@pytest.mark.integration
class TestExportEdgeCases:
    """Test export edge cases and error handling."""

    def test_export_with_minimal_data(self):
        """Test exports work with minimal data."""
        results = {"metadata": {"pcap_file": "minimal.pcap"}}

        with tempfile.TemporaryDirectory() as tmpdir:
            # HTML should work
            html_gen = HTMLReportGenerator()
            html_gen.save(results, os.path.join(tmpdir, "minimal.html"))

            # CSV should work
            csv_exporter = CSVExporter()
            csv_exporter.export_all(results, tmpdir)

            # Should create valid files
            assert os.path.exists(os.path.join(tmpdir, "minimal.html"))
            assert os.path.exists(os.path.join(tmpdir, "summary.csv"))

    def test_export_with_empty_results(self):
        """Test exports handle empty results gracefully."""
        results = {}

        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not crash
            html_gen = HTMLReportGenerator()
            html_gen.save(results, os.path.join(tmpdir, "empty.html"))

            csv_exporter = CSVExporter()
            csv_exporter.export_all(results, tmpdir)

            # Should create files (even if minimal)
            assert os.path.exists(os.path.join(tmpdir, "empty.html"))


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
