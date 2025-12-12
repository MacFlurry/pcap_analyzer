"""
Test suite for CSV Export functionality

Tests CSV export of analysis results:
- Protocol distribution
- Service classification
- Jitter statistics
- Flow details
- Summary metrics
"""

import csv
import os
import tempfile
from pathlib import Path

import pytest


class TestCSVExportBasics:
    """Test basic CSV export functionality."""

    def test_export_protocol_distribution(self):
        """Test exporting protocol distribution to CSV."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "protocol_distribution": {
                "layer4_distribution": {"TCP": 800, "UDP": 200},
                "layer4_percentages": {"TCP": 80.0, "UDP": 20.0},
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_protocol_distribution(results, output_path)
            assert os.path.exists(output_path)

            # Read and verify CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 2
                assert rows[0]["Protocol"] == "TCP"
                assert rows[0]["Count"] == "800"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_export_service_classification(self):
        """Test exporting service classification to CSV."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "service_classification": {
                "service_classifications": {
                    "DNS": 5,
                    "Streaming": 10,
                    "Interactive": 15,
                },
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_service_classification(results, output_path)
            assert os.path.exists(output_path)

            # Read and verify CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 3
                service_types = [row["Service Type"] for row in rows]
                assert "DNS" in service_types
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_export_jitter_statistics(self):
        """Test exporting jitter statistics to CSV."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "jitter": {
                "flows_with_jitter": {
                    "192.168.1.1:1000 -> 10.0.0.1:80 (TCP)": {
                        "mean_jitter": 0.015,
                        "max_jitter": 0.050,
                        "packet_count": 100,
                    },
                },
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_jitter_statistics(results, output_path)
            assert os.path.exists(output_path)

            # Read and verify CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert "192.168.1.1" in rows[0]["Flow"]
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestCSVExportFlows:
    """Test flow export functionality."""

    def test_export_classified_flows(self):
        """Test exporting classified flows to CSV."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "service_classification": {
                "classified_flows": {
                    "192.168.1.1:1000 -> 10.0.0.1:80 (TCP)": {
                        "service_type": "Interactive",
                        "confidence": 0.85,
                        "packet_count": 50,
                        "avg_packet_size": 600,
                    },
                },
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_classified_flows(results, output_path)
            assert os.path.exists(output_path)

            # Read and verify CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) == 1
                assert rows[0]["Service Type"] == "Interactive"
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestCSVExportSummary:
    """Test summary export functionality."""

    def test_export_summary(self):
        """Test exporting executive summary to CSV."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "metadata": {
                "pcap_file": "test.pcap",
                "total_packets": 1000,
                "capture_duration": 60.0,
            },
            "health_score": {
                "overall_score": 95.0,
                "severity": "excellent",
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_summary(results, output_path)
            assert os.path.exists(output_path)

            # Read and verify CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) > 0
                metrics = {row["Metric"]: row["Value"] for row in rows}
                assert "Total Packets" in metrics
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestCSVExportAll:
    """Test exporting all data at once."""

    def test_export_all_to_directory(self):
        """Test exporting all data to directory."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "metadata": {"pcap_file": "test.pcap", "total_packets": 1000},
            "protocol_distribution": {"layer4_distribution": {"TCP": 800, "UDP": 200}},
            "service_classification": {"service_classifications": {"DNS": 5}},
            "jitter": {"global_statistics": {"mean_jitter": 0.015}},
        }

        exporter = CSVExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            exporter.export_all(results, tmpdir)

            # Should create multiple CSV files
            files = os.listdir(tmpdir)
            assert len(files) > 0

            # Check for expected files
            assert any("summary" in f.lower() for f in files)
            assert any("protocol" in f.lower() for f in files)


class TestCSVFormatting:
    """Test CSV formatting and structure."""

    def test_csv_has_headers(self):
        """Test CSV files have proper headers."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "protocol_distribution": {
                "layer4_distribution": {"TCP": 800},
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_protocol_distribution(results, output_path)

            with open(output_path) as f:
                reader = csv.DictReader(f)
                assert reader.fieldnames is not None
                assert len(reader.fieldnames) > 0
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_csv_proper_quoting(self):
        """Test CSV properly quotes fields with commas."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "service_classification": {
                "classified_flows": {
                    "192.168.1.1:1000 -> 10.0.0.1:80 (TCP)": {
                        "service_type": "Web, Interactive",
                        "confidence": 0.85,
                    },
                },
            },
        }

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            exporter.export_classified_flows(results, output_path)

            # Should be valid CSV
            with open(output_path) as f:
                reader = csv.DictReader(f)
                rows = list(reader)
                assert len(rows) > 0
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_export_empty_results(self):
        """Test exporting empty results doesn't crash."""
        from src.exporters.csv_export import CSVExporter

        results = {}

        exporter = CSVExporter()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".csv", delete=False) as f:
            output_path = f.name

        try:
            # Should not raise exception
            exporter.export_summary(results, output_path)
            assert os.path.exists(output_path)
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)

    def test_export_missing_sections(self):
        """Test exporting when optional sections are missing."""
        from src.exporters.csv_export import CSVExporter

        results = {
            "metadata": {"pcap_file": "test.pcap"},
        }

        exporter = CSVExporter()

        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not raise exception
            exporter.export_all(results, tmpdir)

            # Should create at least summary file
            files = os.listdir(tmpdir)
            assert len(files) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
