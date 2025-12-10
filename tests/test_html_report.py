"""
Test suite for HTML Report Generator

Tests professional HTML report generation with:
- Executive summary
- Interactive charts (protocol distribution, jitter, service classification)
- Timeline visualization
- Detailed metrics tables
- Responsive design
- Self-contained HTML (no external dependencies)
"""

import json
import os
import tempfile
from pathlib import Path

import pytest


class TestHTMLReportBasics:
    """Test basic HTML report generation functionality."""

    def test_generate_basic_report(self):
        """Test generating a basic HTML report from analysis results."""
        from src.exporters.html_report import HTMLReportGenerator

        # Minimal analysis results
        results = {
            "metadata": {
                "pcap_file": "test.pcap",
                "total_packets": 100,
                "capture_duration": 10.0,
            },
            "health_score": {
                "overall_score": 95.0,
                "severity": "excellent",
                "summary": "Network is healthy",
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should be valid HTML
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html
        assert "<head>" in html
        assert "<body>" in html

    def test_report_contains_metadata(self):
        """Test report includes file metadata."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "metadata": {
                "pcap_file": "capture.pcap",
                "total_packets": 1000,
                "capture_duration": 60.0,
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        assert "capture.pcap" in html
        assert "1000" in html or "1,000" in html

    def test_report_saves_to_file(self):
        """Test saving report to file."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {"metadata": {"pcap_file": "test.pcap"}}

        generator = HTMLReportGenerator()

        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False) as f:
            output_path = f.name

        try:
            generator.save(results, output_path)
            assert os.path.exists(output_path)

            # Should be readable HTML
            with open(output_path) as f:
                content = f.read()
                assert "<!DOCTYPE html>" in content
        finally:
            if os.path.exists(output_path):
                os.unlink(output_path)


class TestHealthScoreVisualization:
    """Test health score visualization in HTML report."""

    def test_health_score_display(self):
        """Test health score is prominently displayed."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "health_score": {
                "overall_score": 87.5,
                "severity": "good",
                "summary": "Minor issues detected",
                "component_scores": {
                    "retransmission": {"score": 90.0, "weight": 0.3},
                    "rtt": {"score": 85.0, "weight": 0.25},
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should show score and severity
        assert "87.5" in html or "87" in html or "88" in html
        assert "good" in html.lower() or "Good" in html

    def test_component_scores_displayed(self):
        """Test individual component scores are shown."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "health_score": {
                "component_scores": {
                    "retransmission": {"score": 95.0, "weight": 0.3},
                    "rtt": {"score": 88.0, "weight": 0.25},
                    "jitter": {"score": 92.0, "weight": 0.2},
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should list component scores
        assert "retransmission" in html.lower()
        assert "rtt" in html.lower()
        assert "jitter" in html.lower()


class TestProtocolDistributionCharts:
    """Test protocol distribution visualization."""

    def test_protocol_chart_data(self):
        """Test protocol distribution chart includes data."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "protocol_distribution": {
                "layer4_distribution": {"TCP": 800, "UDP": 200},
                "layer4_percentages": {"TCP": 80.0, "UDP": 20.0},
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should have chart or visualization
        assert "TCP" in html
        assert "UDP" in html
        assert "80" in html or "800" in html

    def test_service_distribution_chart(self):
        """Test service distribution visualization."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "protocol_distribution": {
                "service_distribution": {
                    "HTTP": 300,
                    "HTTPS": 400,
                    "DNS": 100,
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        assert "HTTP" in html
        assert "HTTPS" in html
        assert "DNS" in html


class TestServiceClassificationVisualization:
    """Test service classification visualization."""

    def test_service_types_displayed(self):
        """Test service classification results are shown."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "service_classification": {
                "service_classifications": {
                    "VoIP": 5,
                    "Streaming": 3,
                    "Interactive": 10,
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        assert "VoIP" in html
        assert "Streaming" in html
        assert "Interactive" in html

    def test_classification_rate_shown(self):
        """Test classification rate is displayed."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "service_classification": {
                "classification_summary": {
                    "total_flows": 20,
                    "classified_count": 18,
                    "classification_rate": 90.0,
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        assert "90" in html or "18" in html


class TestJitterVisualization:
    """Test jitter analysis visualization."""

    def test_jitter_statistics_displayed(self):
        """Test jitter statistics are shown."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "jitter": {
                "global_statistics": {
                    "mean_jitter": 0.015,
                    "max_jitter": 0.050,
                    "stdev_jitter": 0.008,
                },
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should show jitter stats (in ms)
        assert "jitter" in html.lower()
        assert "15" in html or "0.015" in html  # 15ms


class TestReportStyling:
    """Test report styling and presentation."""

    def test_report_has_css(self):
        """Test report includes CSS styling."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {"metadata": {"pcap_file": "test.pcap"}}

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should have inline CSS
        assert "<style>" in html or "style=" in html

    def test_report_is_responsive(self):
        """Test report has responsive design."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {"metadata": {"pcap_file": "test.pcap"}}

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should have viewport meta tag or responsive CSS
        assert "viewport" in html.lower() or "responsive" in html.lower() or "@media" in html

    def test_report_self_contained(self):
        """Test report is self-contained (no external dependencies)."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {"metadata": {"pcap_file": "test.pcap"}}

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should not reference external resources (CDN, etc.)
        assert "cdn." not in html.lower()
        assert "http://" not in html and "https://" not in html


class TestCompleteReport:
    """Test complete report generation with all features."""

    def test_full_report_all_sections(self):
        """Test complete report with all analysis sections."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {
            "metadata": {
                "pcap_file": "full_capture.pcap",
                "total_packets": 10000,
                "capture_duration": 300.0,
            },
            "health_score": {
                "overall_score": 92.0,
                "severity": "good",
                "component_scores": {
                    "retransmission": {"score": 95.0},
                    "rtt": {"score": 90.0},
                },
            },
            "protocol_distribution": {
                "layer4_distribution": {"TCP": 8000, "UDP": 2000},
                "service_distribution": {"HTTP": 3000, "HTTPS": 5000},
            },
            "jitter": {
                "global_statistics": {"mean_jitter": 0.012, "max_jitter": 0.045},
            },
            "service_classification": {
                "service_classifications": {"VoIP": 5, "Streaming": 10},
            },
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should have all major sections
        assert "health" in html.lower()
        assert "protocol" in html.lower()
        assert "jitter" in html.lower()
        assert "service" in html.lower()


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_empty_results(self):
        """Test report generation with minimal data."""
        from src.exporters.html_report import HTMLReportGenerator

        results = {}

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should generate valid HTML even with no data
        assert "<!DOCTYPE html>" in html
        assert "<html" in html

    def test_missing_optional_sections(self):
        """Test report handles missing optional sections gracefully."""
        from src.exporters.html_report import HTMLReportGenerator

        # Only metadata, no analysis results
        results = {
            "metadata": {"pcap_file": "test.pcap", "total_packets": 100},
        }

        generator = HTMLReportGenerator()
        html = generator.generate(results)

        # Should still generate valid report
        assert "<!DOCTYPE html>" in html
        assert "test.pcap" in html


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
