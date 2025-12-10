"""
CSV Export Module

Exports analysis results to CSV format:
- Protocol distribution
- Service classification
- Jitter statistics
- Flow details
- Summary metrics
"""

import csv
import os
from pathlib import Path
from typing import Any, Dict, List


class CSVExporter:
    """Exports analysis results to CSV files."""

    def __init__(self):
        pass

    def export_protocol_distribution(self, results: Dict[str, Any], output_path: str):
        """
        Export protocol distribution to CSV.

        Args:
            results: Analysis results dictionary
            output_path: Path to output CSV file
        """
        proto_data = results.get("protocol_distribution", {})
        layer4_dist = proto_data.get("layer4_distribution", {})
        layer4_pct = proto_data.get("layer4_percentages", {})

        rows = []
        for protocol, count in sorted(layer4_dist.items(), key=lambda x: x[1], reverse=True):
            percentage = layer4_pct.get(protocol, 0)
            rows.append(
                {
                    "Protocol": protocol,
                    "Count": count,
                    "Percentage": f"{percentage:.2f}%",
                }
            )

        if rows:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Protocol", "Count", "Percentage"])
                writer.writeheader()
                writer.writerows(rows)
        else:
            # Write empty file with headers
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Protocol", "Count", "Percentage"])
                writer.writeheader()

    def export_service_classification(self, results: Dict[str, Any], output_path: str):
        """
        Export service classification to CSV.

        Args:
            results: Analysis results dictionary
            output_path: Path to output CSV file
        """
        service_data = results.get("service_classification", {})
        service_types = service_data.get("service_classifications", {})

        rows = []
        total = sum(service_types.values())
        for service, count in sorted(service_types.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            rows.append(
                {
                    "Service Type": service,
                    "Flow Count": count,
                    "Percentage": f"{percentage:.2f}%",
                }
            )

        if rows:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Service Type", "Flow Count", "Percentage"])
                writer.writeheader()
                writer.writerows(rows)
        else:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Service Type", "Flow Count", "Percentage"])
                writer.writeheader()

    def export_jitter_statistics(self, results: Dict[str, Any], output_path: str):
        """
        Export jitter statistics to CSV.

        Args:
            results: Analysis results dictionary
            output_path: Path to output CSV file
        """
        jitter_data = results.get("jitter", {})
        flows = jitter_data.get("flows_with_jitter", {})

        rows = []
        for flow_key, stats in flows.items():
            mean_jitter = stats.get("mean_jitter", 0) * 1000  # Convert to ms
            max_jitter = stats.get("max_jitter", 0) * 1000
            packet_count = stats.get("packet_count", 0)

            rows.append(
                {
                    "Flow": flow_key,
                    "Mean Jitter (ms)": f"{mean_jitter:.3f}",
                    "Max Jitter (ms)": f"{max_jitter:.3f}",
                    "Packet Count": packet_count,
                }
            )

        if rows:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Flow", "Mean Jitter (ms)", "Max Jitter (ms)", "Packet Count"])
                writer.writeheader()
                writer.writerows(rows)
        else:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=["Flow", "Mean Jitter (ms)", "Max Jitter (ms)", "Packet Count"])
                writer.writeheader()

    def export_classified_flows(self, results: Dict[str, Any], output_path: str):
        """
        Export classified flows to CSV.

        Args:
            results: Analysis results dictionary
            output_path: Path to output CSV file
        """
        service_data = results.get("service_classification", {})
        classified_flows = service_data.get("classified_flows", {})

        rows = []
        for flow_key, flow_info in classified_flows.items():
            service_type = flow_info.get("service_type", "Unknown")
            confidence = flow_info.get("confidence", 0)
            packet_count = flow_info.get("packet_count", 0)
            avg_packet_size = flow_info.get("avg_packet_size", 0)

            rows.append(
                {
                    "Flow": flow_key,
                    "Service Type": service_type,
                    "Confidence": f"{confidence:.2f}",
                    "Packets": packet_count,
                    "Avg Packet Size": f"{avg_packet_size:.0f}",
                }
            )

        if rows:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["Flow", "Service Type", "Confidence", "Packets", "Avg Packet Size"]
                )
                writer.writeheader()
                writer.writerows(rows)
        else:
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(
                    f, fieldnames=["Flow", "Service Type", "Confidence", "Packets", "Avg Packet Size"]
                )
                writer.writeheader()

    def export_summary(self, results: Dict[str, Any], output_path: str):
        """
        Export executive summary to CSV.

        Args:
            results: Analysis results dictionary
            output_path: Path to output CSV file
        """
        rows = []

        # Metadata
        metadata = results.get("metadata", {})
        if "pcap_file" in metadata:
            rows.append({"Metric": "PCAP File", "Value": metadata["pcap_file"]})
        if "total_packets" in metadata:
            rows.append({"Metric": "Total Packets", "Value": str(metadata["total_packets"])})
        if "capture_duration" in metadata:
            rows.append({"Metric": "Capture Duration (s)", "Value": f"{metadata['capture_duration']:.2f}"})

        # Health score
        health_data = results.get("health_score", {})
        if health_data:
            # Handle both dict and dataclass
            if hasattr(health_data, "overall_score"):
                score = health_data.overall_score
                severity = health_data.severity
            else:
                score = health_data.get("overall_score", 0)
                severity = health_data.get("severity", "unknown")

            rows.append({"Metric": "Health Score", "Value": f"{score:.1f}"})
            rows.append({"Metric": "Severity", "Value": severity})

        # Protocol distribution summary
        proto_data = results.get("protocol_distribution", {})
        if proto_data:
            layer4_dist = proto_data.get("layer4_distribution", {})
            for proto, count in layer4_dist.items():
                rows.append({"Metric": f"{proto} Packets", "Value": str(count)})

        # Service classification summary
        service_data = results.get("service_classification", {})
        if service_data:
            summary = service_data.get("classification_summary", {})
            if "total_flows" in summary:
                rows.append({"Metric": "Total Flows", "Value": str(summary["total_flows"])})
            if "classified_count" in summary:
                rows.append({"Metric": "Classified Flows", "Value": str(summary["classified_count"])})
            if "classification_rate" in summary:
                rows.append({"Metric": "Classification Rate (%)", "Value": f"{summary['classification_rate']:.1f}"})

        # Jitter summary
        jitter_data = results.get("jitter", {})
        if jitter_data:
            global_stats = jitter_data.get("global_statistics", {})
            if "mean_jitter" in global_stats:
                mean_jitter_ms = global_stats["mean_jitter"] * 1000
                rows.append({"Metric": "Mean Jitter (ms)", "Value": f"{mean_jitter_ms:.3f}"})

        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["Metric", "Value"])
            writer.writeheader()
            writer.writerows(rows)

    def export_all(self, results: Dict[str, Any], output_dir: str):
        """
        Export all data to multiple CSV files in a directory.

        Args:
            results: Analysis results dictionary
            output_dir: Path to output directory
        """
        # Create output directory if it doesn't exist
        os.makedirs(output_dir, exist_ok=True)

        # Export summary
        self.export_summary(results, os.path.join(output_dir, "summary.csv"))

        # Export protocol distribution if available
        if "protocol_distribution" in results:
            self.export_protocol_distribution(results, os.path.join(output_dir, "protocol_distribution.csv"))

        # Export service classification if available
        if "service_classification" in results:
            self.export_service_classification(results, os.path.join(output_dir, "service_classification.csv"))

            # Also export classified flows
            if results["service_classification"].get("classified_flows"):
                self.export_classified_flows(results, os.path.join(output_dir, "classified_flows.csv"))

        # Export jitter statistics if available
        if "jitter" in results:
            self.export_jitter_statistics(results, os.path.join(output_dir, "jitter_statistics.csv"))
