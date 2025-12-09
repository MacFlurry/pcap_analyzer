from typing import Any, Dict, List, Tuple

from .analyzers import (
    AsymmetricTrafficAnalyzer,
    BurstAnalyzer,
    DNSAnalyzer,
    ICMPAnalyzer,
    IPFragmentationAnalyzer,
    RetransmissionAnalyzer,
    RTTAnalyzer,
    SackAnalyzer,
    SYNRetransmissionAnalyzer,
    TCPHandshakeAnalyzer,
    TCPResetAnalyzer,
    TCPTimeoutAnalyzer,
    TCPWindowAnalyzer,
    TemporalPatternAnalyzer,
    ThroughputAnalyzer,
    TimestampAnalyzer,
    TopTalkersAnalyzer,
)


class AnalyzerFactory:
    @staticmethod
    def create_analyzers(config: Any, latency_filter: float = None) -> Tuple[Dict[str, Any], List[Any]]:
        """
        Create all analyzers with configuration.

        Returns:
            Tuple of (analyzer_dict, analyzer_list) for convenient access
        """
        thresholds = config.thresholds

        # 1. Timestamps
        gap_threshold = latency_filter if latency_filter else thresholds.get("packet_gap", 1.0)
        timestamp_analyzer = TimestampAnalyzer(gap_threshold=gap_threshold)

        # 2. TCP Handshake
        handshake_analyzer = TCPHandshakeAnalyzer(
            syn_synack_threshold=thresholds.get("syn_synack_delay", 0.1),
            total_threshold=thresholds.get("handshake_total", 0.3),
            latency_filter=latency_filter,
        )

        # 3. Retransmissions
        retrans_analyzer = RetransmissionAnalyzer(
            retrans_low=thresholds.get("retransmission_low", 10),
            retrans_medium=thresholds.get("retransmission_medium", 50),
            retrans_critical=thresholds.get("retransmission_critical", 100),
            retrans_rate_low=thresholds.get("retransmission_rate_low", 1.0),
            retrans_rate_medium=thresholds.get("retransmission_rate_medium", 3.0),
            retrans_rate_critical=thresholds.get("retransmission_rate_critical", 5.0),
            rto_threshold_ms=thresholds.get("rto_threshold_ms", 200.0),
            fast_retrans_delay_max_ms=thresholds.get("fast_retrans_delay_max_ms", 50.0),
        )

        # 4. RTT
        rtt_analyzer = RTTAnalyzer(
            rtt_warning=thresholds.get("rtt_warning", 0.1),
            rtt_critical=thresholds.get("rtt_critical", 0.5),
            latency_filter=latency_filter,
        )

        # 5. TCP Window
        window_analyzer = TCPWindowAnalyzer(
            low_window_threshold=thresholds.get("low_window_threshold", 8192),
            zero_window_duration=thresholds.get("zero_window_duration", 0.1),
        )

        # 6. ICMP / PMTU
        icmp_analyzer = ICMPAnalyzer()

        # 7. DNS
        dns_analyzer = DNSAnalyzer(
            response_warning=thresholds.get("dns_response_warning", 0.1),
            response_critical=thresholds.get("dns_response_critical", 1.0),
            timeout=thresholds.get("dns_timeout", 5.0),
            latency_filter=latency_filter,
        )

        # 8. Retransmissions SYN détaillées
        syn_threshold = latency_filter if latency_filter else thresholds.get("syn_retrans_threshold", 2.0)
        syn_retrans_analyzer = SYNRetransmissionAnalyzer(threshold=syn_threshold)

        # 9. TCP Reset
        tcp_reset_analyzer = TCPResetAnalyzer()

        # 10. Fragmentation IP
        ip_fragmentation_analyzer = IPFragmentationAnalyzer()

        # 11. Top Talkers
        top_talkers_analyzer = TopTalkersAnalyzer()

        # 12. Throughput
        throughput_analyzer = ThroughputAnalyzer()

        # 13. TCP Timeout
        tcp_timeout_analyzer = TCPTimeoutAnalyzer(
            idle_threshold=thresholds.get("tcp_idle_threshold", 30.0),
            zombie_threshold=thresholds.get("tcp_zombie_threshold", 60.0),
        )

        # 14. Asymmetric Traffic
        asymmetric_analyzer = AsymmetricTrafficAnalyzer(
            asymmetry_threshold=thresholds.get("asymmetry_threshold", 0.3),
            min_bytes_threshold=thresholds.get("asymmetry_min_bytes", 10000),
        )

        # 15. Burst Analyzer
        burst_analyzer = BurstAnalyzer(
            interval_ms=thresholds.get("burst_interval_ms", 100),
            burst_threshold_multiplier=thresholds.get("burst_threshold_multiplier", 3.0),
            min_packets_for_burst=thresholds.get("burst_min_packets", 50),
        )

        # 16. Temporal Pattern Analyzer
        temporal_analyzer = TemporalPatternAnalyzer(slot_duration_seconds=thresholds.get("temporal_slot_duration", 60))

        # 17. SACK Analyzer
        sack_analyzer = SackAnalyzer()

        # Dictionary for named access
        analyzer_dict = {
            "timestamp": timestamp_analyzer,
            "handshake": handshake_analyzer,
            "retransmission": retrans_analyzer,
            "rtt": rtt_analyzer,
            "window": window_analyzer,
            "icmp": icmp_analyzer,
            "dns": dns_analyzer,
            "syn_retransmissions": syn_retrans_analyzer,
            "tcp_reset": tcp_reset_analyzer,
            "ip_fragmentation": ip_fragmentation_analyzer,
            "top_talkers": top_talkers_analyzer,
            "throughput": throughput_analyzer,
            "tcp_timeout": tcp_timeout_analyzer,
            "asymmetric_traffic": asymmetric_analyzer,
            "burst": burst_analyzer,
            "temporal": temporal_analyzer,
            "sack": sack_analyzer,
        }

        # List for streaming processing
        analyzer_list = [
            timestamp_analyzer,
            handshake_analyzer,
            retrans_analyzer,
            rtt_analyzer,
            window_analyzer,
            icmp_analyzer,
            dns_analyzer,
            syn_retrans_analyzer,
            tcp_reset_analyzer,
            ip_fragmentation_analyzer,
            top_talkers_analyzer,
            throughput_analyzer,
            tcp_timeout_analyzer,
            asymmetric_analyzer,
            burst_analyzer,
            temporal_analyzer,
            sack_analyzer,
        ]

        return analyzer_dict, analyzer_list
