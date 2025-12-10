"""
Health Score Calculator for Network Performance Analysis

Implements RFC 2330 & ITU-T Y.1541 compliant health scoring system.
Calculates a comprehensive network health score (0-100) based on six
weighted metrics with QoS classification.

References:
    RFC 2330: Framework for IP Performance Metrics (IPPM)
    RFC 2680: One-way Packet Loss Metric for IPPM
    RFC 3393: IP Packet Delay Variation (Jitter) Metric for IPPM
    RFC 6349: Framework for TCP Throughput Testing
    RFC 7680: TCP Loss Detection Algorithms
    ITU-T Y.1541: Network Performance Objectives for IP-based Services
    ITU-T G.114: One-way Transmission Time

Author: PCAP Analyzer Team
"""

from dataclasses import dataclass
from typing import Any, Dict, List

# RFC 7680: TCP Loss Detection Algorithms - Retransmission thresholds
RFC_7680_RETRANS_GOOD = 0.01  # <1% is good
RFC_7680_RETRANS_ACCEPTABLE = 0.03  # 1-3% is acceptable
RFC_7680_RETRANS_POOR = 0.05  # 3-5% is poor
RFC_7680_RETRANS_CRITICAL = 0.10  # >10% is critical

# ITU-T G.114: One-way Transmission Time - RTT thresholds (in seconds)
ITU_T_G114_RTT_EXCELLENT = 0.050  # <50ms excellent
ITU_T_G114_RTT_GOOD = 0.150  # <150ms good
ITU_T_G114_RTT_ACCEPTABLE = 0.400  # 150-400ms acceptable
ITU_T_G114_RTT_POOR = 0.800  # 400-800ms poor
ITU_T_G114_RTT_CRITICAL = 2.000  # >800ms critical

# RFC 3393: IP Packet Delay Variation (Jitter) thresholds (in seconds)
RFC_3393_JITTER_GOOD = 0.020  # <20ms is good
RFC_3393_JITTER_ACCEPTABLE = 0.050  # 20-50ms is acceptable
RFC_3393_JITTER_POOR = 0.100  # 50-100ms is poor
RFC_3393_JITTER_CRITICAL = 0.200  # >200ms is critical

# RFC 2680: Packet Loss thresholds
RFC_2680_LOSS_GOOD = 0.005  # <0.5% is good
RFC_2680_LOSS_ACCEPTABLE = 0.02  # 0.5-2% is acceptable
RFC_2680_LOSS_POOR = 0.05  # 2-5% is poor
RFC_2680_LOSS_CRITICAL = 0.10  # >10% is critical

# DNS error thresholds (percentage of transactions)
DNS_ERROR_GOOD = 0.01  # <1% errors is good
DNS_ERROR_ACCEPTABLE = 0.05  # 1-5% errors is acceptable
DNS_ERROR_POOR = 0.15  # 5-15% errors is poor
DNS_ERROR_CRITICAL = 0.30  # >30% errors is critical

# Protocol anomaly thresholds (per 1000 packets)
ANOMALY_RATE_GOOD = 10.0  # <10 per 1000 packets is good
ANOMALY_RATE_ACCEPTABLE = 50.0  # 10-50 per 1000 packets is acceptable
ANOMALY_RATE_POOR = 150.0  # 50-150 per 1000 packets is poor
ANOMALY_RATE_CRITICAL = 500.0  # >500 per 1000 packets is critical

# Metric weights (total must equal 100)
WEIGHT_TCP_RETRANS = 25
WEIGHT_PACKET_LOSS = 20
WEIGHT_RTT = 20
WEIGHT_DNS = 15
WEIGHT_JITTER = 10
WEIGHT_ANOMALIES = 10

# Maximum penalties per metric
MAX_PENALTY_PER_METRIC = 100

# QoS Class thresholds per ITU-T Y.1541
QOS_CLASS_0_MIN = 95  # Excellent (95-100)
QOS_CLASS_1_MIN = 85  # Good (85-94)
QOS_CLASS_2_MIN = 65  # Acceptable (65-84)
QOS_CLASS_3_MIN = 45  # Poor (45-64)
QOS_CLASS_4_MIN = 25  # Critical (25-44)
# QOS_CLASS_5 = 0-24 (Emergency)


@dataclass
class MetricScore:
    """
    Individual metric score with penalty and threshold information.

    Attributes:
        metric_name: Human-readable metric name
        raw_value: Raw measured value (e.g., 0.05 for 5% retransmission rate)
        penalty: Unweighted penalty points (0-100)
        weight: Metric weight as percentage (0-100)
        weighted_penalty: Final penalty contribution (penalty * weight / 100)
        threshold_status: 'excellent', 'good', 'acceptable', 'poor', or 'critical'
        rfc_reference: Reference to RFC/ITU standard
    """

    metric_name: str
    raw_value: float
    penalty: float
    weight: int
    weighted_penalty: float
    threshold_status: str
    rfc_reference: str


@dataclass
class HealthScoreResult:
    """
    Complete health score analysis result.

    Attributes:
        overall_score: Final health score (0-100, higher is better)
        qos_class: ITU-T Y.1541 QoS class (0-5, lower is better)
        severity: Text severity level
        severity_badge: Emoji badge for severity
        total_penalty: Sum of all weighted penalties
        metric_scores: List of individual metric scores
        recommendations: List of actionable recommendations
    """

    overall_score: float
    qos_class: int
    severity: str
    severity_badge: str
    total_penalty: float
    metric_scores: List[MetricScore]
    recommendations: List[str]


class HealthScoreCalculator:
    """
    RFC 2330 & ITU-T Y.1541 compliant network health score calculator.

    Calculates a comprehensive health score (0-100) based on six weighted metrics:
    1. TCP Retransmissions (25%)
    2. Packet Loss Rate (20%)
    3. RTT/Latency (20%)
    4. DNS Errors (15%)
    5. Jitter/IPDV (10%)
    6. Protocol Anomalies (10%)

    The score uses piecewise linear penalty functions for each metric and
    classifies network quality into six ITU-T Y.1541 QoS classes.

    Example:
        calculator = HealthScoreCalculator()
        result = calculator.calculate(analysis_results)
        print(f"Health Score: {result.overall_score}")
        print(f"QoS Class: {result.qos_class}")
    """

    def __init__(self):
        """Initialize the health score calculator."""
        pass

    def calculate(self, analysis_results: Dict[str, Any]) -> HealthScoreResult:
        """
        Calculate comprehensive network health score.

        Analyzes multiple network performance metrics and computes a weighted
        health score according to RFC 2330 and ITU-T Y.1541 standards.

        Args:
            analysis_results: Dictionary containing analysis results with keys:
                - 'timestamps': Total packets and duration
                - 'retransmission': TCP retransmission data
                - 'rtt': Round-trip time statistics
                - 'dns': DNS transaction data

        Returns:
            HealthScoreResult containing overall score, QoS class, severity,
            individual metric scores, and recommendations.

        Algorithm:
            1. Extract raw values from analysis results
            2. Calculate penalty for each metric (0-100)
            3. Apply weights to penalties
            4. Overall score = 100 - total_penalty
            5. Classify into QoS class
            6. Generate recommendations
        """
        # Extract data safely
        total_packets = self._safe_get(analysis_results, ["timestamps", "total_packets"], 0)

        # Calculate individual metric scores
        metric_scores = []

        # 1. TCP Retransmissions (25%)
        tcp_retrans_score = self._calculate_tcp_retransmission_penalty(analysis_results, total_packets)
        metric_scores.append(tcp_retrans_score)

        # 2. Packet Loss Rate (20%)
        packet_loss_score = self._calculate_packet_loss_penalty(analysis_results, total_packets)
        metric_scores.append(packet_loss_score)

        # 3. RTT/Latency (20%)
        rtt_score = self._calculate_rtt_penalty(analysis_results)
        metric_scores.append(rtt_score)

        # 4. DNS Errors (15%)
        dns_score = self._calculate_dns_penalty(analysis_results)
        metric_scores.append(dns_score)

        # 5. Jitter/IPDV (10%)
        jitter_score = self._calculate_jitter_penalty(analysis_results)
        metric_scores.append(jitter_score)

        # 6. Protocol Anomalies (10%)
        anomaly_score = self._calculate_anomaly_penalty(analysis_results, total_packets)
        metric_scores.append(anomaly_score)

        # Calculate total penalty and overall score
        total_penalty = sum(m.weighted_penalty for m in metric_scores)
        overall_score = max(0.0, min(100.0, 100.0 - total_penalty))

        # Classify QoS class and severity
        qos_class = self._classify_qos_class(overall_score)
        severity, severity_badge = self._get_severity(qos_class)

        # Generate recommendations
        recommendations = self._generate_recommendations(metric_scores, analysis_results)

        return HealthScoreResult(
            overall_score=round(overall_score, 1),
            qos_class=qos_class,
            severity=severity,
            severity_badge=severity_badge,
            total_penalty=round(total_penalty, 1),
            metric_scores=metric_scores,
            recommendations=recommendations,
        )

    def _calculate_tcp_retransmission_penalty(
        self, analysis_results: Dict[str, Any], total_packets: int
    ) -> MetricScore:
        """
        Calculate penalty for TCP retransmissions per RFC 7680.

        Penalty function (piecewise linear):
        - 0% retrans: 0 penalty
        - 1% retrans: 10 penalty (RFC 7680 good threshold)
        - 3% retrans: 25 penalty (acceptable threshold)
        - 5% retrans: 50 penalty (poor threshold)
        - 10% retrans: 100 penalty (critical threshold)

        Args:
            analysis_results: Analysis results dictionary
            total_packets: Total packet count

        Returns:
            MetricScore for TCP retransmissions
        """
        retrans_data = analysis_results.get("retransmission", {})
        total_retrans = retrans_data.get("total_retransmissions", 0)

        # Calculate retransmission rate
        if total_packets == 0:
            retrans_rate = 0.0
        else:
            retrans_rate = total_retrans / total_packets

        # Calculate penalty using piecewise linear function
        if retrans_rate <= RFC_7680_RETRANS_GOOD:
            # 0-1%: Linear 0-16 penalty
            penalty = (retrans_rate / RFC_7680_RETRANS_GOOD) * 16.0
            threshold_status = "good"
        elif retrans_rate <= RFC_7680_RETRANS_ACCEPTABLE:
            # 1-3%: Linear 16-34 penalty
            ratio = (retrans_rate - RFC_7680_RETRANS_GOOD) / (RFC_7680_RETRANS_ACCEPTABLE - RFC_7680_RETRANS_GOOD)
            penalty = 16.0 + (ratio * 18.0)
            threshold_status = "acceptable"
        elif retrans_rate <= RFC_7680_RETRANS_POOR:
            # 3-5%: Linear 34-60 penalty
            ratio = (retrans_rate - RFC_7680_RETRANS_ACCEPTABLE) / (RFC_7680_RETRANS_POOR - RFC_7680_RETRANS_ACCEPTABLE)
            penalty = 34.0 + (ratio * 26.0)
            threshold_status = "poor"
        elif retrans_rate <= RFC_7680_RETRANS_CRITICAL:
            # 5-10%: Linear 60-92 penalty
            ratio = (retrans_rate - RFC_7680_RETRANS_POOR) / (RFC_7680_RETRANS_CRITICAL - RFC_7680_RETRANS_POOR)
            penalty = 60.0 + (ratio * 32.0)
            threshold_status = "critical"
        else:
            # >10%: Max penalty
            penalty = MAX_PENALTY_PER_METRIC
            threshold_status = "critical"

        # Apply weight
        weighted_penalty = (penalty * WEIGHT_TCP_RETRANS) / 100.0

        return MetricScore(
            metric_name="TCP Retransmissions",
            raw_value=retrans_rate,
            penalty=round(penalty, 2),
            weight=WEIGHT_TCP_RETRANS,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="RFC 7680",
        )

    def _calculate_packet_loss_penalty(self, analysis_results: Dict[str, Any], total_packets: int) -> MetricScore:
        """
        Calculate penalty for packet loss per RFC 2680.

        Estimates packet loss from retransmissions (conservative estimate).

        Penalty function:
        - 0% loss: 0 penalty
        - 0.5% loss: 10 penalty
        - 2% loss: 30 penalty
        - 5% loss: 60 penalty
        - 10% loss: 100 penalty

        Args:
            analysis_results: Analysis results dictionary
            total_packets: Total packet count

        Returns:
            MetricScore for packet loss
        """
        # Estimate packet loss from unique retransmitted segments
        retrans_data = analysis_results.get("retransmission", {})
        unique_retrans = retrans_data.get("unique_retransmitted_segments", 0)

        if total_packets == 0:
            loss_rate = 0.0
        else:
            # Conservative estimate: unique retrans / total packets
            loss_rate = unique_retrans / total_packets

        # Calculate penalty
        if loss_rate <= RFC_2680_LOSS_GOOD:
            # 0-0.5%: Linear 0-10 penalty
            penalty = (loss_rate / RFC_2680_LOSS_GOOD) * 10.0
            threshold_status = "excellent"
        elif loss_rate <= RFC_2680_LOSS_ACCEPTABLE:
            # 0.5-2%: Linear 10-22 penalty
            ratio = (loss_rate - RFC_2680_LOSS_GOOD) / (RFC_2680_LOSS_ACCEPTABLE - RFC_2680_LOSS_GOOD)
            penalty = 10.0 + (ratio * 12.0)
            threshold_status = "good"
        elif loss_rate <= RFC_2680_LOSS_POOR:
            # 2-5%: Linear 22-47 penalty
            ratio = (loss_rate - RFC_2680_LOSS_ACCEPTABLE) / (RFC_2680_LOSS_POOR - RFC_2680_LOSS_ACCEPTABLE)
            penalty = 22.0 + (ratio * 25.0)
            threshold_status = "acceptable"
        elif loss_rate <= RFC_2680_LOSS_CRITICAL:
            # 5-10%: Linear 47-77 penalty
            ratio = (loss_rate - RFC_2680_LOSS_POOR) / (RFC_2680_LOSS_CRITICAL - RFC_2680_LOSS_POOR)
            penalty = 47.0 + (ratio * 30.0)
            threshold_status = "poor"
        else:
            # >10%: Max penalty
            penalty = MAX_PENALTY_PER_METRIC
            threshold_status = "critical"

        weighted_penalty = (penalty * WEIGHT_PACKET_LOSS) / 100.0

        return MetricScore(
            metric_name="Packet Loss Rate",
            raw_value=loss_rate,
            penalty=round(penalty, 2),
            weight=WEIGHT_PACKET_LOSS,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="RFC 2680",
        )

    def _calculate_rtt_penalty(self, analysis_results: Dict[str, Any]) -> MetricScore:
        """
        Calculate penalty for RTT (latency) per ITU-T G.114.

        Penalty function:
        - <50ms: 0 penalty
        - 150ms: 15 penalty (good threshold)
        - 400ms: 40 penalty (acceptable threshold)
        - 800ms: 70 penalty (poor threshold)
        - 2000ms: 100 penalty (critical threshold)

        Args:
            analysis_results: Analysis results dictionary

        Returns:
            MetricScore for RTT
        """
        rtt_data = analysis_results.get("rtt", {})
        global_stats = rtt_data.get("global_statistics", {})
        median_rtt = global_stats.get("median_rtt", 0.0)

        # Calculate penalty
        if median_rtt <= ITU_T_G114_RTT_EXCELLENT:
            # <50ms: 0 penalty (excellent)
            penalty = 0.0
            threshold_status = "excellent"
        elif median_rtt <= ITU_T_G114_RTT_GOOD:
            # 50-150ms: Linear 0-18 penalty
            ratio = (median_rtt - ITU_T_G114_RTT_EXCELLENT) / (ITU_T_G114_RTT_GOOD - ITU_T_G114_RTT_EXCELLENT)
            penalty = ratio * 18.0
            threshold_status = "good"
        elif median_rtt <= ITU_T_G114_RTT_ACCEPTABLE:
            # 150-400ms: Linear 18-45 penalty
            ratio = (median_rtt - ITU_T_G114_RTT_GOOD) / (ITU_T_G114_RTT_ACCEPTABLE - ITU_T_G114_RTT_GOOD)
            penalty = 18.0 + (ratio * 27.0)
            threshold_status = "acceptable"
        elif median_rtt <= ITU_T_G114_RTT_POOR:
            # 400-800ms: Linear 45-70 penalty
            ratio = (median_rtt - ITU_T_G114_RTT_ACCEPTABLE) / (ITU_T_G114_RTT_POOR - ITU_T_G114_RTT_ACCEPTABLE)
            penalty = 45.0 + (ratio * 25.0)
            threshold_status = "poor"
        elif median_rtt <= ITU_T_G114_RTT_CRITICAL:
            # 800-2000ms: Linear 70-100 penalty
            ratio = (median_rtt - ITU_T_G114_RTT_POOR) / (ITU_T_G114_RTT_CRITICAL - ITU_T_G114_RTT_POOR)
            penalty = 70.0 + (ratio * 30.0)
            threshold_status = "critical"
        else:
            # >2000ms: Max penalty
            penalty = MAX_PENALTY_PER_METRIC
            threshold_status = "critical"

        weighted_penalty = (penalty * WEIGHT_RTT) / 100.0

        return MetricScore(
            metric_name="RTT (Latency)",
            raw_value=median_rtt,
            penalty=round(penalty, 2),
            weight=WEIGHT_RTT,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="ITU-T G.114",
        )

    def _calculate_dns_penalty(self, analysis_results: Dict[str, Any]) -> MetricScore:
        """
        Calculate penalty for DNS errors.

        Combines timeout, error, and slow transactions into error rate.

        Penalty function:
        - 0% errors: 0 penalty
        - 1% errors: 10 penalty
        - 5% errors: 30 penalty
        - 15% errors: 60 penalty
        - 30% errors: 100 penalty

        Args:
            analysis_results: Analysis results dictionary

        Returns:
            MetricScore for DNS errors
        """
        dns_data = analysis_results.get("dns", {})
        total_trans = dns_data.get("total_transactions", 0)
        timeout_trans = dns_data.get("timeout_transactions", 0)
        error_trans = dns_data.get("error_transactions", 0)

        if total_trans == 0:
            error_rate = 0.0
        else:
            # Combine timeouts and errors
            total_errors = timeout_trans + error_trans
            error_rate = total_errors / total_trans

        # Calculate penalty
        if error_rate <= DNS_ERROR_GOOD:
            # 0-1%: Linear 0-8 penalty
            penalty = (error_rate / DNS_ERROR_GOOD) * 8.0
            threshold_status = "excellent"
        elif error_rate <= DNS_ERROR_ACCEPTABLE:
            # 1-5%: Linear 8-25 penalty
            ratio = (error_rate - DNS_ERROR_GOOD) / (DNS_ERROR_ACCEPTABLE - DNS_ERROR_GOOD)
            penalty = 8.0 + (ratio * 17.0)
            threshold_status = "good"
        elif error_rate <= DNS_ERROR_POOR:
            # 5-15%: Linear 25-55 penalty
            ratio = (error_rate - DNS_ERROR_ACCEPTABLE) / (DNS_ERROR_POOR - DNS_ERROR_ACCEPTABLE)
            penalty = 25.0 + (ratio * 30.0)
            threshold_status = "acceptable"
        elif error_rate <= DNS_ERROR_CRITICAL:
            # 15-30%: Linear 50-80 penalty
            ratio = (error_rate - DNS_ERROR_POOR) / (DNS_ERROR_CRITICAL - DNS_ERROR_POOR)
            penalty = 50.0 + (ratio * 30.0)
            threshold_status = "poor"
        else:
            # >30%: 80-95 penalty (cap at 95 to avoid over-penalizing)
            penalty = min(95.0, 80.0 + ((error_rate - DNS_ERROR_CRITICAL) * 50.0))
            threshold_status = "critical"

        weighted_penalty = (penalty * WEIGHT_DNS) / 100.0

        return MetricScore(
            metric_name="DNS Errors",
            raw_value=error_rate,
            penalty=round(penalty, 2),
            weight=WEIGHT_DNS,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="RFC 1035",
        )

    def _calculate_jitter_penalty(self, analysis_results: Dict[str, Any]) -> MetricScore:
        """
        Calculate penalty for jitter (IPDV) per RFC 3393.

        Uses RTT standard deviation as jitter metric.

        Penalty function:
        - 0ms: 0 penalty
        - 20ms: 15 penalty (good threshold)
        - 50ms: 40 penalty (acceptable threshold)
        - 100ms: 70 penalty (poor threshold)
        - 200ms: 100 penalty (critical threshold)

        Args:
            analysis_results: Analysis results dictionary

        Returns:
            MetricScore for jitter
        """
        rtt_data = analysis_results.get("rtt", {})
        global_stats = rtt_data.get("global_statistics", {})
        stdev_rtt = global_stats.get("stdev_rtt", 0.0)

        # Calculate penalty - jitter should have minimal impact on perfect networks
        # Only penalize jitter above 10ms threshold
        if stdev_rtt <= 0.010:
            # 0-10ms: No penalty (excellent)
            penalty = 0.0
            threshold_status = "excellent"
        elif stdev_rtt <= RFC_3393_JITTER_GOOD:
            # 10-20ms: Linear 0-8 penalty
            penalty = ((stdev_rtt - 0.010) / (RFC_3393_JITTER_GOOD - 0.010)) * 8.0
            threshold_status = "excellent"
        elif stdev_rtt <= RFC_3393_JITTER_ACCEPTABLE:
            # 20-50ms: Linear 8-25 penalty
            ratio = (stdev_rtt - RFC_3393_JITTER_GOOD) / (RFC_3393_JITTER_ACCEPTABLE - RFC_3393_JITTER_GOOD)
            penalty = 8.0 + (ratio * 17.0)
            threshold_status = "good"
        elif stdev_rtt <= RFC_3393_JITTER_POOR:
            # 50-100ms: Linear 25-55 penalty
            ratio = (stdev_rtt - RFC_3393_JITTER_ACCEPTABLE) / (RFC_3393_JITTER_POOR - RFC_3393_JITTER_ACCEPTABLE)
            penalty = 25.0 + (ratio * 30.0)
            threshold_status = "acceptable"
        elif stdev_rtt <= RFC_3393_JITTER_CRITICAL:
            # 100-200ms: Linear 50-85 penalty
            ratio = (stdev_rtt - RFC_3393_JITTER_POOR) / (RFC_3393_JITTER_CRITICAL - RFC_3393_JITTER_POOR)
            penalty = 50.0 + (ratio * 35.0)
            threshold_status = "poor"
        else:
            # >200ms: Max penalty
            penalty = MAX_PENALTY_PER_METRIC
            threshold_status = "critical"

        weighted_penalty = (penalty * WEIGHT_JITTER) / 100.0

        return MetricScore(
            metric_name="Jitter (IPDV)",
            raw_value=stdev_rtt,
            penalty=round(penalty, 2),
            weight=WEIGHT_JITTER,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="RFC 3393",
        )

    def _calculate_anomaly_penalty(self, analysis_results: Dict[str, Any], total_packets: int) -> MetricScore:
        """
        Calculate penalty for protocol anomalies.

        Includes: duplicate ACKs, out-of-order packets, zero windows.

        Penalty function (per 1000 packets):
        - 0 anomalies: 0 penalty
        - 10 per 1000: 15 penalty
        - 50 per 1000: 40 penalty
        - 150 per 1000: 70 penalty
        - 500 per 1000: 100 penalty

        Args:
            analysis_results: Analysis results dictionary
            total_packets: Total packet count

        Returns:
            MetricScore for protocol anomalies
        """
        retrans_data = analysis_results.get("retransmission", {})
        anomaly_types = retrans_data.get("anomaly_types", {})

        # Sum all anomaly types
        dup_ack = anomaly_types.get("dup_ack", 0)
        out_of_order = anomaly_types.get("out_of_order", 0)
        zero_window = anomaly_types.get("zero_window", 0)

        total_anomalies = dup_ack + out_of_order + zero_window

        # Calculate anomaly rate per 1000 packets
        if total_packets == 0:
            anomaly_rate = 0.0
        else:
            anomaly_rate = (total_anomalies / total_packets) * 1000.0

        # Calculate penalty
        if anomaly_rate <= ANOMALY_RATE_GOOD:
            # 0-10 per 1000: Linear 0-10 penalty
            penalty = (anomaly_rate / ANOMALY_RATE_GOOD) * 10.0
            threshold_status = "excellent"
        elif anomaly_rate <= ANOMALY_RATE_ACCEPTABLE:
            # 10-50 per 1000: Linear 10-28 penalty
            ratio = (anomaly_rate - ANOMALY_RATE_GOOD) / (ANOMALY_RATE_ACCEPTABLE - ANOMALY_RATE_GOOD)
            penalty = 10.0 + (ratio * 18.0)
            threshold_status = "good"
        elif anomaly_rate <= ANOMALY_RATE_POOR:
            # 50-150 per 1000: Linear 25-55 penalty
            ratio = (anomaly_rate - ANOMALY_RATE_ACCEPTABLE) / (ANOMALY_RATE_POOR - ANOMALY_RATE_ACCEPTABLE)
            penalty = 25.0 + (ratio * 30.0)
            threshold_status = "acceptable"
        elif anomaly_rate <= ANOMALY_RATE_CRITICAL:
            # 150-500 per 1000: Linear 50-85 penalty
            ratio = (anomaly_rate - ANOMALY_RATE_POOR) / (ANOMALY_RATE_CRITICAL - ANOMALY_RATE_POOR)
            penalty = 50.0 + (ratio * 35.0)
            threshold_status = "poor"
        else:
            # >500 per 1000: Max penalty
            penalty = MAX_PENALTY_PER_METRIC
            threshold_status = "critical"

        weighted_penalty = (penalty * WEIGHT_ANOMALIES) / 100.0

        return MetricScore(
            metric_name="Protocol Anomalies",
            raw_value=anomaly_rate,
            penalty=round(penalty, 2),
            weight=WEIGHT_ANOMALIES,
            weighted_penalty=round(weighted_penalty, 2),
            threshold_status=threshold_status,
            rfc_reference="RFC 793",
        )

    def _classify_qos_class(self, score: float) -> int:
        """
        Classify score into ITU-T Y.1541 QoS class.

        QoS Classes:
        - Class 0 (95-100): Excellent
        - Class 1 (85-94): Good
        - Class 2 (65-84): Acceptable
        - Class 3 (45-64): Poor
        - Class 4 (25-44): Critical
        - Class 5 (0-24): Emergency

        Args:
            score: Health score (0-100)

        Returns:
            QoS class (0-5)
        """
        if score >= QOS_CLASS_0_MIN:
            return 0
        elif score >= QOS_CLASS_1_MIN:
            return 1
        elif score >= QOS_CLASS_2_MIN:
            return 2
        elif score >= QOS_CLASS_3_MIN:
            return 3
        elif score >= QOS_CLASS_4_MIN:
            return 4
        else:
            return 5

    def _get_severity(self, qos_class: int) -> tuple[str, str]:
        """
        Get severity level and badge for QoS class.

        Args:
            qos_class: ITU-T Y.1541 QoS class (0-5)

        Returns:
            Tuple of (severity_text, severity_badge)
        """
        severity_map = {
            0: ("excellent", "🟢"),
            1: ("good", "🟡"),
            2: ("warning", "🟠"),
            3: ("poor", "🔴"),
            4: ("critical", "⚫"),
            5: ("emergency", "🆘"),
        }
        return severity_map.get(qos_class, ("unknown", "❓"))

    def _generate_recommendations(
        self, metric_scores: List[MetricScore], analysis_results: Dict[str, Any]
    ) -> List[str]:
        """
        Generate actionable recommendations based on metric scores.

        Args:
            metric_scores: List of individual metric scores
            analysis_results: Original analysis results

        Returns:
            List of recommendation strings
        """
        recommendations = []

        for metric in metric_scores:
            # Only generate recommendations for poor/critical metrics
            if metric.threshold_status in ["poor", "critical"]:
                if metric.metric_name == "TCP Retransmissions":
                    retrans_pct = metric.raw_value * 100
                    recommendations.append(
                        f"High TCP retransmission rate ({retrans_pct:.1f}%). "
                        f"Check for: network congestion, packet loss, "
                        f"insufficient bandwidth, or faulty network equipment."
                    )

                elif metric.metric_name == "Packet Loss Rate":
                    loss_pct = metric.raw_value * 100
                    recommendations.append(
                        f"Significant packet loss detected ({loss_pct:.1f}%). "
                        f"Investigate: physical layer issues, overloaded links, "
                        f"or router/switch buffer overflows."
                    )

                elif metric.metric_name == "RTT (Latency)":
                    rtt_ms = metric.raw_value * 1000
                    recommendations.append(
                        f"High latency detected ({rtt_ms:.0f}ms). "
                        f"Consider: network path optimization, reducing hop count, "
                        f"or implementing traffic prioritization (QoS)."
                    )

                elif metric.metric_name == "DNS Errors":
                    dns_error_pct = metric.raw_value * 100
                    recommendations.append(
                        f"DNS errors affecting {dns_error_pct:.1f}% of queries. "
                        f"Check: DNS server health, network connectivity to DNS servers, "
                        f"or consider adding redundant DNS servers."
                    )

                elif metric.metric_name == "Jitter (IPDV)":
                    jitter_ms = metric.raw_value * 1000
                    recommendations.append(
                        f"High jitter/delay variation ({jitter_ms:.0f}ms). "
                        f"May impact real-time applications. Consider: traffic shaping, "
                        f"prioritizing time-sensitive traffic, or reducing network load."
                    )

                elif metric.metric_name == "Protocol Anomalies":
                    recommendations.append(
                        f"High rate of protocol anomalies ({metric.raw_value:.1f} per 1000 packets). "
                        f"Indicates potential issues with: TCP window management, "
                        f"out-of-order delivery, or application-level problems."
                    )

        # Add general recommendation if no specific issues found
        if not recommendations:
            recommendations.append(
                "Network performance is within acceptable parameters. "
                "Continue monitoring for any degradation trends."
            )

        return recommendations

    def _safe_get(self, data: Dict[str, Any], keys: List[str], default: Any = None) -> Any:
        """
        Safely navigate nested dictionary with default fallback.

        Args:
            data: Dictionary to navigate
            keys: List of keys to traverse
            default: Default value if path not found

        Returns:
            Value at path or default
        """
        current = data
        for key in keys:
            if isinstance(current, dict):
                current = current.get(key, {})
            else:
                return default
        return current if current != {} else default
