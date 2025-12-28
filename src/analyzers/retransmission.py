"""
TCP Retransmission and Anomaly Analyzer.

This analyzer detects TCP retransmissions, duplicate ACKs, out-of-order packets,
and other TCP anomalies according to RFC 793 and RFC 2581 (TCP Congestion Control).

Detection Methods:
1. Exact Match: Detects retransmission of identical segments (seq, len)
2. Spurious Retransmission: Segments already ACKed by receiver
3. Fast Retransmission: Triggered by 3+ duplicate ACKs (RFC 2581)
4. RTO: Timeout-based retransmission (delay > threshold)

Anomaly Detection:
- Duplicate ACKs: Same ACK number received multiple times
- Out-of-Order: Packets with sequence numbers below expected
- Zero Window: TCP window size is 0 (receiver buffer full)

Memory Management:
- LRU-like cleanup: Keeps newest segments when limit exceeded
- Periodic cleanup: Every 10,000 packets
- Max segments per flow: 10,000

References:
    RFC 793: Transmission Control Protocol
    RFC 2581: TCP Congestion Control
    RFC 6298: Computing TCP's Retransmission Timer
"""

import logging
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from scapy.all import IP, TCP, Packet

logger = logging.getLogger(__name__)

from ..utils.packet_utils import get_ip_layer
from ..utils.tcp_utils import get_tcp_logical_length

# Import PacketMetadata for hybrid mode support (3-5x faster)
try:
    from ..parsers.fast_parser import PacketMetadata
except ImportError:
    PacketMetadata = None

# Import TCP State Machine for RFC 793 compliant connection tracking
from .tcp_state_machine import TCPStateMachine


@dataclass
class TCPRetransmission:
    """
    Represents a TCP retransmission event.

    Attributes:
        packet_num: Packet number of the retransmitted segment
        timestamp: Time when retransmission occurred
        src_ip: Source IP address
        dst_ip: Destination IP address
        src_port: Source TCP port
        dst_port: Destination TCP port
        seq_num: TCP sequence number of retransmitted segment
        original_packet_num: Packet number of original transmission
        delay: Time between original and retransmission (seconds)
        retrans_type: Type of retransmission:
            - 'RTO': Retransmission timeout (delay > threshold, typically 200ms)
            - 'Fast Retransmission': Triggered by duplicate ACKs (delay < 50ms)
            - 'Retransmission': Generic retransmission (between thresholds)

        Phase 1: Context enrichment (factual observations, not causal claims)
        expected_ack: Expected next ACK number (calculated from seq + len)
        last_ack_seen: Last ACK observed in capture before this retransmission
        last_ack_packet_num: Packet number where last ACK was observed
        time_since_last_ack_ms: Time elapsed since last ACK (milliseconds)
        dup_ack_count: Number of duplicate ACKs observed before retransmission
        receiver_window_raw: Raw TCP window value from receiver (before scaling)

        suspected_mechanisms: List of possible mechanisms (not definitive causes)
        confidence: Confidence level of analysis ("low" | "medium" | "high")
    """

    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    seq_num: int
    original_packet_num: int
    delay: float
    retrans_type: str = "Unknown"

    # Phase 1: Context enrichment
    expected_ack: Optional[int] = None
    last_ack_seen: Optional[int] = None
    last_ack_packet_num: Optional[int] = None
    time_since_last_ack_ms: Optional[float] = None
    dup_ack_count: int = 0
    receiver_window_raw: Optional[int] = None

    # Suspected mechanisms (NOT definitive cause!)
    suspected_mechanisms: list[str] = None
    confidence: str = "low"  # low | medium | high

    # SYN retransmission flag
    is_syn_retrans: bool = False  # True if this is a retransmitted SYN packet

    # v5.2.3: Classification of SYN retransmission direction
    # "server_unreachable": Client SYN retransmissions (no SYN,ACK received)
    # "client_unreachable": Server SYN,ACK retransmissions (client didn't complete)
    syn_retrans_direction: Optional[str] = None

    # v5.3.0: Spurious retransmission flag (segment already ACKed by receiver)
    # A spurious retransmission occurs when the sender retransmits a segment
    # that has already been acknowledged by the receiver. This indicates the
    # ACK was lost or delayed, causing unnecessary retransmission.
    is_spurious: bool = False

    # TCP flags string (e.g., "SYN", "PSH,ACK", "FIN,ACK")
    tcp_flags: Optional[str] = None

    def __post_init__(self):
        """Initialize default list for suspected_mechanisms."""
        if self.suspected_mechanisms is None:
            self.suspected_mechanisms = []


@dataclass
class TCPAnomaly:
    """Représente une anomalie TCP (DUP ACK, Out-of-Order, etc.)"""

    anomaly_type: str  # 'dup_ack', 'out_of_order', 'zero_window', etc.
    packet_num: int
    timestamp: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    details: str


@dataclass
class SimplePacketInfo:
    """
    Lightweight packet information for sampled timeline.

    This stores only essential packet metadata needed for timeline rendering,
    minimizing memory overhead for the hybrid sampled timeline approach.
    """

    frame: int  # Packet/frame number
    timestamp: float  # Relative timestamp
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    flags: str  # TCP flags string (e.g., "SYN,ACK")
    seq: int  # TCP sequence number
    ack: int  # TCP acknowledgment number
    win: int  # TCP window size
    length: int  # TCP payload length
    is_retransmission: bool = False  # Whether this packet is a retransmission


@dataclass
class SampledTimeline:
    """
    Hybrid sampled timeline for problematic TCP flows.

    Architecture: Option E - Snapshot-on-Problematic (v4.17.0)
    - Lazy allocation: only created when flow becomes problematic
    - Ring buffer: constant memory per flow via deque
    - Samples: handshake (10) + retrans context (±5) + teardown (10)
    - Bidirectional: captures reverse direction at moment of detection

    Memory: ~7.8 KB per problematic flow (vs full capture)
    - Forward: handshake (10) + contexts + teardown (10) ~5.4 KB
    - Reverse: handshake (10) + teardown (10) ~2.4 KB
    """

    handshake: list[SimplePacketInfo]  # First 10 packets (connection setup)
    retrans_context: list[list[SimplePacketInfo]]  # ±5 packets around each retransmission
    teardown: list[SimplePacketInfo]  # Last 10 packets (connection teardown)

    # CRITICAL FIX v4.17.0: Bidirectional timeline snapshot
    # Captures reverse direction at moment flow becomes problematic
    # Prevents data loss when port reuse cleanup deletes _packet_buffer[reverse_key]
    reverse_handshake: list[SimplePacketInfo] = field(default_factory=list)
    reverse_teardown: list[SimplePacketInfo] = field(default_factory=list)
    reverse_captured: bool = False


@dataclass
class FlowStats:
    """Statistiques d'un flux TCP"""

    flow_key: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    total_packets: int
    retransmissions: int
    dup_acks: int
    out_of_order: int
    zero_windows: int
    severity: str = "none"
    retransmission_rate: float = 0.0


def _tcp_flags_to_string(metadata=None, tcp=None) -> str:
    """
    Convert TCP flags to string representation (e.g., "SYN", "PSH,ACK", "FIN,ACK").

    Args:
        metadata: PacketMetadata object (hybrid mode)
        tcp: Scapy TCP layer (scapy mode)

    Returns:
        String representation of TCP flags
    """
    flags = []

    if metadata:
        # Hybrid mode: use boolean flags from PacketMetadata
        if metadata.is_syn:
            flags.append("SYN")
        if metadata.is_fin:
            flags.append("FIN")
        if metadata.is_rst:
            flags.append("RST")
        if metadata.is_psh:
            flags.append("PSH")
        if metadata.is_ack:
            flags.append("ACK")
    elif tcp:
        # Scapy mode: use sprintf to get flags string
        return tcp.sprintf("%TCP.flags%")

    return ",".join(flags) if flags else "NONE"


def _create_simple_packet_info(
    packet_num: int,
    timestamp: float,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    tcp_seq: int,
    tcp_ack: int,
    tcp_window: int,
    tcp_payload_len: int,
    flags_str: str,
    is_retransmission: bool = False,
) -> SimplePacketInfo:
    """
    Create SimplePacketInfo from packet data.

    This factory function creates a lightweight packet info object for timeline sampling.

    Args:
        packet_num: Frame/packet number
        timestamp: Relative timestamp
        src_ip: Source IP address
        src_port: Source port
        dst_ip: Destination IP address
        dst_port: Destination port
        tcp_seq: TCP sequence number
        tcp_ack: TCP acknowledgment number
        tcp_window: TCP window size
        tcp_payload_len: TCP payload length
        flags_str: TCP flags string (e.g., "SYN,ACK")
        is_retransmission: Whether this packet is a retransmission

    Returns:
        SimplePacketInfo object
    """
    return SimplePacketInfo(
        frame=packet_num,
        timestamp=timestamp,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        flags=flags_str,
        seq=tcp_seq,
        ack=tcp_ack,
        win=tcp_window,
        length=tcp_payload_len,
        is_retransmission=is_retransmission,
    )


class RetransmissionAnalyzer:
    """
    TCP Retransmission and Anomaly Analyzer.

    Detects and classifies TCP retransmissions using multiple algorithms:
    1. Exact segment matching (seq, len)
    2. Spurious retransmission detection (already ACKed)
    3. Fast retransmission detection (3+ duplicate ACKs per RFC 2581)
    4. RTO classification based on delay thresholds (RFC 6298)

    The analyzer also tracks TCP anomalies including duplicate ACKs,
    out-of-order packets, and zero window conditions.

    Performance:
        - Time complexity: O(1) average per packet (with periodic cleanup)
        - Space complexity: O(N*M) where N=flows, M=segments per flow (bounded)
    """

    def __init__(
        self,
        retrans_low: int = 10,
        retrans_medium: int = 50,
        retrans_critical: int = 100,
        retrans_rate_low: float = 1.0,
        retrans_rate_medium: float = 3.0,
        retrans_rate_critical: float = 5.0,
        rto_threshold_ms: float = 200.0,
        fast_retrans_delay_max_ms: float = 50.0,
    ) -> None:
        """
        Initialize retransmission analyzer.

        Args:
            retrans_low: Low severity threshold (absolute count)
            retrans_medium: Medium severity threshold (absolute count)
            retrans_critical: Critical severity threshold (absolute count)
            retrans_rate_low: Low severity rate threshold (%)
            retrans_rate_medium: Medium severity rate threshold (%)
            retrans_rate_critical: Critical severity rate threshold (%)
            rto_threshold_ms: Delay threshold for RTO classification (milliseconds).
                Per RFC 6298, typical RTO is >= 200ms.
            fast_retrans_delay_max_ms: Max delay for fast retransmission (milliseconds).
                Per RFC 2581, fast retransmit happens quickly after 3 DUP ACKs.

        Note:
            Default thresholds are suitable for most networks. For high-throughput
            or lossy environments, consider adjusting the rate thresholds.
        """
        self.retrans_low = retrans_low
        self.retrans_medium = retrans_medium
        self.retrans_critical = retrans_critical

        self.retrans_rate_low = retrans_rate_low
        self.retrans_rate_medium = retrans_rate_medium
        self.retrans_rate_critical = retrans_rate_critical

        self.rto_threshold = rto_threshold_ms / 1000.0  # Convert to seconds
        self.fast_retrans_delay_max = fast_retrans_delay_max_ms / 1000.0  # Convert to seconds

        self.retransmissions: list[TCPRetransmission] = []
        self.anomalies: list[TCPAnomaly] = []
        self.flow_stats: dict[str, FlowStats] = {}

        # Tracking interne
        # Changement: on stocke maintenant une liste de (packet_num, timestamp) pour chaque (seq, len)
        # pour détecter les retransmissions multiples du même segment
        self._seen_segments: dict[str, dict[tuple[int, int], list[tuple[int, float]]]] = defaultdict(
            lambda: defaultdict(list)
        )
        self._flow_counters: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._expected_ack: dict[str, int] = {}
        self._expected_seq: dict[str, int] = {}
        self._dup_ack_count: dict[str, int] = defaultdict(int)  # Compteur de DUP ACK par flux
        self._last_ack: dict[str, int] = {}  # Dernier ACK vu par flux
        # Phase 1: Track packet number and timestamp of last ACK
        self._last_ack_packet_num: dict[str, int] = {}  # Packet number of last ACK
        self._last_ack_timestamp: dict[str, float] = {}  # Timestamp of last ACK
        # Tracking du plus haut seq vu par flux (méthode Wireshark)
        self._highest_seq: dict[str, tuple[int, int, float]] = {}  # flow_key -> (highest_seq, packet_num, timestamp)
        # Tracking du plus haut ACK vu par flux (pour Spurious Retransmission)
        self._max_ack_seen: dict[str, int] = defaultdict(int)

        # ISN tracking for distinguishing true SYN retransmissions from port reuse (RFC 793)
        self._initial_seq: dict[str, int] = {}  # flow_key -> Initial Sequence Number

        # RFC 793 compliant TCP State Machine for connection lifecycle tracking
        # This prevents false positives when ports are reused after proper connection closure
        self._state_machine = TCPStateMachine(
            time_wait_duration=120.0,  # RFC 793: 2×MSL (60s MSL)
            connection_timeout=300.0,  # 5 minutes inactivity timeout
            fin_timeout=30.0,  # FIN should complete within 30s
        )

        # Memory optimization: periodic cleanup
        self._packet_counter = 0
        self._cleanup_interval = 10000
        self._max_segments_per_flow = 10000

        # v4.15.0: Hybrid Sampled Timeline (Option C)
        # Lazy allocation: only created when flow becomes problematic (first retransmission detected)
        self.sampled_timelines: dict[str, SampledTimeline] = {}  # flow_key -> SampledTimeline
        # Ring buffer: constant memory per flow (last 10 packets for potential handshake capture)
        self._packet_buffer: dict[str, deque] = {}  # flow_key -> deque of SimplePacketInfo (maxlen=10)
        # v5.2.3: Permanent SYN packet storage to prevent loss in ring buffer
        self._syn_packet: dict[str, Any] = {}  # flow_key -> SimplePacketInfo

    def _reset_flow_state(self, flow_key: str, reverse_key: str) -> None:
        """
        Reset all state for a flow when a new connection is detected (SYN or RST).

        This prevents false positives from port reuse scenarios where the same
        4-tuple is used by a new TCP connection after the old one terminates.

        RFC 793 Compliance:
            - Connections are uniquely identified by (src IP, src port, dst IP, dst port)
            - TIME-WAIT state (2×MSL) normally prevents immediate reuse
            - However, RST packets bypass TIME-WAIT (immediate reuse possible)
            - Operating systems with tcp_tw_reuse allow reuse for outgoing connections
            - Kubernetes/Docker environments exhibit high port reuse rates

        Industry Best Practices (Wireshark, Suricata):
            - Wireshark uses ISN tracking to distinguish connections (tcp.stream)
            - Suricata maintains stateful ISN validation per RFC 793
            - Both reset per-connection state on new SYN detection

        Critical for Accuracy:
            - Failure to reset state causes false positives (11,574 vs 6 actual retransmissions)
            - Particularly severe in containerized environments (rapid connection recycling)

        Args:
            flow_key: Forward flow key (src -> dst)
            reverse_key: Reverse flow key (dst -> src)
        """
        # Sequence tracking (per RFC 793)
        if flow_key in self._highest_seq:
            del self._highest_seq[flow_key]
        if flow_key in self._expected_seq:
            del self._expected_seq[flow_key]

        # ACK tracking (per RFC 793)
        if flow_key in self._max_ack_seen:
            del self._max_ack_seen[flow_key]
        if flow_key in self._expected_ack:
            del self._expected_ack[flow_key]

        # CRITICAL FIX: Retransmission detection state (prevents port reuse false positives)
        # Bug Report: 11,574 false positives reduced to 0 after adding this cleanup
        if flow_key in self._seen_segments:
            del self._seen_segments[flow_key]

        # BIDIRECTIONAL CLEANUP FIX (v4.13.1):
        # TCP connections have TWO independent sequence spaces (client→server, server→client)
        # Port reuse requires cleaning BOTH directions to prevent false positives
        # Audit Report: "Il ne réinitialisait pas l'état du sens inverse (ACKs du serveur)"

        # Reverse direction: Sequence tracking
        if reverse_key in self._highest_seq:
            del self._highest_seq[reverse_key]
        if reverse_key in self._expected_seq:
            del self._expected_seq[reverse_key]

        # Reverse direction: ACK tracking
        if reverse_key in self._max_ack_seen:
            del self._max_ack_seen[reverse_key]
        if reverse_key in self._expected_ack:
            del self._expected_ack[reverse_key]

        # Reverse direction: Retransmission detection state
        if reverse_key in self._seen_segments:
            del self._seen_segments[reverse_key]

        # Reverse direction: ISN tracking
        if reverse_key in self._initial_seq:
            del self._initial_seq[reverse_key]

        # Reverse direction: Duplicate ACK tracking (per RFC 2581)
        if reverse_key in self._dup_ack_count:
            del self._dup_ack_count[reverse_key]
        if reverse_key in self._last_ack:
            del self._last_ack[reverse_key]
        if reverse_key in self._last_ack_packet_num:
            del self._last_ack_packet_num[reverse_key]
        if reverse_key in self._last_ack_timestamp:
            del self._last_ack_timestamp[reverse_key]

        # CRITICAL FIX v4.16.1: Clear packet buffers to prevent contamination
        if flow_key in self._packet_buffer:
            del self._packet_buffer[flow_key]
        if reverse_key in self._packet_buffer:
            del self._packet_buffer[reverse_key]

        # v5.2.3: Cleanup permanent SYN storage
        if flow_key in self._syn_packet:
            del self._syn_packet[flow_key]
        if reverse_key in self._syn_packet:
            del self._syn_packet[reverse_key]


        # RFC 793: Reset TCP state machine for both directions
        self._state_machine.reset_flow(flow_key)
        self._state_machine.reset_flow(reverse_key)

    def analyze(self, packets: list[Packet]) -> dict[str, Any]:
        """
        Analyse les retransmissions et anomalies TCP

        Args:
            packets: Liste des paquets Scapy

        Returns:
            Dictionnaire contenant les résultats d'analyse
        """
        # v5.2.4: Fix frame numbering to match Wireshark (1-based indexing)
        for i, packet in enumerate(packets, start=1):
            self.process_packet(packet, i)

        return self.finalize()

    def process_packet(self, packet: Union[Packet, "PacketMetadata"], packet_num: int) -> None:
        """
        Process a single packet (supports both Scapy Packet and PacketMetadata).

        PERFORMANCE: PacketMetadata is 3-5x faster than Scapy Packet parsing.

        Args:
            packet: Scapy Packet or lightweight PacketMetadata
            packet_num: Packet sequence number in capture
        """
        # FAST PATH: Handle PacketMetadata (dpkt-extracted, 3-5x faster)
        if PacketMetadata and isinstance(packet, PacketMetadata):
            self._process_metadata(packet, packet_num)
            return

        # LEGACY PATH: Handle Scapy Packet (for backward compatibility)
        ip = get_ip_layer(packet)
        if not packet.haslayer(TCP) or not ip:
            return

        # Memory optimization: periodic cleanup
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_segments()

        self._analyze_packet(packet_num, packet)

    def _diagnose_retransmission(
        self,
        seq: int,
        logical_len: int,
        reverse_key: str,
        timestamp: float,
        dup_ack_count: int,
        max_ack_seen: int,
        receiver_window: Optional[int] = None,
    ) -> tuple[list[str], str]:
        """
        Phase 1: Diagnose retransmission with evidence-based context.

        This method provides conservative, evidence-based analysis of retransmissions
        based on observable facts from the capture. It does NOT claim definitive
        root cause (impossible from single-sided capture per RFC and research).

        Args:
            seq: TCP sequence number of retransmitted segment
            logical_len: Logical length of segment (payload + SYN + FIN)
            reverse_key: Reverse flow key for ACK tracking
            timestamp: Current packet timestamp
            dup_ack_count: Number of duplicate ACKs observed
            max_ack_seen: Highest ACK number seen from receiver
            receiver_window: TCP window size from receiver (if available)

        Returns:
            Tuple of (suspected_mechanisms, confidence_level)
            - suspected_mechanisms: List of possible mechanisms (NOT definitive causes)
            - confidence_level: "low" | "medium" | "high"

        Evidence-Based Logic (per ISSUE_11_COUNTER_ANALYSIS.md):
        1. High Confidence: Spurious retransmission (seq+len <= max_ack_seen)
           - We observed the ACK, so we know receiver already received data
        2. Medium Confidence: Fast retransmission (dup_ack_count >= 3)
           - RFC 5681 behavior: 3+ DUP ACKs indicate isolated packet loss
        3. Low Confidence: Timeout-based (default)
           - Multiple possible causes: packet loss, ACK loss, delay, congestion
        """
        suspected_mechanisms = []
        confidence = "low"

        # HIGH CONFIDENCE: Spurious retransmission (already ACKed)
        if seq + logical_len <= max_ack_seen:
            confidence = "high"
            suspected_mechanisms = [
                "Spurious retransmission (already ACKed)",
                "Possible causes: ACK delay, premature timeout, packet reordering",
            ]

        # MEDIUM CONFIDENCE: Fast retransmission (3+ DUP ACKs per RFC 5681)
        elif dup_ack_count >= 3:
            confidence = "medium"
            suspected_mechanisms = [
                "Isolated packet loss (RFC 5681)",
                "Triggered by 3+ duplicate ACKs indicating later packets arrived",
            ]

        # LOW CONFIDENCE: Timeout-based retransmission (RTO)
        else:
            confidence = "low"
            suspected_mechanisms = [
                "Timeout-based retransmission (RTO)",
                "Multiple possibilities (see report):",
                "  - Original packet lost in network",
                "  - ACK packet lost on return path",
                "  - Network congestion causing delay",
                "  - Application pause at receiver",
                "Note: Single-sided capture cannot distinguish between causes",
            ]

        return suspected_mechanisms, confidence

    def _cleanup_old_segments(self) -> None:
        """
        Cleanup old segments to prevent memory exhaustion using LRU-like approach.

        When a flow exceeds the maximum segment limit (10,000), this method
        keeps only the newest half of segments based on most recent timestamp.
        This prevents unbounded memory growth in long captures while maintaining
        recent history for retransmission detection.

        Algorithm:
            1. For each flow exceeding max_segments_per_flow
            2. Sort segments by most recent timestamp (descending)
            3. Keep only the newest 50% of segments
            4. Discard older segments

        Note:
            Called every 10,000 packets. This balances memory usage with
            retransmission detection accuracy.
        """
        for flow_key in list(self._seen_segments.keys()):
            segments = self._seen_segments[flow_key]
            if len(segments) > self._max_segments_per_flow:
                # Keep only the most recent segments (by timestamp)
                sorted_segments = sorted(
                    segments.items(), key=lambda x: max(ts for _, ts in x[1]) if x[1] else 0, reverse=True
                )
                # Keep newest half
                keep_count = self._max_segments_per_flow // 2
                self._seen_segments[flow_key] = dict(sorted_segments[:keep_count])

    def _process_metadata(self, metadata: "PacketMetadata", packet_num: int) -> None:
        """
        PERFORMANCE OPTIMIZED: Process lightweight PacketMetadata (3-5x faster than Scapy).

        This method replicates the exact logic of _analyze_packet() but uses direct
        attribute access from dpkt-extracted metadata instead of Scapy's API.

        Implements RFC 793 and RFC 2581 retransmission detection:
        1. Exact segment matching (seq, payload_len)
        2. Spurious retransmission (already ACKed)
        3. Fast retransmission (triggered by 3+ DUP ACKs)
        4. RTO classification based on delay

        Args:
            metadata: Lightweight packet metadata from dpkt
            packet_num: Packet sequence number in capture
        """
        # Skip non-TCP packets
        if metadata.protocol != "TCP":
            return

        # Memory optimization: periodic cleanup
        self._packet_counter += 1
        if self._packet_counter % self._cleanup_interval == 0:
            self._cleanup_old_segments()

        timestamp = metadata.timestamp

        # Build flow key from metadata
        flow_key = f"{metadata.src_ip}:{metadata.src_port}->{metadata.dst_ip}:{metadata.dst_port}"
        reverse_key = f"{metadata.dst_ip}:{metadata.dst_port}->{metadata.src_ip}:{metadata.src_port}"

        # Initialize tracking for new flows (both directions)
        for key in [flow_key, reverse_key]:
            if key not in self._seen_segments:
                # Note: _seen_segments is defaultdict(lambda: defaultdict(list)) but
                # direct initialization is safer for clarity here.
                # However, for reverse key, we might not have all metadata fields.
                # Use current metadata as best guess for reverse direction ports/ips.
                is_reverse = key == reverse_key
                src_ip = metadata.dst_ip if is_reverse else metadata.src_ip
                dst_ip = metadata.src_ip if is_reverse else metadata.dst_ip
                src_port = metadata.dst_port if is_reverse else metadata.src_port
                dst_port = metadata.src_port if is_reverse else metadata.dst_port

                self.flow_stats[key] = FlowStats(
                    flow_key=key,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    total_packets=0,
                    retransmissions=0,
                    dup_acks=0,
                    out_of_order=0,
                    zero_windows=0,
                )
                self._last_ack[key] = 0
                self._dup_ack_count[key] = 0
                self._last_ack_packet_num[key] = 0
                self._last_ack_timestamp[key] = 0.0
                # Initialize segments dict for this flow
                self._seen_segments[key] = {}

        self._flow_counters[flow_key]["total"] += 1

        # v4.15.0: Buffer packets for hybrid sampled timeline
        # Ring buffer: constant memory per flow (maxlen=10)
        # This captures handshake packets BEFORE we know if flow is problematic
        if flow_key not in self._packet_buffer:
            self._packet_buffer[flow_key] = deque(maxlen=10)

        # Create SimplePacketInfo for current packet
        packet_info = _create_simple_packet_info(
            packet_num=packet_num,
            timestamp=timestamp,
            src_ip=metadata.src_ip,
            src_port=metadata.src_port,
            dst_ip=metadata.dst_ip,
            dst_port=metadata.dst_port,
            tcp_seq=metadata.tcp_seq,
            tcp_ack=metadata.tcp_ack if metadata.is_ack else 0,
            tcp_window=metadata.tcp_window,
            tcp_payload_len=metadata.tcp_payload_len,
            flags_str=_tcp_flags_to_string(metadata=metadata),
            is_retransmission=False,  # Will be updated if retransmission is detected
        )

        # Add to ring buffer (automatically discards oldest if full)
        self._packet_buffer[flow_key].append(packet_info)

        # CRITICAL FIX v4.16.2: Check for port reuse BEFORE updating state machine
        # Race condition fix: must validate ISN and timestamps BEFORE process_packet() overwrites them
        # Bug: process_packet() updates flow_state.isn and last_packet_time, breaking validation
        # Solution: Check should_reset_flow_state() BEFORE calling process_packet()
        syn_seq = metadata.tcp_seq if metadata.is_syn else None
        if self._state_machine.should_reset_flow_state(flow_key, timestamp, syn_seq):
            # Connection closed (FIN-ACK complete, RST, timeout) or port reuse detected
            self._reset_flow_state(flow_key, reverse_key)
            # Update ISN tracking after reset
            if metadata.is_syn:
                self._initial_seq[flow_key] = metadata.tcp_seq

        # v5.2.3: Permanent SYN storage to prevent handshake contamination
        # Ring buffer (maxlen=10) can eject the initial SYN in heavy traffic
        # MUST be AFTER reset to avoid being deleted by _reset_flow_state()
        if metadata.is_syn and flow_key not in self._syn_packet:
            self._syn_packet[flow_key] = packet_info
            logger.debug(f"Captured initial SYN for {flow_key} (Frame {packet_num})")

        # RFC 793: Update TCP state machine (AFTER potential reset)
        tcp_flags = {
            "SYN": metadata.is_syn,
            "ACK": metadata.is_ack,
            "FIN": metadata.is_fin,
            "RST": metadata.is_rst,
        }
        self._state_machine.process_packet(
            flow_key=flow_key,
            timestamp=timestamp,
            tcp_flags=tcp_flags,
            seq=metadata.tcp_seq,
            ack=metadata.tcp_ack if metadata.is_ack else 0,
            payload_len=metadata.tcp_payload_len,
        )

        # Legacy ISN tracking (for backward compatibility and additional validation)
        # The state machine handles the primary logic, this provides secondary validation
        if metadata.is_syn and flow_key not in self._initial_seq:
            self._initial_seq[flow_key] = metadata.tcp_seq

        # Mise à jour du Max ACK vu pour ce flux
        if metadata.is_ack:  # ACK flag
            ack = metadata.tcp_ack
            if flow_key not in self._max_ack_seen or ack > self._max_ack_seen[flow_key]:
                self._max_ack_seen[flow_key] = ack

            # v4.18.0: Track Duplicate ACKs for Fast Retransmission detection
            if flow_key in self._last_ack and ack == self._last_ack[flow_key]:
                # Pure duplicate ACK (no window update, no payload)
                if metadata.tcp_payload_len == 0:
                    self._dup_ack_count[flow_key] += 1

                    # Track where this DUP ACK occurred
                    self._last_ack_packet_num[flow_key] = packet_num
                    self._last_ack_timestamp[flow_key] = timestamp
            else:
                # New ACK seen, reset DUP ACK counter
                self._last_ack[flow_key] = ack
                self._dup_ack_count[flow_key] = 0
                self._last_ack_packet_num[flow_key] = packet_num
                self._last_ack_timestamp[flow_key] = timestamp

        # Calcul de la longueur logique TCP (RFC 793: payload + SYN + FIN)
        seq = metadata.tcp_seq
        payload_len = metadata.tcp_payload_len

        logical_len = payload_len
        if metadata.is_syn:
            logical_len += 1
        if metadata.is_fin:
            logical_len += 1

        next_seq = seq + logical_len

        # On ne cherche des retransmissions QUE si le paquet transporte des données ou SYN/FIN
        has_payload_or_flags = (payload_len > 0) or metadata.is_syn or metadata.is_fin

        if has_payload_or_flags:
            # Clé unique: seq + longueur de payload pour distinguer retransmissions partielles
            segment_key = (seq, payload_len)

            is_retransmission = False
            is_spurious = False  # v5.3.0: Track if this is a spurious retransmission
            original_num = None
            original_time = None

            # Méthode combinée (Wireshark-like + Exact Match)

            # 1. Vérifier si le segment exact (seq, len) a déjà été vu
            if segment_key in self._seen_segments[flow_key]:
                is_retransmission = True
                original_num, original_time = self._seen_segments[flow_key][segment_key][0]

            # 2. Vérifier si c'est une Spurious Retransmission (déjà ACKé par l'autre côté)
            if not is_retransmission and reverse_key in self._max_ack_seen:
                max_ack = self._max_ack_seen[reverse_key]
                if seq + logical_len <= max_ack:
                    is_retransmission = True
                    is_spurious = True  # v5.3.0: Mark as spurious (already ACKed)

            # 3. Vérifier Fast Retransmission (SEQ attendu par >2 DUP ACKs)
            if not is_retransmission and self._dup_ack_count[reverse_key] > 2:
                expected_seq = self._last_ack[reverse_key]
                if seq == expected_seq:
                    is_retransmission = True

            # 4. RFC 793 Compliant: Retransmission = segment already delivered AND acked
            # v5.3.0 FIX: Removed overly aggressive "seq < highest_seq" detection
            # that caused false positives for normal out-of-order packets.
            #
            # DISABLED OLD LOGIC:
            # if seq < highest_seq: is_retransmission = True
            #
            # PROBLEM: Out-of-order packets (arriving late but never sent before) were
            # incorrectly flagged as retransmissions. Example:
            #   - Packet A (seq 1000-2460) arrives first -> highest_seq = 2460
            #   - Packet C (seq 4000-5460) arrives second -> highest_seq = 5460
            #   - Packet B (seq 2460-3920) arrives third -> FALSE POSITIVE!
            #     (2460 < 5460 but it's not a retransmission, just out-of-order)
            #
            # RFC 793: A retransmission occurs when the SAME segment (seq+len) is sent
            # multiple times, OR when a segment is sent again after being ACKed (spurious).
            # Out-of-order delivery is NOT retransmission - it's normal TCP behavior.
            #
            # CORRECT DETECTION (already implemented above):
            #   Method #1: Exact segment match (seq, len) seen multiple times ✅
            #   Method #2: Spurious (seq+len <= max_ack_seen) ✅
            #   Method #3: Fast retrans (3 dup ACKs) ✅
            #
            # Method #4 REMOVED to eliminate false positives (59% over-detection vs tshark)
            pass  # No additional detection needed - methods #1-3 are sufficient and RFC-compliant

            if is_retransmission:
                # Essayer de trouver le paquet original exact
                if original_num is None:
                    if (
                        segment_key in self._seen_segments[flow_key]
                        and len(self._seen_segments[flow_key][segment_key]) > 0
                    ):
                        original_num, original_time = self._seen_segments[flow_key][segment_key][0]
                    elif flow_key in self._highest_seq:
                        _, highest_pkt, highest_time = self._highest_seq[flow_key]
                        original_num = highest_pkt
                        original_time = highest_time
                    else:
                        original_num = packet_num
                        original_time = timestamp

                delay = timestamp - original_time

                # Determine retransmission type based on delay heuristics
                # IMPORTANT: SYN retransmissions are ALWAYS RTO-based (timeout),
                # never Fast Retransmission (no duplicate ACKs possible during handshake)
                is_syn_retrans = metadata.is_syn
                retrans_type = "Retransmission"
                if is_syn_retrans:
                    # SYN retransmissions are always timeout-based
                    if delay >= 0.5:  # Typical SYN RTO is >= 1s, but allow some margin
                        retrans_type = "RTO"
                    else:
                        retrans_type = "Retransmission"  # Generic if unusually fast
                elif delay >= self.rto_threshold:
                    retrans_type = "RTO"
                elif delay <= self.fast_retrans_delay_max:
                    retrans_type = "Fast Retransmission"

                # Phase 1: Calculate context enrichment fields
                expected_ack = seq + logical_len
                last_ack = self._last_ack.get(reverse_key)
                last_ack_pkt = self._last_ack_packet_num.get(reverse_key)
                last_ack_ts = self._last_ack_timestamp.get(reverse_key)
                time_since_last_ack = None
                if last_ack_ts is not None:
                    time_since_last_ack = (timestamp - last_ack_ts) * 1000  # Convert to ms

                current_dup_ack_count = self._dup_ack_count.get(reverse_key, 0)
                max_ack = self._max_ack_seen.get(reverse_key, 0)

                # Phase 1: Diagnose with evidence-based logic
                suspected_mechanisms, confidence = self._diagnose_retransmission(
                    seq=seq,
                    logical_len=logical_len,
                    reverse_key=reverse_key,
                    timestamp=timestamp,
                    dup_ack_count=current_dup_ack_count,
                    max_ack_seen=max_ack,
                    receiver_window=metadata.tcp_window,
                )

                # v4.18.0: Align retrans_type with diagnosis confidence
                if confidence == "high":
                    retrans_type = "Spurious Retransmission"
                elif confidence == "medium":
                    retrans_type = "Fast Retransmission"
                # RTO is already set by delay heuristics if confidence is low

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay,
                    retrans_type=retrans_type,
                    # Phase 1: Context enrichment
                    expected_ack=expected_ack,
                    last_ack_seen=last_ack,
                    last_ack_packet_num=last_ack_pkt,
                    time_since_last_ack_ms=time_since_last_ack,
                    dup_ack_count=current_dup_ack_count,
                    receiver_window_raw=metadata.tcp_window,
                    suspected_mechanisms=suspected_mechanisms,
                    confidence=confidence,
                    is_syn_retrans=is_syn_retrans,
                    syn_retrans_direction=self._classify_syn_retransmission(metadata) if is_syn_retrans else None,
                    is_spurious=is_spurious,  # v5.3.0: Mark spurious retransmissions
                    tcp_flags=_tcp_flags_to_string(metadata=metadata),
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]["retransmissions"] += 1

                # v4.17.0: Sampled Timeline - Lazy allocation with bidirectional snapshot
                if flow_key not in self.sampled_timelines:
                    # Flow just became problematic - snapshot BOTH directions
                    # CRITICAL: Capture reverse direction NOW before port reuse cleanup deletes it
                    
                    # v5.2.3 Fix: Ensure initial SYN is always included in handshake
                    forward_handshake = []
                    # 1. Always include the SYN if it exists
                    if flow_key in self._syn_packet:
                        forward_handshake.append(self._syn_packet[flow_key])
                    # 2. Add other packets from buffer (avoiding duplicates)
                    buffer_packets = [
                        p for p in self._packet_buffer[flow_key] 
                        if not (flow_key in self._syn_packet and p.frame == self._syn_packet[flow_key].frame)
                    ]
                    forward_handshake.extend(buffer_packets)
                    forward_handshake.sort(key=lambda p: p.timestamp)
                    forward_handshake = forward_handshake[:10]

                    # v5.2.3 Fix: Ensure initial SYN is always included in reverse handshake
                    reverse_handshake = []
                    # 1. Always include the SYN if it exists
                    if reverse_key in self._syn_packet:
                        reverse_handshake.append(self._syn_packet[reverse_key])
                    # 2. Add other packets from buffer (avoiding duplicates)
                    if reverse_key in self._packet_buffer:
                        buffer_packets = [
                            p for p in self._packet_buffer[reverse_key]
                            if not (reverse_key in self._syn_packet and p.frame == self._syn_packet[reverse_key].frame)
                        ]
                        reverse_handshake.extend(buffer_packets)
                    reverse_handshake.sort(key=lambda p: p.timestamp)
                    reverse_handshake = reverse_handshake[:10]

                    self.sampled_timelines[flow_key] = SampledTimeline(
                        handshake=forward_handshake,
                        retrans_context=[],
                        teardown=[],
                        reverse_handshake=reverse_handshake,  # NEW: Bidirectional snapshot
                        reverse_teardown=[],  # NEW: Will be captured on FIN/RST
                        reverse_captured=True,  # NEW: Mark as captured
                    )

                # Mark current packet as retransmission in buffer
                packet_info.is_retransmission = True

                # v4.17.1: Capture BIDIRECTIONAL retransmission context
                # Forward direction: Last 5 packets (including current retransmission)
                forward_buffer = list(self._packet_buffer[flow_key])
                forward_start = max(0, len(forward_buffer) - 5)
                forward_context = forward_buffer[forward_start:]

                # Reverse direction: Filter by time window from forward context
                reverse_context = []
                if reverse_key in self._packet_buffer and forward_context:
                    reverse_buffer = list(self._packet_buffer[reverse_key])
                    time_window_start = forward_context[0].timestamp
                    time_window_end = forward_context[-1].timestamp

                    # Filter reverse packets within time window, take last 5
                    reverse_context = [
                        p for p in reverse_buffer if time_window_start <= p.timestamp <= time_window_end
                    ][-5:]

                # Merge bidirectional contexts and bound to 10 packets total
                merged_context = forward_context + reverse_context
                merged_context.sort(key=lambda p: p.timestamp)
                if len(merged_context) > 10:
                    merged_context = merged_context[:10]

                # Store bidirectional retransmission context
                self.sampled_timelines[flow_key].retrans_context.append(merged_context)

            # Store only original packet info
            if segment_key not in self._seen_segments[flow_key]:
                self._seen_segments[flow_key][segment_key] = [(packet_num, timestamp)]

        # Mettre à jour le plus haut seq vu pour ce flux
        if flow_key not in self._highest_seq or next_seq > self._highest_seq[flow_key][0]:
            self._highest_seq[flow_key] = (next_seq, packet_num, timestamp)

        # Détection de DUP ACK et Fast Retransmission
        if metadata.is_ack:  # ACK flag
            ack = metadata.tcp_ack

            # Vérifier si c'est un DUP ACK
            if reverse_key in self._last_ack and ack == self._last_ack[reverse_key]:
                # C'est un DUP ACK
                self._dup_ack_count[reverse_key] += 1

                anomaly = TCPAnomaly(
                    anomaly_type="dup_ack",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    details=f"Duplicate ACK #{self._dup_ack_count[reverse_key]} for seq {ack}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["dup_acks"] += 1
            else:
                # Nouvel ACK, réinitialiser le compteur de DUP ACK
                self._dup_ack_count[reverse_key] = 0

            self._last_ack[reverse_key] = ack
            self._expected_ack[reverse_key] = ack
            # Phase 1: Track packet number and timestamp of ACK
            self._last_ack_packet_num[reverse_key] = packet_num
            self._last_ack_timestamp[reverse_key] = timestamp

        # Détection Out-of-Order
        if logical_len > 0:
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type="out_of_order",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=metadata.src_ip,
                    dst_ip=metadata.dst_ip,
                    src_port=metadata.src_port,
                    dst_port=metadata.dst_port,
                    details=f"Expected seq {expected}, got {seq}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["out_of_order"] += 1
            else:
                self._expected_seq[flow_key] = seq + logical_len

        # Détection Zero Window
        if metadata.tcp_window == 0:
            anomaly = TCPAnomaly(
                anomaly_type="zero_window",
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=metadata.src_ip,
                dst_ip=metadata.dst_ip,
                src_port=metadata.src_port,
                dst_port=metadata.dst_port,
                details="TCP window size is 0",
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]["zero_windows"] += 1

        # v4.17.0: Capture teardown packets (FIN/RST) for sampled timeline - BIDIRECTIONAL
        # v4.15.7: Only capture FIRST teardown (RFC 793 compliant - teardown begins at first FIN/RST)
        # Do NOT overwrite if already captured (e.g., retransmitted FIN 14 minutes later)
        # Only for flows that have sampled timeline (i.e., flows with retransmissions)
        if flow_key in self.sampled_timelines and (metadata.is_fin or metadata.is_rst):
            # Capture forward teardown (only if not already captured)
            if not self.sampled_timelines[flow_key].teardown:
                # v5.2.3: Add safety check to prevent KeyError
                if flow_key in self._packet_buffer:
                    self.sampled_timelines[flow_key].teardown = list(self._packet_buffer[flow_key])

            # CRITICAL FIX v4.17.0: Capture reverse teardown simultaneously
            # Prevents data loss when port reuse cleanup deletes reverse buffer
            if not self.sampled_timelines[flow_key].reverse_teardown:
                if reverse_key in self._packet_buffer:
                    self.sampled_timelines[flow_key].reverse_teardown = list(self._packet_buffer[reverse_key])

    def finalize(self) -> dict[str, Any]:
        """Finalise l'analyse et génère le rapport"""
        # Cleanup: Clear _seen_segments to free memory
        # No longer needed after analysis is complete
        self._seen_segments.clear()
        # Clear other tracking dicts to prevent memory leaks
        self._highest_seq.clear()
        self._max_ack_seen.clear()
        self._dup_ack_count.clear()
        self._initial_seq.clear()  # Clear ISN tracking

        self._calculate_flow_severity()
        return self._generate_report()

    def _analyze_packet(self, packet_num: int, packet: Packet) -> None:
        """Analyse un paquet TCP individuel"""
        tcp = packet[TCP]
        ip = get_ip_layer(packet)
        if not ip:
            return
        timestamp = float(packet.time)

        flow_key = self._get_flow_key(packet)
        reverse_key = self._get_reverse_flow_key(packet)
        self._flow_counters[flow_key]["total"] += 1

        # v4.15.0: Buffer packets for hybrid sampled timeline (Scapy path)
        if flow_key not in self._packet_buffer:
            self._packet_buffer[flow_key] = deque(maxlen=10)

        # Create SimplePacketInfo for current packet
        packet_info = _create_simple_packet_info(
            packet_num=packet_num,
            timestamp=timestamp,
            src_ip=ip.src,
            src_port=tcp.sport,
            dst_ip=ip.dst,
            dst_port=tcp.dport,
            tcp_seq=tcp.seq,
            tcp_ack=tcp.ack if (tcp.flags & 0x10) else 0,  # ACK flag check
            tcp_window=tcp.window,
            tcp_payload_len=len(tcp.payload),
            flags_str=_tcp_flags_to_string(tcp=tcp),
            is_retransmission=False,  # Will be updated if retransmission detected
        )

        # Add to ring buffer
        self._packet_buffer[flow_key].append(packet_info)

        # CRITICAL FIX v4.16.2: Check for port reuse BEFORE updating state machine (Scapy path)
        # Race condition fix: must validate ISN and timestamps BEFORE process_packet() overwrites them
        # Bug: process_packet() updates flow_state.isn and last_packet_time, breaking validation
        # Solution: Check should_reset_flow_state() BEFORE calling process_packet()
        syn_seq = tcp.seq if (tcp.flags & 0x02) else None
        if self._state_machine.should_reset_flow_state(flow_key, timestamp, syn_seq):
            # Connection closed (FIN-ACK complete, RST, timeout) or port reuse detected
            self._reset_flow_state(flow_key, reverse_key)
            # Update ISN tracking after reset
            if tcp.flags & 0x02:  # SYN
                self._initial_seq[flow_key] = tcp.seq

        # v5.2.3: Permanent SYN storage to prevent handshake contamination (Scapy path)
        # MUST be AFTER reset to avoid being deleted by _reset_flow_state()
        if (tcp.flags & 0x02) and flow_key not in self._syn_packet:
            self._syn_packet[flow_key] = packet_info
            logger.debug(f"Captured initial SYN for {flow_key} (Frame {packet_num})")

        # RFC 793: Update TCP state machine (AFTER potential reset)
        tcp_flags = {
            "SYN": bool(tcp.flags & 0x02),
            "ACK": bool(tcp.flags & 0x10),
            "FIN": bool(tcp.flags & 0x01),
            "RST": bool(tcp.flags & 0x04),
        }
        self._state_machine.process_packet(
            flow_key=flow_key,
            timestamp=timestamp,
            tcp_flags=tcp_flags,
            seq=tcp.seq,
            ack=tcp.ack if (tcp.flags & 0x10) else 0,
            payload_len=len(tcp.payload),
        )

        # Legacy ISN tracking (for backward compatibility and additional validation)
        # The state machine handles the primary logic, this provides secondary validation
        if (tcp.flags & 0x02) and flow_key not in self._initial_seq:
            self._initial_seq[flow_key] = tcp.seq

        # Mise à jour du Max ACK vu pour ce flux
        if tcp.flags & 0x10:  # ACK flag
            ack = tcp.ack
            if flow_key not in self._max_ack_seen or ack > self._max_ack_seen[flow_key]:
                self._max_ack_seen[flow_key] = ack

        # Détection de retransmissions
        # On calcule d'abord les propriétés de séquence pour TOUS les paquets TCP
        seq = tcp.seq
        payload_len = len(tcp.payload)

        # FIX: Use proper logical length calculation (RFC 793)
        # SYN and FIN flags each consume one sequence number
        logical_len = get_tcp_logical_length(tcp)

        next_seq = seq + logical_len

        # On ne cherche des retransmissions QUE si le paquet transporte des données ou SYN/FIN
        # (On ignore les purs ACKs pour la détection, mais on les utilise pour le tracking)
        has_payload_or_flags = (payload_len > 0) or (tcp.flags & 0x03)

        if has_payload_or_flags:
            # Clé unique: seq + longueur de payload pour distinguer retransmissions partielles
            segment_key = (seq, payload_len)

            is_retransmission = False
            is_spurious = False  # v5.3.0: Track if this is a spurious retransmission
            original_num = None
            original_time = None

            # Méthode combinée (Wireshark-like + Exact Match)

            # 1. Vérifier si le segment exact (seq, len) a déjà été vu
            # C'est la méthode la plus fiable pour distinguer Retransmission vs Out-of-Order
            if segment_key in self._seen_segments[flow_key]:
                is_retransmission = True
                original_num, original_time = self._seen_segments[flow_key][segment_key][0]

            # 2. Vérifier si c'est une Spurious Retransmission (déjà ACKé par l'autre côté)
            reverse_key = self._get_reverse_flow_key(packet)
            if not is_retransmission and reverse_key in self._max_ack_seen:
                max_ack = self._max_ack_seen[reverse_key]
                # FIX: Use logical_len instead of payload_len (accounts for SYN/FIN)
                # Si le segment entier est avant le max ACK, c'est une retransmission inutile
                if seq + logical_len <= max_ack:
                    is_retransmission = True
                    is_spurious = True  # v5.3.0: Mark as spurious (already ACKed)
                    # On ne connait pas forcément l'original si le tracking a commencé après,
                    # mais on sait que c'est une retransmission.
                    # On garde original_num = None pour l'instant, on le settera ci-dessous

            # 3. Vérifier Fast Retransmission (SEQ attendu par >2 DUP ACKs)
            if not is_retransmission and self._dup_ack_count[reverse_key] > 2:
                expected_seq = self._last_ack[reverse_key]
                if seq == expected_seq:
                    is_retransmission = True
                    # Fast Retransmission confirmée

            # 4. RFC 793 Compliant: Retransmission = segment already delivered AND acked
            # v5.3.0 FIX: Removed overly aggressive "seq < highest_seq" detection
            # that caused false positives for normal out-of-order packets.
            #
            # DISABLED OLD LOGIC:
            # if seq < highest_seq: is_retransmission = True
            #
            # PROBLEM: Out-of-order packets (arriving late but never sent before) were
            # incorrectly flagged as retransmissions. Example:
            #   - Packet A (seq 1000-2460) arrives first -> highest_seq = 2460
            #   - Packet C (seq 4000-5460) arrives second -> highest_seq = 5460
            #   - Packet B (seq 2460-3920) arrives third -> FALSE POSITIVE!
            #     (2460 < 5460 but it's not a retransmission, just out-of-order)
            #
            # RFC 793: A retransmission occurs when the SAME segment (seq+len) is sent
            # multiple times, OR when a segment is sent again after being ACKed (spurious).
            # Out-of-order delivery is NOT retransmission - it's normal TCP behavior.
            #
            # CORRECT DETECTION (already implemented above):
            #   Method #1: Exact segment match (seq, len) seen multiple times ✅
            #   Method #2: Spurious (seq+len <= max_ack_seen) ✅
            #   Method #3: Fast retrans (3 dup ACKs) ✅
            #
            # Method #4 REMOVED to eliminate false positives (59% over-detection vs tshark)
            pass  # No additional detection needed - methods #1-3 are sufficient and RFC-compliant

            if is_retransmission:
                # Essayer de trouver le paquet original exact si pas encore trouvé
                if original_num is None:
                    if (
                        segment_key in self._seen_segments[flow_key]
                        and len(self._seen_segments[flow_key][segment_key]) > 0
                    ):
                        original_num, original_time = self._seen_segments[flow_key][segment_key][0]
                    elif flow_key in self._highest_seq:
                        # Fallback sur highest_seq info si on n'a pas l'historique complet
                        _, highest_pkt, highest_time = self._highest_seq[flow_key]
                        # Attention: ce n'est pas forcément le VRAI original, mais une approx
                        original_num = highest_pkt
                        original_time = highest_time
                    else:
                        # Dernier recours
                        original_num = packet_num
                        original_time = timestamp

                delay = timestamp - original_time

                # Determine retransmission type based on delay heuristics
                retrans_type = "Retransmission"  # Default
                if delay >= self.rto_threshold:
                    retrans_type = "RTO"
                elif delay <= self.fast_retrans_delay_max:
                    retrans_type = "Fast Retransmission"

                # Phase 1: Calculate context enrichment fields
                expected_ack = seq + logical_len
                last_ack = self._last_ack.get(reverse_key)
                last_ack_pkt = self._last_ack_packet_num.get(reverse_key)
                last_ack_ts = self._last_ack_timestamp.get(reverse_key)
                time_since_last_ack = None
                if last_ack_ts is not None:
                    time_since_last_ack = (timestamp - last_ack_ts) * 1000  # Convert to ms

                current_dup_ack_count = self._dup_ack_count.get(reverse_key, 0)
                max_ack = self._max_ack_seen.get(reverse_key, 0)

                # Phase 1: Diagnose with evidence-based logic
                suspected_mechanisms, confidence = self._diagnose_retransmission(
                    seq=seq,
                    logical_len=logical_len,
                    reverse_key=reverse_key,
                    timestamp=timestamp,
                    dup_ack_count=current_dup_ack_count,
                    max_ack_seen=max_ack,
                    receiver_window=tcp.window,
                )

                # v4.18.0: Align retrans_type with diagnosis confidence
                if confidence == "high":
                    retrans_type = "Spurious Retransmission"
                elif confidence == "medium":
                    retrans_type = "Fast Retransmission"

                retrans = TCPRetransmission(
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    seq_num=seq,
                    original_packet_num=original_num,
                    delay=delay,
                    retrans_type=retrans_type,  # Assign the type
                    # Phase 1: Context enrichment
                    expected_ack=expected_ack,
                    last_ack_seen=last_ack,
                    last_ack_packet_num=last_ack_pkt,
                    time_since_last_ack_ms=time_since_last_ack,
                    dup_ack_count=current_dup_ack_count,
                    receiver_window_raw=tcp.window,
                    suspected_mechanisms=suspected_mechanisms,
                    confidence=confidence,
                    is_syn_retrans=(tcp.flags & 0x02) != 0,  # SYN flag check
                    syn_retrans_direction=self._classify_syn_retransmission(tcp) if (tcp.flags & 0x02) else None,
                    is_spurious=is_spurious,  # v5.3.0: Mark spurious retransmissions
                    tcp_flags=_tcp_flags_to_string(tcp=tcp),
                )
                self.retransmissions.append(retrans)
                self._flow_counters[flow_key]["retransmissions"] += 1

                # v4.17.0: Sampled Timeline - Lazy allocation with bidirectional snapshot (Scapy path)
                if flow_key not in self.sampled_timelines:
                    # Flow just became problematic - snapshot BOTH directions
                    # CRITICAL: Capture reverse direction NOW before port reuse cleanup deletes it
                    
                    # v5.2.3 Fix: Ensure initial SYN is always included in handshake
                    forward_handshake = []
                    # 1. Always include the SYN if it exists
                    if flow_key in self._syn_packet:
                        forward_handshake.append(self._syn_packet[flow_key])
                    # 2. Add other packets from buffer (avoiding duplicates)
                    buffer_packets = [
                        p for p in self._packet_buffer[flow_key] 
                        if not (flow_key in self._syn_packet and p.frame == self._syn_packet[flow_key].frame)
                    ]
                    forward_handshake.extend(buffer_packets)
                    forward_handshake.sort(key=lambda p: p.timestamp)
                    forward_handshake = forward_handshake[:10]

                    # v5.2.3 Fix: Ensure initial SYN is always included in reverse handshake
                    reverse_handshake = []
                    # 1. Always include the SYN if it exists
                    if reverse_key in self._syn_packet:
                        reverse_handshake.append(self._syn_packet[reverse_key])
                    # 2. Add other packets from buffer (avoiding duplicates)
                    if reverse_key in self._packet_buffer:
                        buffer_packets = [
                            p for p in self._packet_buffer[reverse_key]
                            if not (reverse_key in self._syn_packet and p.frame == self._syn_packet[reverse_key].frame)
                        ]
                        reverse_handshake.extend(buffer_packets)
                    reverse_handshake.sort(key=lambda p: p.timestamp)
                    reverse_handshake = reverse_handshake[:10]

                    self.sampled_timelines[flow_key] = SampledTimeline(
                        handshake=forward_handshake,
                        retrans_context=[],
                        teardown=[],
                        reverse_handshake=reverse_handshake,  # NEW: Bidirectional snapshot
                        reverse_teardown=[],  # NEW: Will be captured on FIN/RST
                        reverse_captured=True,  # NEW: Mark as captured
                    )

                # Mark current packet as retransmission in buffer
                packet_info.is_retransmission = True

                # v4.17.1: Capture BIDIRECTIONAL retransmission context
                # Forward direction: Last 5 packets (including current retransmission)
                forward_buffer = list(self._packet_buffer[flow_key])
                forward_start = max(0, len(forward_buffer) - 5)
                forward_context = forward_buffer[forward_start:]

                # Reverse direction: Filter by time window from forward context
                reverse_context = []
                if reverse_key in self._packet_buffer and forward_context:
                    reverse_buffer = list(self._packet_buffer[reverse_key])
                    time_window_start = forward_context[0].timestamp
                    time_window_end = forward_context[-1].timestamp

                    # Filter reverse packets within time window, take last 5
                    reverse_context = [
                        p for p in reverse_buffer if time_window_start <= p.timestamp <= time_window_end
                    ][-5:]

                # Merge bidirectional contexts and bound to 10 packets total
                merged_context = forward_context + reverse_context
                merged_context.sort(key=lambda p: p.timestamp)
                if len(merged_context) > 10:
                    merged_context = merged_context[:10]

                # Store bidirectional retransmission context
                self.sampled_timelines[flow_key].retrans_context.append(merged_context)

            # Store only original packet info to prevent unbounded memory growth
            # We only need the first occurrence to detect retransmissions
            if segment_key not in self._seen_segments[flow_key]:
                self._seen_segments[flow_key][segment_key] = [(packet_num, timestamp)]
            # For retransmissions, we already have the original, no need to store more

        # Mettre à jour le plus haut seq vu pour ce flux (POUR TOUS LES PAQUETS)
        if flow_key not in self._highest_seq or next_seq > self._highest_seq[flow_key][0]:
            self._highest_seq[flow_key] = (next_seq, packet_num, timestamp)

        # Détection de DUP ACK et Fast Retransmission
        if tcp.flags & 0x10:  # ACK flag
            ack = tcp.ack
            reverse_flow = self._get_reverse_flow_key(packet)

            # Vérifier si c'est un DUP ACK
            if reverse_flow in self._last_ack and ack == self._last_ack[reverse_flow]:
                # C'est un DUP ACK
                self._dup_ack_count[reverse_flow] += 1

                anomaly = TCPAnomaly(
                    anomaly_type="dup_ack",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Duplicate ACK #{self._dup_ack_count[reverse_flow]} for seq {ack}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["dup_acks"] += 1

                # Détection de Fast Retransmission (après 3 DUP ACK selon RFC)
                if self._dup_ack_count[reverse_flow] >= 3:
                    # Marquer comme fast retransmission potentielle
                    # La vraie fast retrans sera détectée quand le segment sera renvoyé
                    pass
            else:
                # Nouvel ACK, réinitialiser le compteur de DUP ACK
                self._dup_ack_count[reverse_flow] = 0

            self._last_ack[reverse_flow] = ack
            self._expected_ack[reverse_flow] = ack
            # Phase 1: Track packet number and timestamp of ACK
            self._last_ack_packet_num[reverse_flow] = packet_num
            self._last_ack_timestamp[reverse_flow] = timestamp

        # Détection Out-of-Order
        # FIX: Check logical_len instead of just payload (accounts for SYN/FIN)
        if logical_len > 0:
            seq = tcp.seq
            expected = self._expected_seq.get(flow_key, seq)

            if seq < expected:
                # Paquet reçu avec un numéro de séquence inférieur à celui attendu
                anomaly = TCPAnomaly(
                    anomaly_type="out_of_order",
                    packet_num=packet_num,
                    timestamp=timestamp,
                    src_ip=ip.src,
                    dst_ip=ip.dst,
                    src_port=tcp.sport,
                    dst_port=tcp.dport,
                    details=f"Expected seq {expected}, got {seq}",
                )
                self.anomalies.append(anomaly)
                self._flow_counters[flow_key]["out_of_order"] += 1
            else:
                # FIX: Use logical_len (accounts for SYN/FIN flags)
                self._expected_seq[flow_key] = seq + logical_len

        # Détection Zero Window
        if tcp.window == 0:
            anomaly = TCPAnomaly(
                anomaly_type="zero_window",
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=ip.src,
                dst_ip=ip.dst,
                src_port=tcp.sport,
                dst_port=tcp.dport,
                details="TCP window size is 0",
            )
            self.anomalies.append(anomaly)
            self._flow_counters[flow_key]["zero_windows"] += 1

        # v4.17.0: Capture teardown packets (FIN/RST) for sampled timeline - BIDIRECTIONAL (Scapy path)
        # v4.15.7: Only capture FIRST teardown (RFC 793 compliant - teardown begins at first FIN/RST)
        # Do NOT overwrite if already captured (e.g., retransmitted FIN 14 minutes later)
        if flow_key in self.sampled_timelines and (tcp.flags & 0x01 or tcp.flags & 0x04):  # FIN or RST
            # Capture forward teardown (only if not already captured)
            if not self.sampled_timelines[flow_key].teardown:
                # v5.2.3: Add safety check to prevent KeyError
                if flow_key in self._packet_buffer:
                    self.sampled_timelines[flow_key].teardown = list(self._packet_buffer[flow_key])

            # CRITICAL FIX v4.17.0: Capture reverse teardown simultaneously
            # Prevents data loss when port reuse cleanup deletes reverse buffer
            if not self.sampled_timelines[flow_key].reverse_teardown:
                if reverse_key in self._packet_buffer:
                    self.sampled_timelines[flow_key].reverse_teardown = list(self._packet_buffer[reverse_key])

    def _get_flow_key(self, packet: Packet) -> str:
        """Génère une clé de flux unidirectionnelle"""
        ip = get_ip_layer(packet)
        if not ip:
            return ""
        tcp = packet[TCP]
        # Ensure ports are integers (they can sometimes be hex strings)
        sport = (
            int(tcp.sport)
            if isinstance(tcp.sport, int)
            else int(str(tcp.sport), 16) if isinstance(tcp.sport, str) else tcp.sport
        )
        dport = (
            int(tcp.dport)
            if isinstance(tcp.dport, int)
            else int(str(tcp.dport), 16) if isinstance(tcp.dport, str) else tcp.dport
        )
        return f"{ip.src}:{sport}->{ip.dst}:{dport}"

    def _get_reverse_flow_key(self, packet: Packet) -> str:
        """Génère la clé de flux inverse"""
        ip = get_ip_layer(packet)
        if not ip:
            return ""
        tcp = packet[TCP]
        # Ensure ports are integers (they can sometimes be hex strings)
        sport = (
            int(tcp.sport)
            if isinstance(tcp.sport, int)
            else int(str(tcp.sport), 16) if isinstance(tcp.sport, str) else tcp.sport
        )
        dport = (
            int(tcp.dport)
            if isinstance(tcp.dport, int)
            else int(str(tcp.dport), 16) if isinstance(tcp.dport, str) else tcp.dport
        )
        return f"{ip.dst}:{dport}->{ip.src}:{sport}"

    def _classify_syn_retransmission(self, metadata: Any) -> str:
        """
        Classify SYN retransmission as client-side or server-side failure.

        Returns:
            - "server_unreachable": Client SYN retransmissions (no SYN,ACK received)
            - "client_unreachable": Server SYN,ACK retransmissions (client didn't complete)
        """
        # Note: metadata can be PacketMetadata (lightweight) or dict-like from Scapy path
        is_ack = False
        if hasattr(metadata, "is_ack"):
            is_ack = metadata.is_ack
        elif hasattr(metadata, "flags"):
            # Scapy TCP flags: SYN=0x02, ACK=0x10
            is_ack = bool(metadata.flags & 0x10)

        if is_ack:
            # Server retransmitting SYN,ACK → Client unreachable/unable to complete
            return "client_unreachable"
        else:
            # Client retransmitting SYN → Server unreachable
            return "server_unreachable"

    def _calculate_flow_severity(self) -> None:
        """Calcule la sévérité pour chaque flux"""
        for flow_key, counters in self._flow_counters.items():
            try:
                parts = flow_key.split("->")
                # Use rsplit to handle IPv6 addresses (e.g., ::1:46650 -> ['::1', '46650'])
                src_part, dst_part = parts[0].rsplit(":", 1), parts[1].rsplit(":", 1)

                retrans_count = counters["retransmissions"]
                total_packets = counters["total"]

                # Calcul du taux de retransmission en pourcentage
                retrans_rate = (retrans_count / total_packets * 100) if total_packets > 0 else 0

                # La sévérité est déterminée par le taux, MAIS il faut un minimum absolu de retransmissions
                # pour éviter de flagger les très petits flux (ex: 1 retrans sur 4 paquets = 25%)

                severity = "none"

                # On vérifie d'abord si on dépasse le seuil absolu minimal (low)
                if retrans_count >= self.retrans_low:
                    if retrans_rate >= self.retrans_rate_critical:
                        severity = "critical"
                    elif retrans_rate >= self.retrans_rate_medium:
                        severity = "medium"
                    elif retrans_rate >= self.retrans_rate_low:
                        severity = "low"

                    # Fallback: si le nombre absolu est très élevé, on flag quand même
                    # même si le taux est bas (ex: flux très long)
                    if severity == "none" and retrans_count >= self.retrans_critical:
                        severity = "low"  # On reste en low si c'est juste du volume mais taux faible

                # Parse ports with error handling for hex strings or invalid values
                try:
                    src_port = int(src_part[1])
                except ValueError:
                    # Try parsing as hex if decimal fails
                    src_port = int(src_part[1], 16)

                try:
                    dst_port = int(dst_part[1])
                except ValueError:
                    # Try parsing as hex if decimal fails
                    dst_port = int(dst_part[1], 16)

                stats = FlowStats(
                    flow_key=flow_key,
                    src_ip=src_part[0],
                    dst_ip=dst_part[0],
                    src_port=src_port,
                    dst_port=dst_port,
                    total_packets=counters["total"],
                    retransmissions=counters["retransmissions"],
                    dup_acks=counters["dup_acks"],
                    out_of_order=counters["out_of_order"],
                    zero_windows=counters["zero_windows"],
                    severity=severity,
                    retransmission_rate=retrans_rate,
                )

                self.flow_stats[flow_key] = stats
            except (ValueError, IndexError) as e:
                # Skip malformed flow keys
                print(f"Warning: Skipping malformed flow key '{flow_key}': {e}")
                continue

    def _count_unique_retransmitted_segments(self) -> int:
        """
        Compte le nombre de segments uniques qui ont été retransmis.
        Un segment retransmis 2 fois compte pour 1 segment unique.
        """
        unique_segments = set()
        for retrans in self.retransmissions:
            # Clé unique: (src, dst, sport, dport, seq)
            key = (retrans.src_ip, retrans.dst_ip, retrans.src_port, retrans.dst_port, retrans.seq_num)
            unique_segments.add(key)
        return len(unique_segments)

    def _generate_report(self) -> dict[str, Any]:
        """Génère le rapport d'analyse"""
        total_retrans = len(self.retransmissions)
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != "none"]

        # Compte les anomalies par type
        anomaly_counts = defaultdict(int)
        for anomaly in self.anomalies:
            anomaly_counts[anomaly.anomaly_type] += 1

        # Statistiques de sévérité
        severity_counts = defaultdict(int)
        for flow in self.flow_stats.values():
            severity_counts[flow.severity] += 1

        # Tri des retransmissions par délai décroissant (les plus graves en premier)
        sorted_retransmissions = sorted(self.retransmissions, key=lambda r: r.delay, reverse=True)

        # Exclude SYN retransmissions from RTO count (they're connection failures, not RTO during established connections)
        rto_count = sum(1 for r in self.retransmissions if r.retrans_type == "RTO" and not r.is_syn_retrans)
        fast_retrans_count = sum(1 for r in self.retransmissions if r.retrans_type == "Fast Retransmission")
        # All other types (including "Unknown" and "Retransmission")
        other_retrans_count = total_retrans - rto_count - fast_retrans_count

        # v4.17.0: Serialize sampled timelines for HTML report - SIMPLIFIED
        # Uses pre-captured bidirectional snapshots instead of _packet_buffer lookups
        # No complex reverse_key calculations needed - data already captured at detection time
        sampled_timelines_dict = {}
        for flow_key, timeline in self.sampled_timelines.items():
            # CRITICAL FIX v4.17.0: Use pre-captured snapshots (no buffer lookups)
            # Handshake: Merge forward + reverse snapshots
            handshake_packets = list(timeline.handshake) + list(timeline.reverse_handshake)
            handshake_packets.sort(key=lambda p: p.timestamp)
            handshake_packets = handshake_packets[:10]  # First 10 packets total

            # v4.17.1: Retransmission contexts are now BIDIRECTIONAL
            # Contexts already merged at capture time (see lines 883-909, 1255-1281)
            merged_retrans_contexts = timeline.retrans_context

            # Teardown: Merge forward + reverse snapshots
            teardown_packets = list(timeline.teardown) + list(timeline.reverse_teardown)
            teardown_packets.sort(key=lambda p: p.timestamp)
            teardown_packets = teardown_packets[-10:] if len(teardown_packets) > 10 else teardown_packets

            sampled_timelines_dict[flow_key] = {
                "handshake": [asdict(p) for p in handshake_packets],
                "retrans_context": [[asdict(p) for p in context] for context in merged_retrans_contexts],
                "teardown": [asdict(p) for p in teardown_packets],
            }

        return {
            "total_flows": len(self.flow_stats),
            "flows_with_issues": len(flows_with_issues),
            "total_retransmissions": total_retrans,
            "total_anomalies": len(self.anomalies),
            "anomaly_types": dict(anomaly_counts),
            "severity_distribution": dict(severity_counts),
            "thresholds": {"low": self.retrans_low, "medium": self.retrans_medium, "critical": self.retrans_critical},
            "retransmissions": [asdict(r) for r in sorted_retransmissions],
            "anomalies": [asdict(a) for a in self.anomalies],
            "flow_statistics": [asdict(f) for f in self.flow_stats.values()],
            "rto_count": rto_count,
            "fast_retrans_count": fast_retrans_count,
            "other_retrans_count": other_retrans_count,
            "unique_retransmitted_segments": self._count_unique_retransmitted_segments(),
            "sampled_timelines": sampled_timelines_dict,  # v4.15.0: Packet timelines for problematic flows
        }

    def get_summary(self) -> str:
        """Retourne un résumé textuel de l'analyse"""
        total_retrans = len(self.retransmissions)
        unique_segments = self._count_unique_retransmitted_segments()
        flows_with_issues = [f for f in self.flow_stats.values() if f.severity != "none"]

        summary = f"📊 Analyse des retransmissions et anomalies TCP:\n"
        summary += f"  - Flux analysés: {len(self.flow_stats)}\n"
        summary += f"  - Retransmissions totales: {total_retrans}\n"
        summary += f"    ({unique_segments} segment(s) unique(s) retransmis)\n"

        # Exclude SYN retransmissions from RTO count (they're connection failures, not RTO during established connections)
        rto_count = sum(1 for r in self.retransmissions if r.retrans_type == "RTO" and not r.is_syn_retrans)
        fast_retrans_count = sum(1 for r in self.retransmissions if r.retrans_type == "Fast Retransmission")
        other_retrans_count = total_retrans - rto_count - fast_retrans_count

        # Calculate global retransmission rate for contextual alerting
        # Industry standards: <1% normal, 1-3% moderate, >3% severe (NetCraftsmen, arXiv research)
        total_packets = sum(f.total_packets for f in self.flow_stats.values())
        retrans_rate = (total_retrans / total_packets * 100) if total_packets > 0 else 0

        if rto_count > 0:
            # Contextual severity based on rate AND absolute count
            # Prevents false alarms like "1 RTO in 800K packets = severe congestion"
            if retrans_rate > 3.0 or rto_count > 500:
                severity_label = "🔴 (Congestion Sévère)"
            elif retrans_rate > 1.0 or rto_count > 100:
                severity_label = "🟠 (Modérée)"
            else:
                severity_label = "⚪ (Négligeable)"
            summary += f"    dont RTOs: {rto_count} {severity_label}\n"
        if fast_retrans_count > 0:
            summary += f"    dont Fast Retransmissions: {fast_retrans_count} 🟠 (Pertes Légères / Désordre)\n"
        if other_retrans_count > 0:
            summary += f"    dont Autres Retransmissions: {other_retrans_count} 🔵 (Causes diverses)\n"

        summary += f"  - Anomalies totales: {len(self.anomalies)}\n"

        if flows_with_issues:
            summary += f"\n🔴 {len(flows_with_issues)} flux avec problèmes:\n"

            for flow in sorted(flows_with_issues, key=lambda f: f.retransmissions, reverse=True)[:10]:
                summary += f"\n  {flow.flow_key}\n"
                summary += f"    - Sévérité: {flow.severity.upper()}\n"
                summary += f"    - Retransmissions: {flow.retransmissions}\n"
                summary += f"    - DUP ACK: {flow.dup_acks}\n"
                summary += f"    - Out-of-Order: {flow.out_of_order}\n"
                summary += f"    - Zero Window: {flow.zero_windows}\n"

        return summary

    def get_details(self, limit: int = 20, flow_filter: str = None) -> str:
        """
        Retourne les détails des retransmissions

        Args:
            limit: Nombre maximum de retransmissions à afficher
            flow_filter: Filtrer sur un flux spécifique (ex: "10.28.104.211:16586->10.179.161.14:10100")

        Returns:
            Chaîne formatée avec les détails des retransmissions
        """
        if not self.retransmissions:
            return "✅ Aucune retransmission à détailler."

        # Filtrage par flux si demandé
        retrans_list = self.retransmissions
        if flow_filter:
            retrans_list = [
                r for r in retrans_list if f"{r.src_ip}:{r.src_port}->{r.dst_ip}:{r.dst_port}" == flow_filter
            ]

        if not retrans_list:
            return f"✅ Aucune retransmission trouvée pour le flux: {flow_filter}"

        # Tri par délai décroissant (les pires retransmissions en premier)
        # On privilégie les RTO (délais longs) aux Fast Retransmissions (délais courts)
        retrans_list.sort(key=lambda r: r.delay, reverse=True)

        total = len(retrans_list)
        displayed = min(limit, total)

        details = f"🔍 Détails des retransmissions (Top {displayed} par délai / Total {total}):\n\n"

        for i, retrans in enumerate(retrans_list[:limit], 1):
            delay_ms = retrans.delay * 1000  # Convertir en ms
            details += f"  #{i}: Paquet {retrans.packet_num} (retrans de #{retrans.original_packet_num})\n"
            details += f"      Seq: {retrans.seq_num}, Délai: {delay_ms:.1f}ms\n"
            details += f"      {retrans.src_ip}:{retrans.src_port} → {retrans.dst_ip}:{retrans.dst_port}\n"
            if i < displayed:
                details += "\n"

        if total > limit:
            details += (
                f"\n  ... et {total - limit} autres retransmissions (utilisez --details-limit pour en voir plus)\n"
            )

        return details
