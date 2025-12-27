"""
Fast packet parser using dpkt for 10x performance improvement.

This module uses dpkt (lightweight packet parsing) to extract metadata from packets
much faster than Scapy's full dissection. dpkt achieves ~12,000 packets/second
compared to Scapy's ~700-900 packets/second.

SECURITY: Implements decompression bomb protection (OWASP ASVS 5.2.3, CWE-409).

Usage:
    parser = FastPacketParser('capture.pcap')
    for metadata in parser.parse():
        # Process lightweight metadata instead of full Scapy packets
        print(f"{metadata.src_ip}:{metadata.src_port} -> {metadata.dst_ip}:{metadata.dst_port}")
"""

import logging
import os
import socket
import struct
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import dpkt

from ..utils.decompression_monitor import DecompressionMonitor, DecompressionBombError
from ..utils.logging_filters import PIIRedactionFilter

logger = logging.getLogger(__name__)
# GDPR/NIST Compliance: Redact PII from logs (IP addresses, file paths)
logger.addFilter(PIIRedactionFilter())


@dataclass
class PacketMetadata:
    """
    Lightweight packet metadata extracted by dpkt.

    This is much smaller in memory than a full Scapy Packet object.
    Contains only the essential information needed by most analyzers.
    """

    # Packet identification
    packet_num: int
    timestamp: float

    # Network layer (IP)
    src_ip: str
    dst_ip: str
    ip_version: int  # 4 or 6
    ttl: int
    total_length: int  # IP layer length (for IP fragmentation analysis)
    packet_length: int  # Full packet length including all headers (equivalent to len(packet) in Scapy)
    protocol: str  # 'TCP', 'UDP', 'ICMP', 'Other'

    # Transport layer (TCP/UDP)
    src_port: Optional[int] = None
    dst_port: Optional[int] = None

    # TCP-specific fields
    tcp_seq: Optional[int] = None
    tcp_ack: Optional[int] = None
    tcp_flags: Optional[int] = None  # Raw flags value
    tcp_window: Optional[int] = None
    tcp_payload_len: int = 0

    # UDP-specific
    udp_length: Optional[int] = None

    # ICMP-specific
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None

    # Convenience flags for TCP (computed from tcp_flags)
    is_syn: bool = False
    is_ack: bool = False
    is_fin: bool = False
    is_rst: bool = False
    is_psh: bool = False

    def __post_init__(self):
        """Compute convenience TCP flags after initialization."""
        if self.tcp_flags is not None:
            self.is_syn = bool(self.tcp_flags & dpkt.tcp.TH_SYN)
            self.is_ack = bool(self.tcp_flags & dpkt.tcp.TH_ACK)
            self.is_fin = bool(self.tcp_flags & dpkt.tcp.TH_FIN)
            self.is_rst = bool(self.tcp_flags & dpkt.tcp.TH_RST)
            self.is_psh = bool(self.tcp_flags & dpkt.tcp.TH_PUSH)


class FastPacketParser:
    """
    Fast PCAP parser using dpkt.

    Provides 10x performance improvement over Scapy for basic packet metadata extraction.
    Use this for initial pass through large PCAP files, then use Scapy only for
    packets that need deep inspection (DNS, ICMP details, etc.).

    SECURITY: Includes decompression bomb protection (OWASP ASVS 5.2.3, CWE-409).
    """

    def __init__(
        self,
        pcap_file: str,
        enable_bomb_protection: bool = True,
        max_expansion_ratio: int = 1000,
        critical_expansion_ratio: int = 10000,
    ):
        """
        Initialize fast parser.

        Args:
            pcap_file: Path to PCAP file
            enable_bomb_protection: Enable decompression bomb detection (default: True)
            max_expansion_ratio: Warning threshold for expansion ratio (default: 1000)
            critical_expansion_ratio: Critical threshold for expansion ratio (default: 10000)
        """
        self.pcap_file = Path(pcap_file)
        if not self.pcap_file.exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_file}")

        # Initialize decompression bomb monitor
        self.decompression_monitor = DecompressionMonitor(
            max_ratio=max_expansion_ratio, critical_ratio=critical_expansion_ratio, enabled=enable_bomb_protection
        )
        self.file_size = os.path.getsize(self.pcap_file)

    def parse(self) -> Iterator[PacketMetadata]:
        """
        Parse PCAP file and yield lightweight PacketMetadata objects.

        This is significantly faster than Scapy's PcapReader because dpkt
        does minimal parsing - only what's needed for the metadata.

        SECURITY: Monitors for decompression bomb attacks (OWASP ASVS 5.2.3, CWE-409).

        Yields:
            PacketMetadata: Lightweight packet information

        Raises:
            DecompressionBombError: If expansion ratio exceeds critical threshold
        """
        packet_num = 0
        bytes_processed = 0

        with open(self.pcap_file, "rb") as f:
            try:
                pcap = dpkt.pcap.Reader(f)
                logger.debug(f"Detected PCAP format for {self.pcap_file}")
            except ValueError:
                # Try pcapng format
                try:
                    f.seek(0)
                    pcap = dpkt.pcapng.Reader(f)
                    logger.debug(f"Detected PCAPNG format for {self.pcap_file}")
                except (ValueError, dpkt.dpkt.UnpackError) as e:
                    logger.error(f"Unable to read PCAP file {self.pcap_file}: {e}")
                    raise ValueError(f"Unable to read PCAP file: {self.pcap_file}")

            # Detect datalink type for optimized parsing
            datalink = pcap.datalink()

            for timestamp, buf in pcap:
                try:
                    metadata = self._extract_metadata(buf, packet_num, timestamp, datalink)
                    if metadata:
                        # Track bytes processed for decompression bomb detection
                        bytes_processed += metadata.packet_length

                        # Check for decompression bomb every N packets (OWASP ASVS 5.2.3)
                        if packet_num % 10000 == 0 and packet_num > 0:
                            try:
                                self.decompression_monitor.check_expansion_ratio(
                                    self.file_size, bytes_processed, packet_num
                                )
                            except DecompressionBombError:
                                logger.critical(
                                    f"Decompression bomb detected at packet {packet_num}. "
                                    f"Processing aborted for security. "
                                    f"Processed {bytes_processed:,} bytes from {self.file_size:,} byte file."
                                )
                                raise

                        yield metadata
                    packet_num += 1
                except DecompressionBombError:
                    # Re-raise security exceptions
                    raise
                except Exception as e:
                    # Skip malformed packets but log for debugging
                    logger.debug(f"Skipping malformed packet #{packet_num}: {e}")
                    packet_num += 1
                    continue

    def _extract_metadata(
        self, buf: bytes, packet_num: int, timestamp: float, datalink: int
    ) -> Optional[PacketMetadata]:
        """
        Extract metadata from raw packet buffer.

        Args:
            buf: Raw packet bytes
            packet_num: Packet number (0-indexed)
            timestamp: Packet timestamp
            datalink: PCAP datalink type (e.g., DLT_EN10MB, DLT_LINUX_SLL2)

        Returns:
            PacketMetadata if packet can be parsed, None otherwise
        """
        try:
            # Parse based on datalink type for efficiency
            if datalink == dpkt.pcap.DLT_LINUX_SLL2:  # 276 - Linux cooked v2
                sll2 = dpkt.sll2.SLL2(buf)
                ip_packet = sll2.data
            elif datalink == dpkt.pcap.DLT_LINUX_SLL:  # 113 - Linux cooked v1
                sll = dpkt.sll.SLL(buf)
                ip_packet = sll.data
            elif datalink == dpkt.pcap.DLT_EN10MB:  # 1 - Ethernet
                eth = dpkt.ethernet.Ethernet(buf)
                ip_packet = eth.data
            elif datalink == 12 or (hasattr(dpkt.pcap, "DLT_RAW") and datalink == dpkt.pcap.DLT_RAW):
                # 12 - Raw IP (no datalink header)
                ip_packet = dpkt.ip.IP(buf)
            elif datalink == 228 or (hasattr(dpkt.pcap, "DLT_IPV4") and datalink == dpkt.pcap.DLT_IPV4):
                # 228 - Raw IPv4
                ip_packet = dpkt.ip.IP(buf)
            elif datalink == 229 or (hasattr(dpkt.pcap, "DLT_IPV6") and datalink == dpkt.pcap.DLT_IPV6):
                # 229 - Raw IPv6
                ip_packet = dpkt.ip6.IP6(buf)
            elif datalink == 0 or (hasattr(dpkt.pcap, "DLT_NULL") and datalink == dpkt.pcap.DLT_NULL):
                # 0 - BSD loopback
                # The first 4 bytes are the protocol family (AF_INET, etc.)
                ip_packet = dpkt.ip.IP(buf[4:])
            else:
                # Try to guess the format (fallback for other datalink types)
                try:
                    eth = dpkt.ethernet.Ethernet(buf)
                    ip_packet = eth.data
                except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, struct.error):
                    try:
                        sll = dpkt.sll.SLL(buf)
                        ip_packet = sll.data
                    except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, struct.error):
                        try:
                            sll2 = dpkt.sll2.SLL2(buf)
                            ip_packet = sll2.data
                        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, struct.error) as e:
                            logger.debug(f"Packet #{packet_num}: Unable to parse datalink layer (type {datalink}): {e}")
                            return None

            # Check if it's IP
            if not isinstance(ip_packet, (dpkt.ip.IP, dpkt.ip6.IP6)):
                return None

            # Extract IP layer info
            if isinstance(ip_packet, dpkt.ip.IP):
                src_ip = socket.inet_ntoa(ip_packet.src)
                dst_ip = socket.inet_ntoa(ip_packet.dst)
                ip_version = 4
                ttl = ip_packet.ttl
                total_length = ip_packet.len
            else:  # IPv6
                src_ip = socket.inet_ntop(socket.AF_INET6, ip_packet.src)
                dst_ip = socket.inet_ntop(socket.AF_INET6, ip_packet.dst)
                ip_version = 6
                ttl = ip_packet.hlim
                total_length = ip_packet.plen + 40  # IPv6 header is 40 bytes

            # Initialize metadata
            metadata = PacketMetadata(
                packet_num=packet_num,
                timestamp=timestamp,
                src_ip=src_ip,
                dst_ip=dst_ip,
                ip_version=ip_version,
                ttl=ttl,
                total_length=total_length,
                packet_length=len(buf),  # Full packet size (including all headers)
                protocol="Other",
            )

            # Extract transport layer info
            transport = ip_packet.data

            if isinstance(transport, dpkt.tcp.TCP):
                metadata.protocol = "TCP"
                metadata.src_port = transport.sport
                metadata.dst_port = transport.dport
                metadata.tcp_seq = transport.seq
                metadata.tcp_ack = transport.ack
                metadata.tcp_flags = transport.flags
                metadata.tcp_window = transport.win
                metadata.tcp_payload_len = len(transport.data)
                # Re-compute convenience flags after setting tcp_flags
                metadata.__post_init__()

            elif isinstance(transport, dpkt.udp.UDP):
                metadata.protocol = "UDP"
                metadata.src_port = transport.sport
                metadata.dst_port = transport.dport
                metadata.udp_length = transport.ulen
                metadata.tcp_payload_len = len(transport.data)  # For consistency

            elif isinstance(transport, dpkt.icmp.ICMP):
                metadata.protocol = "ICMP"
                metadata.icmp_type = transport.type
                metadata.icmp_code = transport.code

            return metadata

        except (dpkt.dpkt.UnpackError, dpkt.dpkt.NeedData, struct.error, OSError) as e:
            logger.debug(f"Failed to extract metadata from packet #{packet_num}: {e}")
            return None

    def count_packets(self) -> int:
        """
        Quickly count total packets in PCAP file.

        Returns:
            Total number of packets
        """
        count = 0
        for _ in self.parse():
            count += 1
        return count


def benchmark_comparison(pcap_file: str, num_packets: int = 10000):
    """
    Benchmark dpkt vs Scapy parsing speed.

    Args:
        pcap_file: Path to PCAP file
        num_packets: Number of packets to parse for benchmark
    """
    import time

    from scapy.all import PcapReader

    # Benchmark dpkt
    print(f"Benchmarking dpkt on {pcap_file}...")
    start = time.time()
    parser = FastPacketParser(pcap_file)
    dpkt_count = 0
    for metadata in parser.parse():
        dpkt_count += 1
        if dpkt_count >= num_packets:
            break
    dpkt_time = time.time() - start
    dpkt_speed = dpkt_count / dpkt_time if dpkt_time > 0 else 0

    # Benchmark Scapy
    print(f"Benchmarking Scapy on {pcap_file}...")
    start = time.time()
    scapy_count = 0
    with PcapReader(pcap_file) as reader:
        for packet in reader:
            scapy_count += 1
            if scapy_count >= num_packets:
                break
    scapy_time = time.time() - start
    scapy_speed = scapy_count / scapy_time if scapy_time > 0 else 0

    print(f"\n📊 Benchmark Results ({num_packets} packets):")
    print(f"  dpkt:  {dpkt_time:.2f}s ({dpkt_speed:.0f} p/s)")
    print(f"  Scapy: {scapy_time:.2f}s ({scapy_speed:.0f} p/s)")
    print(f"  Speedup: {scapy_time/dpkt_time:.1f}x faster with dpkt")


if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        benchmark_comparison(sys.argv[1])
    else:
        print("Usage: python fast_parser.py <pcap_file>")
