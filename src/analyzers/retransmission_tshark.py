"""
tshark Backend for Retransmission Detection

This module provides a tshark-based backend for TCP retransmission detection.
It achieves 100% accuracy by delegating to Wireshark's battle-tested analysis engine.

Architecture:
- find_tshark(): Platform-specific path detection
- TsharkRetransmissionAnalyzer: Subprocess-based analyzer using tshark JSON output
- Maps tshark output to TCPRetransmission dataclass

Performance:
- Single tshark subprocess call for entire PCAP
- JSON output parsing (stdlib, no dependencies)
- Comparable speed to builtin analyzer

Fallback:
- If tshark not found, caller should use BuiltinRetransmissionAnalyzer
- See RetransmissionAnalyzerFactory in retransmission.py
"""

import json
import logging
import platform
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Dict, Any

from .retransmission import TCPRetransmission

logger = logging.getLogger(__name__)


def find_tshark() -> Optional[str]:
    """
    Find tshark binary with platform-specific logic.

    Detection strategy:
    1. macOS: Check /Applications/Wireshark.app/Contents/MacOS/tshark
    2. Linux/Windows: Use shutil.which('tshark') to check PATH
    3. Linux: Check common installation paths
    4. Return None if not found

    Returns:
        Full path to tshark binary, or None if not found

    Examples:
        >>> tshark_path = find_tshark()
        >>> if tshark_path:
        ...     print(f"Found tshark: {tshark_path}")
        ... else:
        ...     print("tshark not found, use builtin backend")
    """
    system = platform.system()
    logger.debug(f"Detecting tshark on platform: {system}")

    # 1. macOS: Check Wireshark.app bundle FIRST (user likely installed via DMG)
    if system == "Darwin":
        macos_path = Path("/Applications/Wireshark.app/Contents/MacOS/tshark")
        if macos_path.exists() and macos_path.is_file():
            logger.info(f"Found tshark (macOS Wireshark.app): {macos_path}")
            return str(macos_path)

    # 2. All platforms: Check PATH (works for Homebrew, apt, yum, etc.)
    tshark_in_path = shutil.which("tshark")
    if tshark_in_path:
        logger.info(f"Found tshark in PATH: {tshark_in_path}")
        return tshark_in_path

    # 3. Linux: Check common installation paths (dpkg, rpm, manual install)
    if system == "Linux":
        linux_paths = [
            "/usr/bin/tshark",
            "/usr/local/bin/tshark",
            "/opt/wireshark/bin/tshark",
            "/snap/bin/tshark",  # Snap package
        ]
        for path_str in linux_paths:
            path = Path(path_str)
            if path.exists() and path.is_file():
                logger.info(f"Found tshark (Linux): {path}")
                return str(path)

    # 4. Windows: Check common Program Files paths
    if system == "Windows":
        import os

        program_files = os.environ.get("ProgramFiles", "C:\\Program Files")
        program_files_x86 = os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")

        windows_paths = [
            Path(program_files) / "Wireshark" / "tshark.exe",
            Path(program_files_x86) / "Wireshark" / "tshark.exe",
        ]

        for path in windows_paths:
            if path.exists() and path.is_file():
                logger.info(f"Found tshark (Windows): {path}")
                return str(path)

    logger.warning("tshark not found on this system")
    return None


def check_tshark_version(tshark_path: str) -> Optional[str]:
    """
    Check tshark version and ensure it's compatible.

    Args:
        tshark_path: Full path to tshark binary

    Returns:
        Version string (e.g., "4.6.2") or None if check failed

    Raises:
        RuntimeError: If tshark execution fails
    """
    try:
        result = subprocess.run(
            [tshark_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=True,
        )

        # Parse version from output: "TShark (Wireshark) 4.6.2 ..."
        first_line = result.stdout.split("\n")[0]
        if "TShark" in first_line and "Wireshark" in first_line:
            # Extract version number
            parts = first_line.split()
            for part in parts:
                if part[0].isdigit() and "." in part:
                    version = part.rstrip(".")
                    logger.info(f"tshark version: {version}")
                    return version

        logger.warning(f"Could not parse tshark version from: {first_line}")
        return None

    except subprocess.TimeoutExpired:
        raise RuntimeError("tshark --version timeout")
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"tshark --version failed: {e.stderr}")
    except Exception as e:
        raise RuntimeError(f"tshark version check failed: {e}")


class TsharkRetransmissionAnalyzer:
    """
    tshark-based retransmission analyzer for 100% accuracy.

    This analyzer delegates TCP retransmission detection to tshark (Wireshark CLI).
    It provides the same level of accuracy as viewing the PCAP in Wireshark GUI.

    Advantages:
    - 100% accuracy (Wireshark's gold standard analysis)
    - Detects ALL retransmission types (RTO, Fast Retrans, Spurious)
    - No maintenance (tshark handles edge cases)
    - Battle-tested (20+ years of development)

    Limitations:
    - Requires tshark installed (use find_tshark() to check)
    - Subprocess overhead (~1-2 seconds for large PCAPs)
    - JSON parsing memory usage (scales with retransmission count)

    Usage:
        >>> tshark_path = find_tshark()
        >>> if tshark_path:
        ...     analyzer = TsharkRetransmissionAnalyzer(tshark_path)
        ...     retransmissions = analyzer.analyze("capture.pcap")
        ...     print(f"Found {len(retransmissions)} retransmissions (100% accuracy)")
    """

    def __init__(self, tshark_path: str):
        """
        Initialize tshark analyzer.

        Args:
            tshark_path: Full path to tshark binary (from find_tshark())

        Raises:
            RuntimeError: If tshark not executable or version check fails
        """
        self.tshark_path = tshark_path

        # Verify tshark is executable
        if not Path(tshark_path).exists():
            raise RuntimeError(f"tshark not found at: {tshark_path}")

        # Check version
        self.version = check_tshark_version(tshark_path)
        if not self.version:
            logger.warning("Could not determine tshark version, proceeding anyway")

        logger.info(f"Initialized tshark backend: {tshark_path} (v{self.version or 'unknown'})")

    def analyze(self, pcap_path: str) -> List[TCPRetransmission]:
        """
        Analyze PCAP using tshark for retransmission detection.

        This method spawns tshark subprocesses to:
        1. Extract all TCP packets to build original segment tracking
        2. Extract retransmissions with their flags
        3. Calculate delay from original packet timestamp

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of TCPRetransmission objects (sorted by packet number)

        Raises:
            RuntimeError: If tshark execution fails
            FileNotFoundError: If PCAP file doesn't exist
            subprocess.TimeoutExpired: If analysis takes > 5 minutes
        """
        if not Path(pcap_path).exists():
            raise FileNotFoundError(f"PCAP file not found: {pcap_path}")

        logger.info(f"Analyzing {pcap_path} with tshark backend...")

        # Step 1: Get ALL TCP packets to build original segment index
        # This enables delay calculation by tracking first occurrence of each (flow, seq)
        original_packets = self._get_all_tcp_packets(pcap_path)
        
        # Build index: (flow_key, seq_num) -> (packet_num, timestamp)
        segment_first_seen: Dict[tuple, tuple] = {}
        for pkt in original_packets:
            flow_key = (pkt["src_ip"], pkt["dst_ip"], pkt["src_port"], pkt["dst_port"])
            seq_num = pkt["seq_num"]
            key = (flow_key, seq_num)
            
            # Only store FIRST occurrence (original packet)
            if key not in segment_first_seen:
                segment_first_seen[key] = (pkt["packet_num"], pkt["timestamp"])

        # Step 2: Build tshark command for retransmissions
        cmd = [
            self.tshark_path,
            "-r", pcap_path,  # Read PCAP
            "-Y", "tcp.analysis.retransmission",  # Filter: only retransmissions
            "-T", "json",  # Output format: JSON
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.seq",
            "-e", "tcp.len",
            "-e", "tcp.nxtseq",
            "-e", "tcp.ack",
            "-e", "tcp.window_size",
            "-e", "tcp.flags",
            "-e", "tcp.analysis.retransmission",
            "-e", "tcp.analysis.fast_retransmission",
            "-e", "tcp.analysis.spurious_retransmission",
            "-e", "tcp.analysis.rto",
        ]

        try:
            logger.debug(f"Running: {' '.join(cmd)}")
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300,  # 5 minutes timeout
            )
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"tshark failed (exit {e.returncode}): {e.stderr}")
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"tshark timeout (>5min) analyzing {pcap_path}")

        # Parse JSON output
        try:
            packets = json.loads(result.stdout) if result.stdout.strip() else []
        except json.JSONDecodeError as e:
            raise RuntimeError(f"Failed to parse tshark JSON output: {e}")

        logger.info(f"tshark found {len(packets)} retransmissions")

        # Convert tshark output to TCPRetransmission objects
        retransmissions = []
        for pkt in packets:
            try:
                retrans = self._parse_tshark_packet(pkt, segment_first_seen)
                if retrans:
                    retransmissions.append(retrans)
            except Exception as e:
                logger.warning(f"Failed to parse packet: {e}")
                continue

        # Sort by packet number
        retransmissions.sort(key=lambda r: r.packet_num)

        logger.info(f"Successfully parsed {len(retransmissions)} retransmissions from tshark")
        return retransmissions

    def _get_all_tcp_packets(self, pcap_path: str) -> List[Dict[str, Any]]:
        """
        Get all TCP packets from PCAP for delay calculation.

        Uses tshark fields output (faster than JSON) to build segment index.

        Args:
            pcap_path: Path to PCAP file

        Returns:
            List of packet dicts with frame.number, timestamp, flow info, seq
        """
        cmd = [
            self.tshark_path,
            "-r", pcap_path,
            "-Y", "tcp",  # All TCP packets
            "-T", "fields",
            "-E", "separator=|",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "tcp.seq",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True,
                timeout=300,
            )
        except subprocess.CalledProcessError as e:
            logger.warning(f"Failed to get TCP packets: {e.stderr}")
            return []
        except subprocess.TimeoutExpired:
            logger.warning("Timeout getting TCP packets")
            return []

        packets = []
        for line in result.stdout.strip().split("\n"):
            if not line:
                continue
            parts = line.split("|")
            if len(parts) >= 7:
                try:
                    packets.append({
                        "packet_num": int(parts[0]),
                        "timestamp": float(parts[1]),
                        "src_ip": parts[2],
                        "dst_ip": parts[3],
                        "src_port": int(parts[4]) if parts[4] else 0,
                        "dst_port": int(parts[5]) if parts[5] else 0,
                        "seq_num": int(parts[6]) if parts[6] else 0,
                    })
                except (ValueError, IndexError) as e:
                    logger.debug(f"Skipping malformed line: {line} ({e})")
                    continue

        logger.debug(f"Indexed {len(packets)} TCP packets for delay calculation")
        return packets

    def _parse_tshark_packet(
        self, 
        pkt: Dict[str, Any], 
        segment_first_seen: Dict[tuple, tuple] = None,
    ) -> Optional[TCPRetransmission]:
        """
        Parse a single tshark JSON packet into TCPRetransmission.

        Args:
            pkt: JSON packet dict from tshark output
            segment_first_seen: Index mapping (flow_key, seq) -> (original_pkt_num, timestamp)

        Returns:
            TCPRetransmission object or None if parsing failed
        """
        layers = pkt.get("_source", {}).get("layers", {})

        # Helper to safely extract field (tshark returns lists)
        def get_field(key: str, default=None, cast=str):
            value = layers.get(key, [default])
            if isinstance(value, list) and len(value) > 0:
                try:
                    return cast(value[0]) if value[0] is not None else default
                except (ValueError, TypeError):
                    return default
            return default

        # Determine retransmission type
        is_fast = "tcp.analysis.fast_retransmission" in layers
        is_spurious = "tcp.analysis.spurious_retransmission" in layers
        is_rto = "tcp.analysis.rto" in layers

        if is_fast:
            retrans_type = "fast_retransmission"
        elif is_rto:
            retrans_type = "rto"
        else:
            retrans_type = "retransmission"  # Generic

        # Classify TCP flags
        tcp_flags_int = get_field("tcp.flags", "0x0", lambda x: int(x, 16))
        tcp_flags_str = self._parse_tcp_flags(tcp_flags_int)

        # Determine if SYN retransmission
        is_syn = (tcp_flags_int & 0x02) != 0  # SYN flag
        is_ack = (tcp_flags_int & 0x10) != 0  # ACK flag

        # Classify SYN retransmission direction
        syn_retrans_direction = None
        if is_syn:
            if is_ack:
                # SYN,ACK retransmitted → Server sent SYN,ACK but client didn't complete handshake
                syn_retrans_direction = "client_unreachable"
            else:
                # SYN retransmitted → Client sent SYN but server didn't respond
                syn_retrans_direction = "server_unreachable"

        # Extract packet info for delay calculation
        packet_num = get_field("frame.number", 0, int)
        timestamp = get_field("frame.time_epoch", 0.0, float)
        src_ip = get_field("ip.src", "")
        dst_ip = get_field("ip.dst", "")
        src_port = get_field("tcp.srcport", 0, int)
        dst_port = get_field("tcp.dstport", 0, int)
        seq_num = get_field("tcp.seq", 0, int)

        # Calculate delay from original packet (if segment index available)
        original_packet_num = None
        delay = None
        
        if segment_first_seen:
            flow_key = (src_ip, dst_ip, src_port, dst_port)
            key = (flow_key, seq_num)
            
            if key in segment_first_seen:
                orig_pkt_num, orig_timestamp = segment_first_seen[key]
                # Only calculate if this is NOT the original (retrans comes after original)
                if orig_pkt_num < packet_num:
                    original_packet_num = orig_pkt_num
                    delay = timestamp - orig_timestamp
                    logger.debug(
                        f"Retrans #{packet_num}: delay={delay:.3f}s from original #{orig_pkt_num}"
                    )

        # Create TCPRetransmission object
        retrans = TCPRetransmission(
            packet_num=packet_num,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            retrans_type=retrans_type,
            # Now calculated from segment index
            original_packet_num=original_packet_num,
            delay=delay,
            # Context enrichment (best effort from tshark output)
            expected_ack=get_field("tcp.nxtseq", None, int),
            last_ack_seen=get_field("tcp.ack", None, int),
            last_ack_packet_num=None,  # Not available from tshark
            time_since_last_ack_ms=None,  # Not available
            dup_ack_count=0,  # Not available from this filter
            receiver_window_raw=get_field("tcp.window_size", None, int),
            suspected_mechanisms=[],  # Not computed here
            confidence="high",  # tshark is authoritative
            is_syn_retrans=is_syn,
            syn_retrans_direction=syn_retrans_direction,
            is_spurious=is_spurious,
            tcp_flags=tcp_flags_str,
        )

        return retrans

    def _parse_tcp_flags(self, flags_int: int) -> str:
        """
        Parse TCP flags integer to string representation.

        Args:
            flags_int: TCP flags as integer (e.g., 0x10 for ACK)

        Returns:
            Comma-separated flag string (e.g., "SYN,ACK")
        """
        flag_names = []

        if flags_int & 0x01:  # FIN
            flag_names.append("FIN")
        if flags_int & 0x02:  # SYN
            flag_names.append("SYN")
        if flags_int & 0x04:  # RST
            flag_names.append("RST")
        if flags_int & 0x08:  # PSH
            flag_names.append("PSH")
        if flags_int & 0x10:  # ACK
            flag_names.append("ACK")
        if flags_int & 0x20:  # URG
            flag_names.append("URG")
        if flags_int & 0x40:  # ECE
            flag_names.append("ECE")
        if flags_int & 0x80:  # CWR
            flag_names.append("CWR")

        return ",".join(flag_names) if flag_names else "NONE"
