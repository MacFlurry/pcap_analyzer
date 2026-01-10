#!/usr/bin/env python3
"""
Generate PCAP files with controlled TCP retransmissions for testing.

This script creates PCAPs with:
1. SYN retransmissions (simulating connection issues)
2. PSH,ACK retransmissions (simulating data transfer issues)

The retransmission timings are precisely controlled to validate
that pcap_analyzer reports correct delay values.

Usage:
    python3 generate_retransmission_pcap.py --type syn --output syn_retrans.pcap
    python3 generate_retransmission_pcap.py --type psh_ack --output psh_retrans.pcap
    python3 generate_retransmission_pcap.py --type both --output combined_retrans.pcap
"""

import argparse
import struct
import time
from dataclasses import dataclass
from typing import List, Tuple


@dataclass
class RetransmissionConfig:
    """Configuration for retransmission timing."""
    
    # SYN retransmission delays (seconds from original)
    syn_delays: Tuple[float, ...] = (1.0, 2.0)  # Total ~3s with 2 retrans
    
    # PSH,ACK retransmission delays (seconds from original)
    psh_ack_delays: Tuple[float, ...] = (0.2, 0.4, 0.8)  # Exponential backoff style


class PcapWriter:
    """Low-level PCAP file writer."""
    
    PCAP_MAGIC = 0xa1b2c3d4
    PCAP_VERSION_MAJOR = 2
    PCAP_VERSION_MINOR = 4
    LINKTYPE_ETHERNET = 1
    
    def __init__(self, filename: str):
        self.filename = filename
        self.packets: List[Tuple[float, bytes]] = []
    
    def add_packet(self, timestamp: float, data: bytes) -> None:
        """Add a packet with its timestamp."""
        self.packets.append((timestamp, data))
    
    def write(self) -> None:
        """Write the PCAP file."""
        with open(self.filename, 'wb') as f:
            # Global header (24 bytes)
            f.write(struct.pack('<I', self.PCAP_MAGIC))
            f.write(struct.pack('<H', self.PCAP_VERSION_MAJOR))
            f.write(struct.pack('<H', self.PCAP_VERSION_MINOR))
            f.write(struct.pack('<i', 0))  # thiszone
            f.write(struct.pack('<I', 0))  # sigfigs
            f.write(struct.pack('<I', 65535))  # snaplen
            f.write(struct.pack('<I', self.LINKTYPE_ETHERNET))
            
            # Write packets
            for timestamp, data in sorted(self.packets, key=lambda x: x[0]):
                ts_sec = int(timestamp)
                ts_usec = int((timestamp - ts_sec) * 1_000_000)
                
                f.write(struct.pack('<I', ts_sec))
                f.write(struct.pack('<I', ts_usec))
                f.write(struct.pack('<I', len(data)))
                f.write(struct.pack('<I', len(data)))
                f.write(data)


class TcpPacketBuilder:
    """Build TCP/IP packets with Ethernet framing."""
    
    # TCP Flags
    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    PSH = 0x08
    ACK = 0x10
    URG = 0x20
    
    def __init__(
        self,
        src_mac: bytes = b'\x00\x11\x22\x33\x44\x55',
        dst_mac: bytes = b'\x66\x77\x88\x99\xaa\xbb',
        src_ip: str = '192.168.1.100',
        dst_ip: str = '192.168.1.1',
        src_port: int = 54321,
        dst_port: int = 80,
    ):
        self.src_mac = src_mac
        self.dst_mac = dst_mac
        self.src_ip = self._ip_to_bytes(src_ip)
        self.dst_ip = self._ip_to_bytes(dst_ip)
        self.src_port = src_port
        self.dst_port = dst_port
    
    @staticmethod
    def _ip_to_bytes(ip: str) -> bytes:
        """Convert dotted IP string to bytes."""
        return bytes(int(octet) for octet in ip.split('.'))
    
    @staticmethod
    def _checksum(data: bytes) -> int:
        """Calculate IP/TCP checksum."""
        if len(data) % 2:
            data += b'\x00'
        
        total = 0
        for i in range(0, len(data), 2):
            total += (data[i] << 8) + data[i + 1]
        
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ~total & 0xffff
    
    def build_packet(
        self,
        seq: int,
        ack: int,
        flags: int,
        payload: bytes = b'',
        window: int = 65535,
    ) -> bytes:
        """Build a complete Ethernet/IP/TCP packet."""
        
        # TCP Header (20 bytes without options)
        tcp_header_len = 20
        data_offset = (tcp_header_len // 4) << 4
        
        tcp_header = struct.pack(
            '!HHIIBBHHH',
            self.src_port,
            self.dst_port,
            seq,
            ack,
            data_offset,
            flags,
            window,
            0,  # checksum placeholder
            0,  # urgent pointer
        )
        
        # TCP pseudo-header for checksum
        tcp_length = tcp_header_len + len(payload)
        pseudo_header = (
            self.src_ip +
            self.dst_ip +
            struct.pack('!BBH', 0, 6, tcp_length)
        )
        
        tcp_checksum = self._checksum(pseudo_header + tcp_header + payload)
        tcp_header = tcp_header[:16] + struct.pack('!H', tcp_checksum) + tcp_header[18:]
        
        # IP Header (20 bytes)
        ip_total_len = 20 + tcp_length
        ip_header = struct.pack(
            '!BBHHHBBH',
            0x45,  # version + IHL
            0,     # DSCP + ECN
            ip_total_len,
            54321, # identification
            0x4000,  # flags + fragment offset (Don't Fragment)
            64,    # TTL
            6,     # protocol (TCP)
            0,     # checksum placeholder
        ) + self.src_ip + self.dst_ip
        
        ip_checksum = self._checksum(ip_header)
        ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
        
        # Ethernet Header (14 bytes)
        eth_header = self.dst_mac + self.src_mac + struct.pack('!H', 0x0800)
        
        return eth_header + ip_header + tcp_header + payload


def generate_syn_retransmissions(
    writer: PcapWriter,
    config: RetransmissionConfig,
    base_time: float,
) -> float:
    """
    Generate SYN packets with retransmissions.
    
    Simulates a client trying to connect but not receiving SYN-ACK.
    
    Returns: The timestamp after the last packet.
    """
    builder = TcpPacketBuilder(
        src_ip='192.168.1.100',
        dst_ip='10.0.0.1',
        src_port=54321,
        dst_port=443,
    )
    
    seq = 1000000
    current_time = base_time
    
    # Original SYN
    packet = builder.build_packet(
        seq=seq,
        ack=0,
        flags=TcpPacketBuilder.SYN,
    )
    writer.add_packet(current_time, packet)
    print(f"  [SYN] Original at t={current_time:.3f}s, seq={seq}")
    
    # SYN Retransmissions
    for i, delay in enumerate(config.syn_delays, 1):
        current_time = base_time + delay
        packet = builder.build_packet(
            seq=seq,  # Same seq = retransmission
            ack=0,
            flags=TcpPacketBuilder.SYN,
        )
        writer.add_packet(current_time, packet)
        print(f"  [SYN] Retransmit #{i} at t={current_time:.3f}s (delay={delay:.3f}s)")
    
    return current_time + 0.5


def generate_psh_ack_retransmissions(
    writer: PcapWriter,
    config: RetransmissionConfig,
    base_time: float,
) -> float:
    """
    Generate a complete TCP session with PSH,ACK retransmissions.
    
    Simulates:
    1. Successful 3-way handshake
    2. Data transfer with retransmissions
    3. Connection close
    
    Returns: The timestamp after the last packet.
    """
    client = TcpPacketBuilder(
        src_ip='192.168.1.100',
        dst_ip='10.0.0.2',
        src_port=54322,
        dst_port=80,
    )
    
    server = TcpPacketBuilder(
        src_mac=client.dst_mac,
        dst_mac=client.src_mac,
        src_ip='10.0.0.2',
        dst_ip='192.168.1.100',
        src_port=80,
        dst_port=54322,
    )
    
    client_seq = 2000000
    server_seq = 3000000
    current_time = base_time
    
    # === 3-Way Handshake ===
    print("  [Handshake] Starting...")
    
    # Client SYN
    packet = client.build_packet(seq=client_seq, ack=0, flags=TcpPacketBuilder.SYN)
    writer.add_packet(current_time, packet)
    client_seq += 1
    current_time += 0.001
    
    # Server SYN-ACK
    packet = server.build_packet(
        seq=server_seq,
        ack=client_seq,
        flags=TcpPacketBuilder.SYN | TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    server_seq += 1
    current_time += 0.001
    
    # Client ACK
    packet = client.build_packet(
        seq=client_seq,
        ack=server_seq,
        flags=TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    current_time += 0.010
    print("  [Handshake] Complete")
    
    # === Data Transfer with Retransmissions ===
    payload = b'GET /test HTTP/1.1\r\nHost: example.com\r\n\r\n'
    data_start_time = current_time
    
    # Original PSH,ACK with data
    packet = client.build_packet(
        seq=client_seq,
        ack=server_seq,
        flags=TcpPacketBuilder.PSH | TcpPacketBuilder.ACK,
        payload=payload,
    )
    writer.add_packet(current_time, packet)
    print(f"  [PSH,ACK] Original at t={current_time:.3f}s, seq={client_seq}, len={len(payload)}")
    
    # PSH,ACK Retransmissions (server doesn't ACK)
    for i, delay in enumerate(config.psh_ack_delays, 1):
        retrans_time = data_start_time + delay
        packet = client.build_packet(
            seq=client_seq,  # Same seq = retransmission
            ack=server_seq,
            flags=TcpPacketBuilder.PSH | TcpPacketBuilder.ACK,
            payload=payload,
        )
        writer.add_packet(retrans_time, packet)
        print(f"  [PSH,ACK] Retransmit #{i} at t={retrans_time:.3f}s (delay={delay:.3f}s)")
        current_time = retrans_time
    
    # Server finally ACKs
    current_time += 0.050
    client_seq += len(payload)
    packet = server.build_packet(
        seq=server_seq,
        ack=client_seq,
        flags=TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    print("  [ACK] Server acknowledges data")
    
    # === Connection Close ===
    current_time += 0.010
    
    # Client FIN
    packet = client.build_packet(
        seq=client_seq,
        ack=server_seq,
        flags=TcpPacketBuilder.FIN | TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    client_seq += 1
    current_time += 0.001
    
    # Server FIN-ACK
    packet = server.build_packet(
        seq=server_seq,
        ack=client_seq,
        flags=TcpPacketBuilder.FIN | TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    server_seq += 1
    current_time += 0.001
    
    # Client ACK
    packet = client.build_packet(
        seq=client_seq,
        ack=server_seq,
        flags=TcpPacketBuilder.ACK,
    )
    writer.add_packet(current_time, packet)
    print("  [Close] Connection closed")
    
    return current_time + 0.5


def main():
    parser = argparse.ArgumentParser(
        description='Generate PCAP files with controlled TCP retransmissions',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        '--type',
        choices=['syn', 'psh_ack', 'both'],
        default='both',
        help='Type of retransmissions to generate (default: both)',
    )
    parser.add_argument(
        '--output', '-o',
        default='/tmp/retransmission_test.pcap',
        help='Output PCAP file path (default: /tmp/retransmission_test.pcap)',
    )
    parser.add_argument(
        '--syn-delays',
        type=str,
        default='1.0,2.0',
        help='Comma-separated SYN retransmission delays in seconds (default: 1.0,2.0)',
    )
    parser.add_argument(
        '--psh-delays',
        type=str,
        default='0.2,0.4,0.8',
        help='Comma-separated PSH,ACK retransmission delays in seconds (default: 0.2,0.4,0.8)',
    )
    
    args = parser.parse_args()
    
    # Parse delays
    syn_delays = tuple(float(d) for d in args.syn_delays.split(','))
    psh_delays = tuple(float(d) for d in args.psh_delays.split(','))
    
    config = RetransmissionConfig(
        syn_delays=syn_delays,
        psh_ack_delays=psh_delays,
    )
    
    writer = PcapWriter(args.output)
    base_time = time.time()
    
    print(f"\n🔧 Generating PCAP with retransmissions...")
    print(f"   Output: {args.output}")
    print(f"   Type: {args.type}")
    print()
    
    current_time = base_time
    
    if args.type in ('syn', 'both'):
        print("📡 Generating SYN retransmissions:")
        print(f"   Delays: {syn_delays}")
        current_time = generate_syn_retransmissions(writer, config, current_time)
        print()
    
    if args.type in ('psh_ack', 'both'):
        print("📡 Generating PSH,ACK retransmissions:")
        print(f"   Delays: {psh_delays}")
        current_time = generate_psh_ack_retransmissions(writer, config, current_time)
        print()
    
    writer.write()
    
    print(f"✅ PCAP written: {args.output}")
    print(f"   Packets: {len(writer.packets)}")
    print()
    print("📋 Expected retransmission timings:")
    if args.type in ('syn', 'both'):
        print(f"   SYN retransmissions: {len(syn_delays)} at delays {syn_delays}s")
    if args.type in ('psh_ack', 'both'):
        print(f"   PSH,ACK retransmissions: {len(psh_delays)} at delays {psh_delays}s")
    print()
    print("🧪 Validate with:")
    print(f"   tshark -r {args.output} -Y 'tcp.analysis.retransmission' -T fields -e frame.time_relative -e tcp.flags")


if __name__ == '__main__':
    main()
