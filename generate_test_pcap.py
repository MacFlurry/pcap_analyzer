#!/usr/bin/env python3
"""
Generate a valid minimal PCAP file for testing upload functionality.

Creates: /tmp/test_upload.pcap
"""

import struct
import sys

def create_test_pcap(output_path='/tmp/test_upload.pcap'):
    """Create a minimal valid PCAP file with one packet."""

    # PCAP Global Header (24 bytes)
    magic = struct.pack('I', 0xa1b2c3d4)  # Magic number (little-endian)
    version_major = struct.pack('H', 2)    # Version major
    version_minor = struct.pack('H', 4)    # Version minor
    thiszone = struct.pack('i', 0)         # GMT to local correction
    sigfigs = struct.pack('I', 0)          # Accuracy of timestamps
    snaplen = struct.pack('I', 65535)      # Max length of captured packets
    network = struct.pack('I', 1)          # Data link type (1 = Ethernet)

    global_header = (magic + version_major + version_minor +
                    thiszone + sigfigs + snaplen + network)

    # Packet Record (minimal Ethernet frame)
    # Packet Header (16 bytes)
    ts_sec = struct.pack('I', 1700000000)   # Timestamp seconds
    ts_usec = struct.pack('I', 0)           # Timestamp microseconds
    incl_len = struct.pack('I', 60)         # Number of octets saved
    orig_len = struct.pack('I', 60)         # Actual length of packet

    # Packet Data (60 bytes - minimal Ethernet frame)
    # Ethernet: dst MAC (6) + src MAC (6) + type (2) + padding (46)
    dst_mac = b'\xff\xff\xff\xff\xff\xff'  # Broadcast
    src_mac = b'\x00\x11\x22\x33\x44\x55'  # Source
    eth_type = struct.pack('!H', 0x0800)   # IPv4
    padding = b'\x00' * 46                 # Padding to 60 bytes

    packet_data = dst_mac + src_mac + eth_type + padding
    packet = ts_sec + ts_usec + incl_len + orig_len + packet_data

    # Write to file
    with open(output_path, 'wb') as f:
        f.write(global_header + packet)

    print(f"✅ PCAP file created: {output_path}")
    print(f"   Size: {len(global_header + packet)} bytes")
    print(f"   Magic: 0xa1b2c3d4 (little-endian)")
    print(f"   Packets: 1")
    print(f"\n📤 Ready for upload testing!")

    return output_path


if __name__ == '__main__':
    output = sys.argv[1] if len(sys.argv) > 1 else '/tmp/test_upload.pcap'
    create_test_pcap(output)
