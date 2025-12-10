#!/usr/bin/env python3
"""
Simulated Network Attacks for Testing Security Detectors

Generates controlled attack traffic patterns for validation:
1. Port scanning (horizontal, vertical, distributed)
2. SSH brute-force attempts
3. Service enumeration

WARNING: Use only on authorized systems for testing purposes!
"""

import socket
import sys
import time
from datetime import datetime


def print_header(msg):
    """Print formatted header"""
    print("\n" + "=" * 60)
    print(f"  {msg}")
    print("=" * 60 + "\n")


def port_scan_horizontal(target_ip, ports, delay=0.1):
    """
    Simulate horizontal port scan (many ports, one target)

    Args:
        target_ip: Target IP address
        ports: List of ports to scan
        delay: Delay between attempts in seconds
    """
    print_header(f"HORIZONTAL PORT SCAN: {target_ip}")
    print(f"Scanning {len(ports)} ports on {target_ip}")
    print(f"Delay: {delay}s between attempts")
    print(f"Start time: {datetime.now()}\n")

    results = {"open": [], "closed": [], "filtered": []}

    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"  ✓ Port {port} OPEN")
                results["open"].append(port)
            else:
                print(f"  ✗ Port {port} CLOSED")
                results["closed"].append(port)
        except socket.timeout:
            print(f"  ? Port {port} FILTERED (timeout)")
            results["filtered"].append(port)
        except Exception as e:
            print(f"  ! Port {port} ERROR: {e}")
        finally:
            sock.close()
            time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {len(results['open'])} open, {len(results['closed'])} closed, {len(results['filtered'])} filtered")
    return results


def port_scan_vertical(target_ips, port, delay=0.1):
    """
    Simulate vertical port scan (one port, many targets)

    Args:
        target_ips: List of target IP addresses
        port: Port to scan
        delay: Delay between attempts
    """
    print_header(f"VERTICAL PORT SCAN: Port {port}")
    print(f"Scanning {len(target_ips)} targets on port {port}")
    print(f"Delay: {delay}s between attempts")
    print(f"Start time: {datetime.now()}\n")

    results = {"open": [], "closed": []}

    for ip in target_ips:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((ip, port))
            if result == 0:
                print(f"  ✓ {ip}:{port} OPEN")
                results["open"].append(ip)
            else:
                print(f"  ✗ {ip}:{port} CLOSED")
                results["closed"].append(ip)
        except Exception as e:
            print(f"  ! {ip}:{port} ERROR: {e}")
        finally:
            sock.close()
            time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {len(results['open'])} open, {len(results['closed'])} closed")
    return results


def ssh_brute_force_simulation(target_ip, port=22, attempts=20, delay=0.5):
    """
    Simulate SSH brute-force attack (connection attempts only, no auth)

    Args:
        target_ip: Target IP address
        port: SSH port (default 22)
        attempts: Number of connection attempts
        delay: Delay between attempts
    """
    print_header(f"SSH BRUTE-FORCE SIMULATION: {target_ip}:{port}")
    print(f"Attempts: {attempts}")
    print(f"Delay: {delay}s between attempts")
    print(f"Start time: {datetime.now()}\n")

    successful = 0
    failed = 0

    for i in range(1, attempts + 1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)

        try:
            # Just connect and disconnect (no actual authentication)
            sock.connect((target_ip, port))
            print(f"  [{i:2d}/{attempts}] Connection established to {target_ip}:{port}")
            successful += 1
            sock.close()
        except socket.timeout:
            print(f"  [{i:2d}/{attempts}] Connection timeout")
            failed += 1
        except ConnectionRefusedError:
            print(f"  [{i:2d}/{attempts}] Connection refused")
            failed += 1
        except Exception as e:
            print(f"  [{i:2d}/{attempts}] Error: {e}")
            failed += 1
        finally:
            time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} connected, {failed} failed")
    return {"successful": successful, "failed": failed}


def service_enumeration(target_ip, services, delay=0.2):
    """
    Simulate service enumeration (common auth services)

    Args:
        target_ip: Target IP
        services: Dict of {port: service_name}
        delay: Delay between probes
    """
    print_header(f"SERVICE ENUMERATION: {target_ip}")
    print(f"Probing {len(services)} services")
    print(f"Start time: {datetime.now()}\n")

    results = {}

    for port, service in services.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        try:
            result = sock.connect_ex((target_ip, port))
            if result == 0:
                print(f"  ✓ {service:15s} (port {port:5d}) - OPEN")
                results[service] = "open"
            else:
                print(f"  ✗ {service:15s} (port {port:5d}) - CLOSED")
                results[service] = "closed"
        except Exception as e:
            print(f"  ! {service:15s} (port {port:5d}) - ERROR: {e}")
            results[service] = "error"
        finally:
            sock.close()
            time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    return results


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  NETWORK ATTACK SIMULATION TOOL")
    print("  For Testing Security Detectors Only")
    print("=" * 60)

    if len(sys.argv) < 2:
        print("\nUsage:")
        print(f"  {sys.argv[0]} <target_ip>")
        print("\nExample:")
        print(f"  {sys.argv[0]} 192.168.25.1")
        print("\nThis will run all attack simulations:")
        print("  1. Horizontal port scan (20 common ports)")
        print("  2. Vertical scan (5 IPs, port 22)")
        print("  3. SSH brute-force (20 attempts)")
        print("  4. Service enumeration (auth services)")
        sys.exit(1)

    target = sys.argv[1]

    print(f"\n🎯 Target: {target}")
    print(f"⚠️  WARNING: Only use on authorized systems!")
    print(f"📝 This generates attack patterns for detection testing.\n")

    input("Press ENTER to continue or Ctrl+C to cancel...")

    # Scenario 1: Horizontal port scan (common ports)
    common_ports = [
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        80,  # HTTP
        110,  # POP3
        143,  # IMAP
        443,  # HTTPS
        445,  # SMB
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        5900,  # VNC
        6379,  # Redis
        8080,  # HTTP-Alt
        8443,  # HTTPS-Alt
        27017,  # MongoDB
    ]

    port_scan_horizontal(target, common_ports, delay=0.05)
    time.sleep(2)

    # Scenario 2: Vertical scan (sweep network for SSH)
    base_ip = ".".join(target.split(".")[:-1])  # Get network prefix
    target_ips = [f"{base_ip}.{i}" for i in [1, 15, 67, 100, 178]]
    port_scan_vertical(target_ips, 22, delay=0.1)
    time.sleep(2)

    # Scenario 3: SSH brute-force simulation
    ssh_brute_force_simulation(target, port=22, attempts=15, delay=0.3)
    time.sleep(2)

    # Scenario 4: Service enumeration
    auth_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        6379: "Redis",
        27017: "MongoDB",
    }

    service_enumeration(target, auth_services, delay=0.1)

    print_header("ATTACK SIMULATION COMPLETE")
    print("✅ All scenarios executed")
    print("📦 Capture the traffic with tcpdump and analyze with pcap_analyzer")
    print("🔍 Expected detections:")
    print("   - 1-2 Horizontal port scans (18 ports)")
    print("   - 1 Vertical scan (5 IPs)")
    print("   - 1 SSH brute-force attack (15 attempts)")
    print("   - 1 Service enumeration pattern\n")
