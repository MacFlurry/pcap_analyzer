from scapy.all import Ether, IP, TCP, wrpcap
import time

def generate_invalid_pcap(output_path):
    # Packet 1: Today
    p1 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP()
    p1.time = time.time()
    
    # Packet 2: 2 years later
    p2 = Ether()/IP(src="1.1.1.1", dst="2.2.2.2")/TCP()
    p2.time = p1.time + (365 * 24 * 3600 * 2) # 2 years
    
    wrpcap(output_path, [p1, p2])
    print(f"Generated invalid PCAP at {output_path}")

if __name__ == "__main__":
    import os
    os.makedirs("tests/fixtures/invalid_pcaps", exist_ok=True)
    generate_invalid_pcap("tests/fixtures/invalid_pcaps/ultimate_pcap_sample.pcapng")
