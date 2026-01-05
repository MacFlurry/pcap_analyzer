"""
Unit tests for DNSAnalyzer.
"""

import pytest
from scapy.all import DNS, DNSQR, DNSRR, IP, UDP, Ether
from src.analyzers.dns_analyzer import DNSAnalyzer

@pytest.fixture
def analyzer():
    return DNSAnalyzer()

def create_dns_query(query_id, qname, timestamp=100.0):
    packet = Ether()/IP(src="1.1.1.1", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(id=query_id, qr=0, qd=DNSQR(qname=qname))
    packet.time = timestamp
    return packet

def create_dns_response(query_id, qname, rcode=0, timestamp=100.1):
    packet = Ether()/IP(src="8.8.8.8", dst="1.1.1.1")/UDP(sport=53, dport=12345)/DNS(id=query_id, qr=1, qd=DNSQR(qname=qname), rcode=rcode)
    packet.time = timestamp
    return packet

class TestDNSAnalyzer:
    """Test suite for DNSAnalyzer."""

    def test_dns_success_transaction(self, analyzer):
        """Test a successful DNS query and response."""
        q = create_dns_query(0x1234, "www.google.com")
        r = create_dns_response(0x1234, "www.google.com")
        
        analyzer.process_packet(q, 1)
        analyzer.process_packet(r, 2)
        
        results = analyzer.finalize()
        assert results["total_queries"] == 1
        assert results["total_responses"] == 1
        assert results["successful_transactions"] == 1
        assert results["transactions"][0]["status"] == "success"

    def test_dns_timeout(self, analyzer):
        """Test a DNS query that times out."""
        q = create_dns_query(0xabcd, "timeout.com", timestamp=100.0)
        analyzer.process_packet(q, 1)
        
        # We need a later packet to advance last_packet_time beyond the timeout threshold
        q2 = create_dns_query(0xeeee, "other.com", timestamp=110.0)
        analyzer.process_packet(q2, 2)
        
        results = analyzer.finalize()
        assert results["timeout_transactions"] == 1
        assert results["transactions"][0]["timed_out"] is True

    def test_dns_error_nxdomain(self, analyzer):
        """Test DNS error response (NXDOMAIN)."""
        q = create_dns_query(0x5555, "nonexistent.example", timestamp=100.0)
        r = create_dns_response(0x5555, "nonexistent.example", rcode=3, timestamp=100.1) # NXDOMAIN
        
        analyzer.process_packet(q, 1)
        analyzer.process_packet(r, 2)
        
        results = analyzer.finalize()
        assert results["error_transactions"] == 1
        assert results["real_errors"] == 1
        assert results["transactions"][0]["status"] == "error"

    def test_malformed_dns_packet_empty_qd(self, analyzer):
        """Test handling of DNS packet with empty question section."""
        # Force empty qd
        packet = Ether()/IP(src="1.1.1.1", dst="8.8.8.8")/UDP(sport=12345, dport=53)/DNS(id=0x9999, qr=0, qd=[])
        packet.time = 100.0
        
        analyzer.process_packet(packet, 1)
        
        results = analyzer.finalize()
        assert results["total_queries"] == 0

    def test_k8s_domain_ignored(self, analyzer):
        """Test that Kubernetes internal domains are identified as expected errors."""
        analyzer.ignore_k8s_domains = True
        q = create_dns_query(0x1111, "myservice.namespace.svc.cluster.local", timestamp=100.0)
        r = create_dns_response(0x1111, "myservice.namespace.svc.cluster.local", rcode=3, timestamp=100.1)
        
        analyzer.process_packet(q, 1)
        analyzer.process_packet(r, 2)
        
        results = analyzer.finalize()
        assert results["error_transactions"] == 1
        assert results["k8s_expected_errors"] == 1
        assert results["real_errors"] == 0