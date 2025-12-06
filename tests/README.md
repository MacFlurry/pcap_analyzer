# PCAP Analyzer Test Suite

This directory contains the test suite for the PCAP Analyzer project.

## Test Structure

```
tests/
├── conftest.py           # Shared fixtures and test configuration
├── test_tcp_handshake.py # Unit tests for TCP handshake analyzer
├── test_utils.py         # Unit tests for utility functions
├── test_integration.py   # Integration tests
└── README.md            # This file
```

## Running Tests

### Run all tests
```bash
pytest
```

### Run with verbose output
```bash
pytest -v
```

### Run specific test file
```bash
pytest tests/test_tcp_handshake.py
```

### Run specific test
```bash
pytest tests/test_tcp_handshake.py::TestTCPHandshakeAnalyzer::test_complete_handshake
```

### Run with coverage
```bash
pytest --cov=src --cov-report=html
```

### Run only unit tests
```bash
pytest -m unit
```

### Run only integration tests
```bash
pytest -m integration
```

### Run tests in parallel
```bash
pytest -n auto
```

## Test Markers

Tests are marked with the following markers:

- `@pytest.mark.unit` - Unit tests for individual components
- `@pytest.mark.integration` - Integration tests across components
- `@pytest.mark.slow` - Tests that take a long time to run
- `@pytest.mark.network` - Tests requiring network access
- `@pytest.mark.requires_pcap` - Tests requiring sample PCAP files

## Writing Tests

### Example Unit Test

```python
import pytest
from src.analyzers.tcp_handshake import TCPHandshakeAnalyzer

class TestTCPHandshakeAnalyzer:
    def test_initialization(self):
        analyzer = TCPHandshakeAnalyzer()
        assert analyzer.handshakes == []
```

### Example Integration Test

```python
@pytest.mark.integration
def test_multiple_analyzers(tcp_connection_packets):
    handshake_analyzer = TCPHandshakeAnalyzer()
    retrans_analyzer = RetransmissionAnalyzer()

    h_results = handshake_analyzer.analyze(tcp_connection_packets)
    r_results = retrans_analyzer.analyze(tcp_connection_packets)

    assert h_results['total_handshakes'] >= 1
```

## Fixtures

Common fixtures are defined in `conftest.py`:

- `sample_tcp_packet` - Basic TCP packet
- `sample_tcp_syn_packet` - TCP SYN packet
- `sample_tcp_synack_packet` - TCP SYN-ACK packet
- `sample_tcp_ack_packet` - TCP ACK packet
- `sample_tcp_data_packet` - TCP packet with data
- `sample_tcp_fin_packet` - TCP FIN packet
- `sample_tcp_rst_packet` - TCP RST packet
- `sample_udp_packet` - UDP packet
- `sample_dns_query` - DNS query packet
- `sample_dns_response` - DNS response packet
- `sample_icmp_packet` - ICMP packet
- `sample_ipv6_packet` - IPv6 packet
- `tcp_handshake_packets` - Complete TCP handshake sequence
- `tcp_connection_packets` - Complete TCP connection
- `retransmission_packets` - Packets with retransmission

## Coverage Goals

Target: **>80% code coverage**

Check current coverage:
```bash
pytest --cov=src --cov-report=term-missing
```

View HTML coverage report:
```bash
pytest --cov=src --cov-report=html
open htmlcov/index.html
```

## CI/CD

Tests run automatically on:
- Push to `main` or `comprehensive-code-review` branches
- Pull requests to `main`

GitHub Actions workflow: `.github/workflows/test.yml`

## Adding New Tests

1. Create test file with `test_` prefix
2. Create test class with `Test` prefix
3. Create test methods with `test_` prefix
4. Use fixtures from `conftest.py`
5. Add appropriate markers
6. Run tests locally before committing

## Test Best Practices

- **One assertion per test** (when possible)
- **Descriptive test names** (test_should_do_something_when_condition)
- **Arrange-Act-Assert** pattern
- **Use fixtures** for common setup
- **Test edge cases** and error conditions
- **Keep tests fast** (use mocks for external dependencies)
- **Test behavior, not implementation**
