"""
Security tests for file validation (CWE-22, CWE-434, CWE-770).

Tests:
- PCAP magic number validation (OWASP ASVS 5.2.2)
- File size pre-validation (NIST SC-5)
- Path traversal protection (CWE-22 Rank 6/2025)
"""

import os
import tempfile
from pathlib import Path

import pytest

from src.utils.file_validator import (
    validate_pcap_magic_number,
    validate_file_size,
    validate_file_path,
    FileValidationError,
)


class TestPCAPMagicNumberValidation:
    """Test PCAP file type validation (OWASP ASVS 5.2.2)."""

    def test_valid_pcap_big_endian(self, tmp_path):
        """Valid PCAP file (big-endian) passes validation."""
        pcap_file = tmp_path / "valid_big_endian.pcap"
        pcap_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 20)

        file_type = validate_pcap_magic_number(str(pcap_file))
        assert file_type == "pcap"

    def test_valid_pcap_little_endian(self, tmp_path):
        """Valid PCAP file (little-endian) passes validation."""
        pcap_file = tmp_path / "valid_little_endian.pcap"
        pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

        file_type = validate_pcap_magic_number(str(pcap_file))
        assert file_type == "pcap"

    def test_valid_pcap_nanosecond_precision(self, tmp_path):
        """Valid PCAP-NS file passes validation."""
        pcap_file = tmp_path / "valid_pcap_ns.pcap"
        pcap_file.write_bytes(b"\xa1\xb2\x3c\x4d" + b"\x00" * 20)

        file_type = validate_pcap_magic_number(str(pcap_file))
        assert file_type == "pcap-ns"

    def test_valid_pcapng(self, tmp_path):
        """Valid PCAP-NG file passes validation."""
        pcapng_file = tmp_path / "valid.pcapng"
        pcapng_file.write_bytes(b"\x0a\x0d\x0d\x0a" + b"\x00" * 20)

        file_type = validate_pcap_magic_number(str(pcapng_file))
        assert file_type == "pcapng"

    def test_invalid_magic_number(self, tmp_path):
        """File with invalid magic number is rejected (CWE-434)."""
        invalid_file = tmp_path / "invalid.pcap"
        invalid_file.write_bytes(b"\x12\x34\x56\x78" + b"\x00" * 20)

        with pytest.raises(ValueError, match="Invalid PCAP file.*magic number"):
            validate_pcap_magic_number(str(invalid_file))

    def test_text_file_rejected(self, tmp_path):
        """Text file masquerading as PCAP is rejected."""
        text_file = tmp_path / "fake.pcap"
        text_file.write_text("This is not a PCAP file")

        with pytest.raises(ValueError, match="Invalid PCAP file"):
            validate_pcap_magic_number(str(text_file))

    def test_empty_file_rejected(self, tmp_path):
        """Empty file is rejected."""
        empty_file = tmp_path / "empty.pcap"
        empty_file.write_bytes(b"")

        with pytest.raises(Exception):  # Could be ValueError or IOError
            validate_pcap_magic_number(str(empty_file))

    def test_truncated_file_rejected(self, tmp_path):
        """File with less than 4 bytes is rejected."""
        truncated_file = tmp_path / "truncated.pcap"
        truncated_file.write_bytes(b"\xa1\xb2")  # Only 2 bytes

        with pytest.raises(Exception):
            validate_pcap_magic_number(str(truncated_file))


class TestFileSizeValidation:
    """Test file size pre-validation (NIST SC-5, CWE-770)."""

    def test_normal_file_size_accepted(self, tmp_path):
        """File under size limit is accepted."""
        normal_file = tmp_path / "normal.pcap"
        normal_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 1024 * 1024)  # 1 MB

        # Should not raise exception
        validate_file_size(str(normal_file), max_size_bytes=10 * 1024 * 1024 * 1024)

    def test_oversized_file_rejected(self, tmp_path):
        """File exceeding size limit is rejected (CWE-770)."""
        # Create 11 MB file (exceeds 10 MB limit)
        large_file = tmp_path / "large.pcap"
        large_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * (11 * 1024 * 1024))

        with pytest.raises(FileValidationError, match="File size.*exceeds maximum"):
            validate_file_size(str(large_file), max_size_bytes=10 * 1024 * 1024)

    def test_exact_size_limit_accepted(self, tmp_path):
        """File exactly at size limit is accepted."""
        exact_file = tmp_path / "exact.pcap"
        size_limit = 5 * 1024 * 1024  # 5 MB
        exact_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * (size_limit - 4))

        # Should not raise exception
        validate_file_size(str(exact_file), max_size_bytes=size_limit)

    def test_default_size_limit_10gb(self, tmp_path):
        """Default size limit is 10 GB."""
        small_file = tmp_path / "small.pcap"
        small_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 1024)

        # Should use default 10 GB limit
        validate_file_size(str(small_file))

    def test_nonexistent_file_raises_error(self):
        """Non-existent file raises error."""
        with pytest.raises(FileNotFoundError):
            validate_file_size("/nonexistent/file.pcap")


class TestPathTraversalProtection:
    """Test path traversal protection (CWE-22 Rank 6/2025)."""

    def test_normal_path_accepted(self, tmp_path):
        """Normal file path is accepted."""
        normal_file = tmp_path / "normal.pcap"
        normal_file.touch()

        validated_path = validate_file_path(str(normal_file))
        assert Path(validated_path).resolve() == normal_file.resolve()

    def test_dotdot_traversal_rejected(self, tmp_path):
        """Path with .. (parent directory) is rejected (CWE-22)."""
        traversal_path = str(tmp_path / ".." / "etc" / "passwd")

        with pytest.raises(ValueError, match="Path traversal detected"):
            validate_file_path(traversal_path)

    def test_tilde_expansion_rejected(self, tmp_path):
        """Path with ~ (home directory) is rejected."""
        tilde_path = "~/secrets.pcap"

        with pytest.raises(ValueError, match="Path traversal detected"):
            validate_file_path(tilde_path)

    def test_absolute_path_outside_allowed_dirs_rejected(self, tmp_path):
        """Absolute path outside allowed directories is rejected."""
        allowed_dirs = [str(tmp_path)]
        outside_path = "/etc/passwd"

        with pytest.raises(ValueError, match="Access denied.*outside allowed directories"):
            validate_file_path(outside_path, allowed_dirs=allowed_dirs)

    def test_path_within_allowed_dir_accepted(self, tmp_path):
        """Path within allowed directory is accepted."""
        allowed_dirs = [str(tmp_path)]
        valid_file = tmp_path / "subdir" / "file.pcap"
        valid_file.parent.mkdir(parents=True, exist_ok=True)
        valid_file.touch()

        validated_path = validate_file_path(str(valid_file), allowed_dirs=allowed_dirs)
        assert Path(validated_path).resolve() == valid_file.resolve()

    def test_symlink_outside_allowed_dir_rejected(self, tmp_path):
        """Symbolic link pointing outside allowed directories is rejected."""
        allowed_dir = tmp_path / "allowed"
        allowed_dir.mkdir()
        outside_dir = tmp_path / "outside"
        outside_dir.mkdir()

        # Create symlink from allowed_dir to outside_dir
        symlink = allowed_dir / "link_to_outside"
        target = outside_dir / "secret.pcap"
        target.touch()

        try:
            symlink.symlink_to(target)
        except OSError:
            pytest.skip("Cannot create symlinks on this system")

        allowed_dirs = [str(allowed_dir)]

        with pytest.raises(ValueError, match="Access denied.*outside allowed directories"):
            validate_file_path(str(symlink), allowed_dirs=allowed_dirs)

    def test_no_allowed_dirs_accepts_any_valid_path(self, tmp_path):
        """Without allowed_dirs restriction, any valid path is accepted."""
        valid_file = tmp_path / "file.pcap"
        valid_file.touch()

        validated_path = validate_file_path(str(valid_file), allowed_dirs=None)
        assert Path(validated_path).resolve() == valid_file.resolve()


class TestIntegratedFileValidation:
    """Integration tests combining multiple validation layers."""

    def test_valid_pcap_passes_all_validations(self, tmp_path):
        """Valid PCAP file passes all validation layers."""
        pcap_file = tmp_path / "valid.pcap"
        pcap_file.write_bytes(b"\xa1\xb2\xc3\xd4" + b"\x00" * 1024)

        # All validations should pass
        file_type = validate_pcap_magic_number(str(pcap_file))
        validate_file_size(str(pcap_file), max_size_bytes=10 * 1024 * 1024)
        validate_file_path(str(pcap_file), allowed_dirs=[str(tmp_path)])

        assert file_type == "pcap"

    def test_malicious_file_blocked_at_first_layer(self, tmp_path):
        """Malicious file is blocked at earliest validation layer."""
        # File with path traversal in name
        malicious_path = str(tmp_path / ".." / "etc" / "passwd")

        # Path validation should block before even checking magic number
        with pytest.raises(ValueError, match="Path traversal detected"):
            validate_file_path(malicious_path)

    def test_oversized_invalid_pcap_blocked_by_size_check(self, tmp_path):
        """Oversized file with invalid magic is blocked by size check first."""
        huge_file = tmp_path / "huge_invalid.pcap"
        # Write 11 MB of invalid data
        huge_file.write_bytes(b"NOTAPCAP" + b"\x00" * (11 * 1024 * 1024))

        # Size check should fail before magic number check
        with pytest.raises(FileValidationError, match="File size.*exceeds maximum"):
            validate_file_size(str(huge_file), max_size_bytes=10 * 1024 * 1024)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
