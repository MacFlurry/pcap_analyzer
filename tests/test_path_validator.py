"""
Tests for path validation utilities.

Coverage target: > 90%
"""

import pytest
from pathlib import Path
import tempfile
import os

from app.utils.path_validator import (
    validate_task_id,
    validate_filename,
    validate_path_in_directory
)
from fastapi import HTTPException


class TestValidateTaskId:
    """Test UUID v4 validation for task IDs."""

    def test_valid_uuid_v4(self):
        """Test that valid UUID v4 is accepted."""
        valid_uuid = "550e8400-e29b-41d4-a716-446655440000"
        result = validate_task_id(valid_uuid)
        assert result == valid_uuid

    def test_invalid_uuid_format(self):
        """Test that invalid UUID format is rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_task_id("not-a-uuid")

        assert exc_info.value.status_code == 400
        assert "Invalid task_id format" in exc_info.value.detail

    def test_path_traversal_in_task_id(self):
        """Test that path traversal attempts are rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_task_id("../../etc/passwd")

        assert exc_info.value.status_code == 400

    def test_uuid_with_uppercase(self):
        """Test that uppercase UUID is accepted."""
        uuid_upper = "550E8400-E29B-41D4-A716-446655440000"
        result = validate_task_id(uuid_upper)
        # UUID is preserved as-is
        assert result == uuid_upper

    def test_empty_task_id(self):
        """Test that empty task ID is rejected."""
        with pytest.raises(HTTPException) as exc_info:
            validate_task_id("")

        assert exc_info.value.status_code == 400

    def test_uuid_v1_rejected(self):
        """Test that UUID v1 (not v4) is rejected."""
        uuid_v1 = "550e8400-e29b-11d4-a716-446655440000"  # v1
        with pytest.raises(HTTPException) as exc_info:
            validate_task_id(uuid_v1)

        assert exc_info.value.status_code == 400


class TestValidateFilename:
    """Test filename sanitization."""

    def test_simple_filename(self):
        """Test that simple filenames pass through."""
        result = validate_filename("test.pcap")
        assert result == "test.pcap"

    def test_path_traversal_removed(self):
        """Test that path traversal is sanitized."""
        result = validate_filename("../../etc/passwd.pcap")
        assert result == "passwd.pcap"
        assert ".." not in result
        assert "/" not in result

    def test_backslash_traversal_removed(self):
        """Test that Windows-style path traversal is rejected."""
        # Implementation rejects filenames starting with dot after sanitization
        with pytest.raises(HTTPException) as exc_info:
            validate_filename("..\\..\\windows\\system32\\config.pcap")
        assert exc_info.value.status_code == 400

    def test_null_bytes_removed(self):
        """Test that null bytes are rejected."""
        # Implementation explicitly rejects null bytes
        with pytest.raises(HTTPException) as exc_info:
            validate_filename("test\x00.pcap")
        assert exc_info.value.status_code == 400
        assert "null byte" in exc_info.value.detail

    def test_special_characters_preserved(self):
        """Test that safe special characters are preserved."""
        result = validate_filename("test-file_123.pcap")
        assert result == "test-file_123.pcap"

    def test_unicode_filename(self):
        """Test that Unicode characters are handled."""
        result = validate_filename("tést_fîlé.pcap")
        # Should preserve Unicode or sanitize safely
        assert ".pcap" in result

    def test_empty_filename(self):
        """Test that empty filename raises error."""
        with pytest.raises(HTTPException) as exc_info:
            validate_filename("")

        assert exc_info.value.status_code == 400
        assert "Invalid filename" in exc_info.value.detail

    def test_filename_only_special_chars(self):
        """Test that filename with only special chars raises error."""
        with pytest.raises(HTTPException) as exc_info:
            validate_filename("../../")

        assert exc_info.value.status_code == 400

    def test_very_long_filename(self):
        """Test that very long filenames are rejected."""
        long_name = "a" * 300 + ".pcap"
        # Implementation rejects filenames > 255 chars
        with pytest.raises(HTTPException) as exc_info:
            validate_filename(long_name)
        assert exc_info.value.status_code == 400
        assert "too long" in exc_info.value.detail


class TestValidatePathInDirectory:
    """Test path validation against directory boundaries."""

    def test_valid_path_in_directory(self):
        """Test that valid path within directory is accepted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir).resolve()
            test_file = base_dir / "test.pcap"

            result = validate_path_in_directory(test_file, base_dir)
            # Compare resolved paths (macOS has /private/var vs /var)
            assert result.resolve() == test_file.resolve()

    def test_path_traversal_rejected(self):
        """Test that path traversal outside directory is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir).resolve()
            malicious_path = base_dir / ".." / ".." / "etc" / "passwd"

            with pytest.raises(HTTPException) as exc_info:
                validate_path_in_directory(malicious_path, base_dir)

            assert exc_info.value.status_code == 400
            assert "escapes base directory" in exc_info.value.detail

    def test_symlink_outside_directory_rejected(self):
        """Test that symlinks pointing outside directory are rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)

            # Create a symlink pointing outside
            link_path = base_dir / "malicious_link"
            target_path = Path("/etc/passwd")

            try:
                link_path.symlink_to(target_path)

                with pytest.raises(HTTPException) as exc_info:
                    validate_path_in_directory(link_path, base_dir)

                assert exc_info.value.status_code == 400
            except OSError:
                # Symlink creation might fail on some systems, skip test
                pytest.skip("Cannot create symlinks on this system")

    def test_nested_path_allowed(self):
        """Test that nested paths within directory are allowed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir).resolve()
            nested_path = base_dir / "subdir" / "test.pcap"

            result = validate_path_in_directory(nested_path, base_dir)
            # Compare resolved paths
            assert result.resolve() == nested_path.resolve()

    def test_absolute_path_outside_rejected(self):
        """Test that absolute path outside directory is rejected."""
        with tempfile.TemporaryDirectory() as tmpdir:
            base_dir = Path(tmpdir)
            outside_path = Path("/tmp/malicious.pcap")

            with pytest.raises(HTTPException) as exc_info:
                validate_path_in_directory(outside_path, base_dir)

            assert exc_info.value.status_code == 400
