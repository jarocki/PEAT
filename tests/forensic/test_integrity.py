"""
Tests for forensic integrity module.

@decision: Tests use hashlib directly to compute expected values rather than
hardcoding hex strings. This keeps tests resilient to platform differences
and clearly shows the relationship between input data and expected output.
"""

import hashlib
import io
from pathlib import Path

import pytest

from peat.forensic.integrity import (
    ForensicMetadata,
    compute_hash_from_stream,
    compute_hashes,
    generate_forensic_metadata,
    verify_hash,
)


class TestComputeHashes:
    """Tests for hash computation functions."""

    def test_known_hash(self, tmp_path: Path) -> None:
        """Verify SHA-256 and MD5 against known values."""
        content = b"PEAT forensic test data"
        f = tmp_path / "test.bin"
        f.write_bytes(content)

        sha256_hex, md5_hex = compute_hashes(f)

        assert sha256_hex == hashlib.sha256(content).hexdigest()
        assert md5_hex == hashlib.md5(content).hexdigest()  # noqa: S324

    def test_empty_file(self, tmp_path: Path) -> None:
        """Empty file should produce the well-known empty-input hashes."""
        f = tmp_path / "empty.bin"
        f.write_bytes(b"")

        sha256_hex, md5_hex = compute_hashes(f)

        assert sha256_hex == hashlib.sha256(b"").hexdigest()
        assert md5_hex == hashlib.md5(b"").hexdigest()  # noqa: S324

    def test_large_file_streams(self, tmp_path: Path) -> None:
        """File larger than buffer size (64KB) should still hash correctly."""
        content = b"A" * 200_000  # ~200 KB
        f = tmp_path / "large.bin"
        f.write_bytes(content)

        sha256_hex, md5_hex = compute_hashes(f)

        assert sha256_hex == hashlib.sha256(content).hexdigest()

    def test_nonexistent_file_raises(self, tmp_path: Path) -> None:
        with pytest.raises(OSError):
            compute_hashes(tmp_path / "no_such_file.bin")


class TestComputeHashFromStream:
    """Tests for stream-based hashing."""

    def test_sha256_stream(self) -> None:
        data = b"stream test data"
        stream = io.BytesIO(data)
        result = compute_hash_from_stream(stream, "sha256")
        assert result == hashlib.sha256(data).hexdigest()

    def test_md5_stream(self) -> None:
        data = b"stream test data"
        stream = io.BytesIO(data)
        result = compute_hash_from_stream(stream, "md5")
        assert result == hashlib.md5(data).hexdigest()  # noqa: S324


class TestVerifyHash:
    """Tests for hash verification."""

    def test_matching_hash(self, tmp_path: Path) -> None:
        content = b"verify me"
        f = tmp_path / "test.bin"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest()

        assert verify_hash(f, expected) is True

    def test_mismatched_hash(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"actual content")

        assert verify_hash(f, "0" * 64) is False

    def test_case_insensitive(self, tmp_path: Path) -> None:
        content = b"case test"
        f = tmp_path / "test.bin"
        f.write_bytes(content)
        expected = hashlib.sha256(content).hexdigest().upper()

        assert verify_hash(f, expected) is True


class TestGenerateForensicMetadata:
    """Tests for full metadata generation."""

    def test_metadata_fields(self, tmp_path: Path) -> None:
        content = b"metadata test"
        f = tmp_path / "evidence.e01"
        f.write_bytes(content)

        meta = generate_forensic_metadata(f, notes="Test case 001")

        assert meta.file_name == "evidence.e01"
        assert meta.file_size == len(content)
        assert meta.sha256 == hashlib.sha256(content).hexdigest()
        assert meta.md5 == hashlib.md5(content).hexdigest()  # noqa: S324
        assert meta.notes == "Test case 001"
        assert meta.ingest_time  # non-empty
        assert meta.original_modified_time  # non-empty
        assert "evidence.e01" in meta.file_path

    def test_to_dict_structure(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"dict test")

        meta = generate_forensic_metadata(f)
        d = meta.to_dict()

        assert "forensic_integrity" in d
        fi = d["forensic_integrity"]
        assert "hashes" in fi
        assert "sha256" in fi["hashes"]
        assert "md5" in fi["hashes"]
        assert "ingest_time_utc" in fi
        assert "file_size" in fi

    def test_to_dict_without_notes(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"no notes")

        meta = generate_forensic_metadata(f)
        d = meta.to_dict()

        assert "notes" not in d["forensic_integrity"]

    def test_to_dict_with_notes(self, tmp_path: Path) -> None:
        f = tmp_path / "test.bin"
        f.write_bytes(b"with notes")

        meta = generate_forensic_metadata(f, notes="Case 42")
        d = meta.to_dict()

        assert d["forensic_integrity"]["notes"] == "Case 42"
