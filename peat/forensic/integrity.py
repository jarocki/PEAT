"""
Forensic integrity module — hashing, chain of custody, and read-only enforcement.

Provides cryptographic hashing for evidence files, chain-of-custody metadata
generation, and utilities to ensure all forensic operations are read-only.

@decision: Uses streaming SHA-256 for hashing rather than loading entire files
into memory. ICS disk images and PCAPs can be multi-gigabyte; streaming with
a 64KB buffer keeps memory usage constant regardless of file size.
"""
# Copyright 2026 John Jarocki
# Developed with AI assistance from Claude Opus 4.6 (Anthropic)
#
# This file is part of PEAT and is licensed under GPL-3.0.
# See LICENSE for details.


from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, BinaryIO

from peat import log


@dataclass
class ForensicMetadata:
    """
    Chain-of-custody metadata for a forensic artifact.

    Captures the cryptographic hash, file properties, and processing
    timestamps needed to establish evidence integrity.
    """

    file_path: str
    file_name: str
    file_size: int
    sha256: str
    md5: str
    ingest_time: str  # ISO 8601 UTC
    peat_version: str = ""
    notes: str = ""
    original_modified_time: str = ""  # ISO 8601 UTC
    additional_hashes: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Export metadata as a dictionary for JSON serialization."""
        result = {
            "forensic_integrity": {
                "file_path": self.file_path,
                "file_name": self.file_name,
                "file_size": self.file_size,
                "hashes": {
                    "sha256": self.sha256,
                    "md5": self.md5,
                    **self.additional_hashes,
                },
                "ingest_time_utc": self.ingest_time,
                "original_modified_time_utc": self.original_modified_time,
                "peat_version": self.peat_version,
            }
        }
        if self.notes:
            result["forensic_integrity"]["notes"] = self.notes
        return result


# 64 KB read buffer for streaming hash computation
_HASH_BUFFER_SIZE = 65536


def compute_hashes(path: Path) -> tuple[str, str]:
    """
    Compute SHA-256 and MD5 hashes of a file using streaming reads.

    Args:
        path: Path to the file to hash.

    Returns:
        Tuple of (sha256_hex, md5_hex).

    Raises:
        OSError: If the file cannot be read.
    """
    sha256 = hashlib.sha256()
    md5 = hashlib.md5()  # noqa: S324 — MD5 used for identification, not security

    with open(path, "rb") as f:
        while True:
            data = f.read(_HASH_BUFFER_SIZE)
            if not data:
                break
            sha256.update(data)
            md5.update(data)

    return sha256.hexdigest(), md5.hexdigest()


def compute_hash_from_stream(stream: BinaryIO, algorithm: str = "sha256") -> str:
    """
    Compute a hash from a binary stream without consuming it entirely into memory.

    Args:
        stream: An open binary stream (must support read()).
        algorithm: Hash algorithm name (default: sha256).

    Returns:
        Hex digest string.
    """
    h = hashlib.new(algorithm)
    while True:
        data = stream.read(_HASH_BUFFER_SIZE)
        if not data:
            break
        h.update(data)
    return h.hexdigest()


def generate_forensic_metadata(path: Path, notes: str = "") -> ForensicMetadata:
    """
    Generate complete forensic metadata for an evidence file.

    Computes hashes, captures file properties, and records the ingest timestamp.

    Args:
        path: Path to the evidence file.
        notes: Optional analyst notes.

    Returns:
        ForensicMetadata instance.
    """
    from peat import __version__

    log.info(f"Computing forensic hashes for: {path.name}")
    sha256_hex, md5_hex = compute_hashes(path)
    log.debug(f"SHA-256: {sha256_hex}")
    log.debug(f"MD5:     {md5_hex}")

    stat = path.stat()
    mod_time = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()
    ingest_time = datetime.now(tz=timezone.utc).isoformat()

    return ForensicMetadata(
        file_path=str(path.resolve()),
        file_name=path.name,
        file_size=stat.st_size,
        sha256=sha256_hex,
        md5=md5_hex,
        ingest_time=ingest_time,
        peat_version=__version__,
        notes=notes,
        original_modified_time=mod_time,
    )


def verify_hash(path: Path, expected_sha256: str) -> bool:
    """
    Verify a file's SHA-256 hash against an expected value.

    Args:
        path: Path to the file.
        expected_sha256: Expected SHA-256 hex digest.

    Returns:
        True if the hash matches.
    """
    sha256_hex, _ = compute_hashes(path)
    match = sha256_hex == expected_sha256.lower()
    if not match:
        log.warning(
            f"Hash mismatch for {path.name}: "
            f"expected {expected_sha256}, got {sha256_hex}"
        )
    return match


def ensure_read_only(path: Path) -> None:
    """
    Verify that a file is not writable, and log a warning if it is.

    This is a defensive check — forensic operations should never modify evidence.
    The actual protection comes from opening files in read-only mode.

    Args:
        path: Path to check.
    """
    if os.access(path, os.W_OK):
        log.warning(
            f"Evidence file is writable: {path}. "
            f"Consider setting read-only permissions before analysis."
        )
