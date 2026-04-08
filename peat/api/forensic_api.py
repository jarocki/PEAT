"""
High-level forensic API — entry point for passive forensic analysis.

Routes forensic inputs (disk images, log files, PCAPs) to the appropriate
analysis pipeline and manages forensic integrity throughout.

@decision: Designed as a single entry point (forensic_main) that auto-detects
input type and delegates, rather than requiring users to know which sub-module
handles their input. This mirrors how `peat pull` auto-detects device types.
Users can also force a specific mode via CLI flags.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from peat import config, log, state
from peat.forensic import ForensicInputType, detect_input_type
from peat.forensic.integrity import (
    ForensicMetadata,
    ensure_read_only,
    generate_forensic_metadata,
)


def forensic_main(args: dict[str, Any]) -> bool:
    """
    Main entry point for forensic analysis.

    Determines input type, computes integrity hashes, and dispatches
    to the appropriate analysis pipeline.

    Args:
        args: CLI arguments dictionary containing at minimum 'forensic_source'
              and optionally 'forensic_mode' to force a specific analysis type.

    Returns:
        True if analysis completed successfully.
    """
    source = args.get("forensic_source")
    if not source:
        log.critical("No forensic source specified. Run 'peat forensic --help' for usage.")
        return False

    source_path = Path(source).resolve()

    if not source_path.exists():
        log.critical(f"Forensic source does not exist: {source_path}")
        return False

    # Determine input type (auto-detect or forced via CLI flag)
    forced_mode = args.get("forensic_mode")
    if forced_mode:
        try:
            input_type = ForensicInputType(forced_mode)
        except ValueError:
            log.critical(f"Unknown forensic mode: {forced_mode}")
            return False
        log.info(f"Forensic mode forced to: {input_type.value}")
    else:
        input_type = detect_input_type(source_path)
        log.info(f"Auto-detected forensic input type: {input_type.value}")

    if input_type == ForensicInputType.UNKNOWN:
        log.critical(
            f"Cannot determine input type for: {source_path}. "
            f"Use --forensic-mode to specify manually."
        )
        return False

    # Generate forensic metadata (hashing) for file inputs
    metadata: ForensicMetadata | None = None
    if source_path.is_file():
        ensure_read_only(source_path)
        metadata = generate_forensic_metadata(
            source_path,
            notes=args.get("forensic_notes", ""),
        )
        log.info(
            f"Evidence file: {metadata.file_name} "
            f"({metadata.file_size:,} bytes, SHA-256: {metadata.sha256[:16]}...)"
        )

    # Write forensic metadata to output directory
    if metadata and config.RUN_DIR:
        _write_forensic_metadata(metadata)

    # Dispatch to appropriate analysis pipeline
    success = False
    if input_type == ForensicInputType.DISK_IMAGE:
        success = _analyze_disk_image(source_path, metadata, args)
    elif input_type == ForensicInputType.PCAP:
        success = _analyze_pcap(source_path, metadata, args)
    elif input_type in (ForensicInputType.LOG_FILE, ForensicInputType.LOG_DIRECTORY):
        success = _analyze_logs(source_path, metadata, args)
    elif input_type == ForensicInputType.FIRMWARE:
        success = _analyze_firmware(source_path, metadata, args)

    if success:
        log.info(f"Forensic analysis completed successfully for: {source_path.name}")
    else:
        log.error(f"Forensic analysis failed for: {source_path.name}")

    return success


def _write_forensic_metadata(metadata: ForensicMetadata) -> None:
    """Write forensic metadata JSON to the output directory."""
    meta_path = config.RUN_DIR / "forensic-metadata.json"
    try:
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        meta_path.write_text(json.dumps(metadata.to_dict(), indent=4))
        log.debug(f"Forensic metadata written to: {meta_path}")
    except OSError as e:
        log.warning(f"Failed to write forensic metadata: {e}")


def _analyze_disk_image(
    path: Path, metadata: ForensicMetadata | None, args: dict[str, Any]
) -> bool:
    """Dispatch to disk image analysis pipeline, then parse extracted artifacts."""
    from peat.forensic.image import analyze_disk_image

    result = analyze_disk_image(image_path=path, metadata=metadata)

    # Feed extracted artifacts into PEAT's parse pipeline
    extracted_paths = [
        Path(a.output_path) for a in result.artifacts
        if a.output_path and Path(a.output_path).exists()
    ]
    if extracted_paths:
        parse_results = _parse_extracted_artifacts(extracted_paths)
        log.info(
            f"Parse pipeline: {parse_results['parsed']} of "
            f"{parse_results['total']} extracted artifacts parsed successfully"
        )

    return len(result.errors) == 0 or len(result.artifacts) > 0


def _analyze_pcap(
    path: Path, metadata: ForensicMetadata | None, args: dict[str, Any]
) -> bool:
    """Dispatch to PCAP analysis pipeline."""
    from peat.forensic.pcap import analyze_pcap

    result = analyze_pcap(pcap_path=path)
    return len(result.errors) == 0


def _analyze_logs(
    path: Path, metadata: ForensicMetadata | None, args: dict[str, Any]
) -> bool:
    """Dispatch to log file analysis pipeline."""
    from peat.forensic.logs.ingest import ingest_logs

    entries = ingest_logs(path)
    return len(entries) > 0


def _analyze_firmware(
    path: Path, metadata: ForensicMetadata | None, args: dict[str, Any]
) -> bool:
    """Dispatch to firmware analysis pipeline, then parse extracted content."""
    from peat.forensic.firmware import analyze_firmware

    result = analyze_firmware(firmware_path=path)

    # Feed extracted firmware files into PEAT's parse pipeline
    extracted_paths = [
        Path(p) for p in result.extracted_files
        if Path(p).exists()
    ]
    if extracted_paths:
        parse_results = _parse_extracted_artifacts(extracted_paths)
        log.info(
            f"Parse pipeline: {parse_results['parsed']} of "
            f"{parse_results['total']} extracted files parsed successfully"
        )

    return len(result.errors) == 0 or len(result.regions) > 0


def _parse_extracted_artifacts(artifact_paths: list[Path]) -> dict[str, int]:
    """
    Feed extracted forensic artifacts into PEAT's existing parse pipeline.

    Matches each artifact against PEAT device module filename patterns and
    invokes the module's parser for matching files. This connects the forensic
    extraction layer to PEAT's full device data model.

    Args:
        artifact_paths: Paths to extracted files on disk.

    Returns:
        Dict with 'total', 'parsed', and 'failed' counts.
    """
    from peat.api.parse_api import find_parsable_files, parse_data
    from peat import module_api

    results = {"total": len(artifact_paths), "parsed": 0, "failed": 0}
    all_files = sorted(str(p) for p in artifact_paths)

    # Get all parse-capable modules
    parse_modules = [
        cls for cls in module_api.classes
        if hasattr(cls, "filename_patterns") and cls.filename_patterns
    ]

    for dev_cls in parse_modules:
        matched_files = find_parsable_files(all_files, dev_cls)
        for file_path in matched_files:
            log.info(f"Parsing extracted artifact with {dev_cls.__name__}: {file_path.name}")
            try:
                dev = parse_data(file_path, dev_cls)
                if dev:
                    results["parsed"] += 1
                    log.info(f"Successfully parsed: {file_path.name} → {dev_cls.__name__}")
                else:
                    results["failed"] += 1
            except Exception as e:
                log.warning(f"Parse failed for {file_path.name}: {e}")
                results["failed"] += 1

    unmatched = results["total"] - results["parsed"] - results["failed"]
    if unmatched > 0:
        log.debug(f"{unmatched} extracted files did not match any PEAT module patterns")

    return results
