### Important note:  This is an experimental fork of https://github.com/sandialabs/PEAT that adds a "forensic" workflow.  It is untested in actual forensic cases and is not guaranteed to produce accurate or forensically sound results.

# Process Extraction and Analysis Tool (PEAT)

[![GitHub Actions Pipeline Status](https://github.com/jarocki/PEAT/actions/workflows/tests.yml/badge.svg)](https://github.com/jarocki/PEAT/actions)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/11835/badge)](https://www.bestpractices.dev/projects/11835)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Open in Dev Containers](https://img.shields.io/static/v1?label=Dev%20Containers&message=Open&color=blue)](https://vscode.dev/redirect?url=vscode://ms-vscode-remote.remote-containers/cloneInVolume?url=https://github.com/jarocki/PEAT)

PEAT is a Operational Technology (OT) device interrogator, including pulling, parsing and uploading artifacts (configuration, firmware, process logic, etc.) and network discovery ("scanning"). It runs on most systems, including Linux, Windows, and as a Docker container.

Documentation about installation, usage, development, and other information is in the [PEAT documentation](https://sandialabs.github.io/PEAT/).

## Easy install

Quick "one-liners" to easily install PEAT. We *strongly* recommend verifying script contents before downloading and running.

NOTE: PEAT will hang for a few seconds after running before there is output. This is normal, and is caused by slow imports.

### Linux/MacOS

The install script will download the latest full release of PEAT and install it into `/usr/local/bin/peat`. It will also download the manpage into `/usr/local/share/man/man1/peat.1` and update the manual database, if `mandb` command is present.

```shell
curl -sSL https://raw.githubusercontent.com/jarocki/PEAT/refs/heads/main/scripts/install_peat.sh | sudo sh -
```

### Windows

```powershell
powershell -ExecutionPolicy ByPass -c "irm https://raw.githubusercontent.com/jarocki/PEAT/refs/heads/main/scripts/install_peat.ps1 | iex"
```

### Docker

```shell
sudo docker run -i ghcr.io/jarocki/peat:latest --help
```

## Quickstart

1. Download the [latest release](https://github.com/jarocki/PEAT/releases) for your platform
1. Open a terminal in the folder you downloaded PEAT to
1. Run help to list subcommands
    - Windows: `.\peat.exe --help`
    - Linux: `./peat --help`
1. Get help for a subcommand, e.g. `scan`
    - Windows: `.\peat.exe scan --help`
    - Linux: `./peat scan --help`
1. Run a basic scan:
    - Windows: `.\peat.exe scan -i 192.0.2.0/24`
    - Linux: `./peat scan -i 192.0.2.0/24`

## Forensic Analysis

PEAT includes a passive forensic analysis mode (`peat forensic`) for analyzing OT/ICS artifacts without touching live devices. This is intended for incident response, digital forensics, and offline security assessments where active device interrogation is not possible or poses operational risk.

### Capabilities

**Disk Images** (E01, dd/raw, VMDK, VHD, QCoW2):
Mounts forensic disk images virtually using the [dissect](https://github.com/fox-it/dissect) framework — no root privileges or `qemu-nbd` required. Searches for ICS artifacts (PLC projects, relay configs, firmware) using patterns from all registered PEAT device modules. Supports embedded filesystems found in OT devices: NTFS, ext4, FAT, QNX, SquashFS, JFFS2.

**Firmware Binaries**:
Scans firmware blobs for known signatures (VxWorks `ESTFBINR`, SquashFS, JFFS2, CramFS, ELF, gzip/zlib, U-Boot) and extracts embedded content with automatic decompression.

**ICS/SCADA Log Files**:
Auto-detects and parses vendor-specific log formats with output normalized to the Elastic Common Schema (ECS):
- SEL relay Sequential Events Recorder (SER) logs
- Siemens SIPROTEC diagnostic CSV exports (from DIGSI 5)
- Schneider ClearSCADA / Geo SCADA Expert comms logs (TX/RX format)
- Schneider Modicon PLC CSV logs (SD card/flash exports)
- Generic CSV with timestamp auto-detection (fallback)

**Network Packet Captures** (PCAP/PCAPNG):
Two-stage analysis pipeline — fast triage with [dpkt](https://github.com/kbandla/dpkt) followed by deep ICS protocol dissection:
- Modbus TCP: function code decoding, register address extraction, exception detection
- DNP3: function code parsing, source/destination address extraction
- EtherNet/IP (CIP): encapsulation command parsing, session tracking
- S7comm, OPC-UA, BACnet: port-based identification
- Passive asset inventory: builds a device list from observed traffic without sending any packets

### Forensic Integrity

All forensic operations maintain evidence integrity:
- Streaming SHA-256 and MD5 hashes computed on ingest
- Chain-of-custody metadata (timestamps, file properties, analyst notes) written as JSON
- Read-only file access with warnings for writable evidence
- Per-log-line SHA-256 hashes in parsed output for log integrity verification

### Usage Examples

```shell
# Analyze a forensic disk image
peat forensic ./evidence/workstation.E01

# Analyze a PCAP with ICS traffic
peat forensic ./captures/scada_network.pcap

# Analyze a directory of ICS log files
peat forensic ./logs/sel_relay_exports/

# Analyze firmware with analyst notes
peat forensic --forensic-notes "Case 2026-042, item 3" ./evidence/plc_firmware.bin

# Force input type when auto-detection is ambiguous
peat forensic --forensic-mode firmware ./evidence/unknown_format.bin

# Output to Elasticsearch
peat forensic -e http://192.0.2.20:9200 ./evidence/historian.vmdk
```

Output is written to `./peat_results/` and includes:
- `forensic-metadata.json` — evidence hashes and chain-of-custody data
- `forensic_artifacts/` — extracted ICS files from disk images
- `firmware_extracted/` — carved and decompressed firmware regions
- `forensic_logs/parsed-log-entries.ndjson` — ECS-normalized log entries (Elasticsearch bulk-importable)
- `forensic_pcap/ics-events.ndjson` — extracted ICS protocol events
- `forensic_pcap/asset-inventory.json` — passively discovered device inventory

## Install notes

PEAT is distributed in several formats, including executable files for Linux and Windows and a Docker Container. The format you want to install depends on your use case. Typically, you'll want the executable format, which is `peat` on Linux and `peat.exe` on Windows. These can be downloaded from the [releases page](https://github.com/jarocki/PEAT/releases) or from [CI/CD builds](https://github.com/jarocki/PEAT/actions).

Python is NOT required to run PEAT if using the executable or container. PEAT is designed to be portable and brings it's own dependencies for the most part, requiring minimal or no configuring on the target system. Refer to the [system requirements page](https://sandialabs.github.io/PEAT/system_requirements.html) for further details.

NOTE: Refer to the [installation guide](https://sandialabs.github.io/PEAT/install.html) for installation instructions and [operation docs](https://sandialabs.github.io/PEAT/operate.html) for usage. The commands in the [quickstart](#quickstart) section are intended to get you going quickly, and are not comprehensive.

## Development

Refer to the [contributing guide](https://sandialabs.github.io/PEAT/contributing.html) and [development infrastructure](https://sandialabs.github.io/PEAT/development_infrastructure.html) documentation for details, including setting up a development environment, testing, and building on your local system.

The commands below are a basic "quick start" for development. Ensure [PDM is installed](https://pdm-project.org/en/stable/#installation) before proceeding.

```bash
# Ensure PDM is installed
# Clone repo, if it hasn't been already
git clone https://github.com/jarocki/PEAT.git

# Change directory
cd peat

# Disable update checks (faster and reduces chances for proxy-related errors)
pdm config check_update false

# Install dependencies and create virtual environment (in "./.venv/")
pdm install -d

# The virtual environment ("venv") contains PEAT's dependencies and development
# tools, and is automatically used and managed by PDM.
# There is NO need to "activate" the venv, use "pdm run" for any commands.

# Ensure the environment is working
pdm run peat --version
pdm run peat --help
pdm run python --version
pdm run pip --version

# List available scripts
pdm run -l
```

### Basic development commands

```shell
# List available scripts
pdm run -l

# Run lint checks
pdm run lint

# Automatically format code files
pdm run format

# Run unit tests
pdm run test

# Run unit tests, including slow tests
# This takes significantly longer, but is more comprehensive
pdm run test-full

# Run tests for a specific version of Python
# For example, Python 3.12
pdm use -f 3.12
pdm install -d
pdm run test
```

## License

Copyright 2026 National Technology & Engineering Solutions of Sandia, LLC (NTESS). Under the terms of Contract DE-NA0003525 with NTESS, the U.S. Government retains certain rights in this software.

This software is licensed under a GPLv3 license. Please see [LICENSE](LICENSE) and [COPYRIGHT.md](COPYRIGHT.md) for more information.

Modifications for forensic workflow are Copyright 2026 John Jarocki and respective copyright holders.