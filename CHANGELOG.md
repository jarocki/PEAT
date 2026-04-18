# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added
- Passive forensic analysis command (`peat forensic`) for offline ICS/SCADA artifact analysis
- Disk image analysis (E01, dd/raw, VMDK, VHD, QCoW2) via dissect framework
- Firmware binary signature scanning and extraction (VxWorks, SquashFS, JFFS2, CramFS, ELF)
- ICS/SCADA log parsers: SEL SER, Siemens SIPROTEC, Schneider ClearSCADA, GE UR relay, Rockwell FactoryTalk, OSIsoft PI/AVEVA historian
- Network capture analysis (PCAP/PCAPNG): Modbus TCP, DNP3, EtherNet/IP, S7comm, BACnet
- Passive device fingerprinting from network captures (TCP stack, TLS/JA3, ICS protocol signatures)
- Zeek/ICSNPP optional integration for advanced ICS protocol analysis
- Forensic integrity: SHA-256/MD5 evidence hashing, chain-of-custody metadata, read-only enforcement
- 168+ unit tests for all forensic analysis capabilities

### Dependencies
- Added: dissect>=3.0 (AGPL-3.0-or-later) for forensic disk image analysis
- Added: dpkt>=1.9 (BSD) for PCAP triage processing

### Attribution
- Forensic extension code co-authored with Claude Opus 4.6 (Anthropic)
