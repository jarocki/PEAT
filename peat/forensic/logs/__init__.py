"""
ICS/SCADA log file parsing — vendor-specific parsers with ECS normalization.

Provides a unified ingestion framework that auto-detects log format and
normalizes output to Elastic Common Schema (ECS) compliant JSON.

Supported formats:
  - SEL relay SER (Sequential Events Recorder) logs
  - Siemens SIPROTEC CSV/text diagnostic exports
  - GE UR relay Security Audit Logs and IEC 61850 SCL XML
  - Schneider ClearSCADA Comms logs (TX/RX format)
  - Rockwell FactoryTalk Alarms and Events CSV exports
  - OSIsoft PI / AVEVA historian CSV/XML exports
"""
