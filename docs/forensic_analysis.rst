******************
Forensic Analysis
******************

.. warning::
   The forensic analysis module is experimental and was developed with AI
   assistance (Claude, Anthropic). It has not undergone the same level of
   field testing as PEAT's core device interrogation capabilities. Verify
   results independently in production incident response scenarios.

The ``peat forensic`` command provides passive analysis of OT/ICS artifacts
without touching live devices. It supports disk images, firmware binaries,
ICS/SCADA log files, and network packet captures.

High-level API
==============
.. automodule:: peat.api.forensic_api
   :members:

Input Detection
===============
.. automodule:: peat.forensic
   :members:

Forensic Integrity
==================
.. automodule:: peat.forensic.integrity
   :members:

Disk Image Analysis
===================
.. automodule:: peat.forensic.image
   :members:

Firmware Analysis
=================
.. automodule:: peat.forensic.firmware
   :members:

PCAP Analysis
=============
.. automodule:: peat.forensic.pcap
   :members:

Device Fingerprinting
=====================
.. automodule:: peat.forensic.fingerprint
   :members:

Zeek Integration
================
.. automodule:: peat.forensic.zeek
   :members:

Log Parsers
===========

Base Classes
^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.base
   :members:

Log Ingest Pipeline
^^^^^^^^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.ingest
   :members:

SEL Parser
^^^^^^^^^^
.. automodule:: peat.forensic.logs.sel_parser
   :members:

SIPROTEC Parser
^^^^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.siprotec_parser
   :members:

Schneider Parser
^^^^^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.schneider_parser
   :members:

GE Parser
^^^^^^^^^
.. automodule:: peat.forensic.logs.ge_parser
   :members:

Rockwell Parser
^^^^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.rockwell_parser
   :members:

Historian Parser
^^^^^^^^^^^^^^^^
.. automodule:: peat.forensic.logs.historian_parser
   :members:
