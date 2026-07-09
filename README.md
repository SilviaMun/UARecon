# OpcPEAS

OpcPEAS is an OPC-UA enumeration and security assessment tool for pentesters and OT security engineers.

It supports:

- OPC UA endpoint discovery
- authenticated enumeration
- deep node browsing
- session diagnostics
- security diagnostics
- vendor information extraction
- local CVE matching against a bundled JSON database
- offline CVE database listing
- JSON report output

## Features

- Auto-generated self-signed client certificates
- Detection of insecure / legacy OPC UA security configurations
- Post-auth enumeration of server information, namespaces, sessions, vendor info, and nodes
- Local CVE database in `data/opcua_cves.json`
- Separate CVE DB builder in `tools/build_cve_db.py`
- JSON report output for later review or team sharing

## Recommended Python Version

Recommended:
- Python 3.10
- Python 3.11

`python-opcua` may behave oddly on Python 3.13 in some environments.

## Requirements

- Python 3
- OpenSSL installed on the system
- Network reachability to the OPC UA target

## Installation

```bash
git clone https://github.com/YOURUSER/opcpeas.git
cd opcpeas

python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt
python3 tools/build_cve_db.py
