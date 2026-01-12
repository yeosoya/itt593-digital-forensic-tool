# ITT593 Digital Forensic Analysis Tool

## Description
This project is a Python-based digital forensic tool developed for ITT593.
It performs automated evidence hashing, network traffic analysis, and system log analysis while preserving evidence integrity.

## Features
- SHA-256 ingress and egress hashing
- Network traffic anomaly detection
- Failed login analysis from system logs
- Automated integrity verification

## Tools & Libraries
- Python 3.x
- pandas
- hashlib

## How to Run
1. Install Python
2. Install pandas: `pip install pandas`
3. Run: `python digital_forensic_tool.py`

## Evidence Integrity
The tool calculates cryptographic hashes before and after analysis to ensure no modification occurs.
