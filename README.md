# Automated Cyber Threat Intelligence (CTI) Generation Project

This project automates collection of Cyber Threat Intelligence (CTI) data from open-source feeds (AlienVault OTX).

## Features
- Jenkins pipeline automation
- Python-based CTI fetch
- JSON output saved to `/out`
- Secure API key via Jenkins Credentials (ID: `otx-api-key`)

## Quick Start
1. Create a Jenkins credential (Secret text) with ID: `otx-api-key` (value = your OTX API key).
2. Create a Multibranch or Pipeline job pointing at this repo.
3. Run the pipeline — outputs appear in `out/` and are archived as artifacts.

## Local Test
```bash
export OTX_API_KEY=YOUR_KEY
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python cti/otx_fetch.py
```
