#!/usr/bin/env python3
import os
import json
import requests
import pandas as pd
from datetime import datetime

# Load environment variables from .env file if present (for local development)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# Get API key securely
OTX_API_KEY = os.getenv("OTX_API_KEY")

if not OTX_API_KEY:
    raise SystemExit("ERROR: OTX_API_KEY not set. Please set in .env or environment.")

headers = {"X-OTX-API-KEY": OTX_API_KEY, "User-Agent": "cti-pipeline/1.0"}
url = "https://otx.alienvault.com/api/v1/pulses/subscribed"

print("Fetching CTI data from AlienVault OTX...")
r = requests.get(url, headers=headers, timeout=45)
r.raise_for_status()
data = r.json()

os.makedirs("out", exist_ok=True)
ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

# Save raw JSON snapshot
json_path = f"out/otx_pulses_{ts}.json"
with open(json_path, "w") as f:
    json.dump(data, f, indent=2)
print(f"Saved JSON: {json_path}")

# Flatten indicators into CSV
rows = []
for pulse in data.get("results", []):
    pulse_name = pulse.get("name")
    pulse_created = pulse.get("created")
    author = pulse.get("author_name") or pulse.get("author", {}).get("username")
    tags = ",".join(pulse.get("tags", []) or [])
    references = ",".join(pulse.get("references", []) or [])
    adversary = pulse.get("adversary") or ""
    tlp = pulse.get("tlp") or ""

    indicators = pulse.get("indicators", []) or []
    for ind in indicators:
        rows.append({
            "pulse_name": pulse_name,
            "pulse_created": pulse_created,
            "author": author,
            "tlp": tlp,
            "adversary": adversary,
            "tags": tags,
            "references": references,
            "indicator_type": ind.get("type"),
            "indicator": ind.get("indicator"),
            "indicator_title": ind.get("title"),
            "indicator_description": ind.get("description"),
            "indicator_created": ind.get("created"),
            "indicator_source": ind.get("source"),
        })

df = pd.DataFrame(rows)
csv_path = f"out/otx_indicators_{ts}.csv"
df.to_csv(csv_path, index=False)
print(f"Saved CSV: {csv_path} | rows={len(df)}")

print("✅ CTI data collection complete.")