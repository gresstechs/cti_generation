#!/usr/bin/env python3
import os
import json
import requests
import pandas as pd
import glob
import shutil
from datetime import datetime

def cleanup_old_files():
    """Remove old CTI output files, keeping only the most recent 3 of each type"""
    print("🧹 Cleaning up old output files...")
    
    file_patterns = [
        "out/cti_pulses_*.csv",
        "out/cti_indicators_*.csv", 
        "out/cti_summary_*.json",
        "out/cti_grafana_*.json",
        "out/cti_raw_*.json",
        "out/otx_indicators_*.csv",  # Legacy files
        "out/otx_pulses_*.json"      # Legacy files
    ]
    
    total_deleted = 0
    for pattern in file_patterns:
        files = glob.glob(pattern)
        if len(files) > 3:  # Keep most recent 3 files
            # Sort by modification time, newest first
            files.sort(key=os.path.getmtime, reverse=True)
            files_to_delete = files[3:]  # Delete all but the 3 most recent
            
            for file_path in files_to_delete:
                try:
                    os.remove(file_path)
                    print(f"   Deleted: {os.path.basename(file_path)}")
                    total_deleted += 1
                except OSError as e:
                    print(f"   ⚠️  Could not delete {file_path}: {e}")
    
    if total_deleted > 0:
        print(f"✅ Cleaned up {total_deleted} old files")
    else:
        print("✅ No old files to clean up")

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

# Clean up old files before creating new ones
cleanup_old_files()

os.makedirs("out", exist_ok=True)
ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
fetch_date = datetime.utcnow().isoformat()

# ============================================================================
# 1. PULSES DATA - Summary of all threat pulses
# ============================================================================
pulses_rows = []
for pulse in data.get("results", []):
    pulses_rows.append({
        "pulse_id": pulse.get("id"),
        "pulse_name": pulse.get("name"),
        "description": pulse.get("description"),
        "created_date": pulse.get("created"),
        "modified_date": pulse.get("modified"),
        "author": pulse.get("author_name") or pulse.get("author", {}).get("username"),
        "tlp": pulse.get("tlp") or "unknown",
        "adversary": pulse.get("adversary") or "",
        "malware_families": ",".join(pulse.get("malware_families", []) or []),
        "attack_ids": ",".join(pulse.get("attack_ids", []) or []),
        "tags": ",".join(pulse.get("tags", []) or []),
        "references": ",".join(pulse.get("references", []) or []),
        "indicator_count": len(pulse.get("indicators", []) or []),
        "subscription_count": pulse.get("subscription_count", 0),
        "fetch_timestamp": fetch_date
    })

pulses_df = pd.DataFrame(pulses_rows)
pulses_csv = f"out/cti_pulses_{ts}.csv"
pulses_df.to_csv(pulses_csv, index=False)
print(f"✅ Saved pulses: {pulses_csv} | rows={len(pulses_df)}")

# ============================================================================
# 2. INDICATORS DATA - Detailed indicators with pulse context
# ============================================================================
indicators_rows = []
for pulse in data.get("results", []):
    pulse_id = pulse.get("id")
    pulse_name = pulse.get("name")
    author = pulse.get("author_name") or pulse.get("author", {}).get("username")
    tlp = pulse.get("tlp") or "unknown"
    adversary = pulse.get("adversary") or ""
    malware_families = ",".join(pulse.get("malware_families", []) or [])
    attack_ids = ",".join(pulse.get("attack_ids", []) or [])
    tags = ",".join(pulse.get("tags", []) or [])
    
    indicators = pulse.get("indicators", []) or []
    for ind in indicators:
        indicators_rows.append({
            "pulse_id": pulse_id,
            "pulse_name": pulse_name,
            "indicator_id": ind.get("id"),
            "indicator_type": ind.get("type"),
            "indicator": ind.get("indicator"),
            "indicator_title": ind.get("title"),
            "indicator_description": ind.get("description"),
            "indicator_created": ind.get("created"),
            "indicator_modified": ind.get("modified"),
            "indicator_source": ind.get("source"),
            "severity": ind.get("severity") or "unknown",
            "pulse_author": author,
            "pulse_tlp": tlp,
            "pulse_adversary": adversary,
            "pulse_malware_families": malware_families,
            "pulse_attack_ids": attack_ids,
            "pulse_tags": tags,
            "pulse_created": pulse.get("created"),
            "fetch_timestamp": fetch_date
        })

indicators_df = pd.DataFrame(indicators_rows)
indicators_csv = f"out/cti_indicators_{ts}.csv"
indicators_df.to_csv(indicators_csv, index=False)
print(f"✅ Saved indicators: {indicators_csv} | rows={len(indicators_df)}")

# ============================================================================
# 3. SUMMARY STATISTICS - Aggregated metrics for dashboards
# ============================================================================
summary = {
    "fetch_timestamp": fetch_date,
    "total_pulses": len(pulses_df),
    "total_indicators": len(indicators_df),
    "indicator_types": indicators_df["indicator_type"].value_counts().to_dict() if len(indicators_df) > 0 else {},
    "tlp_distribution": pulses_df["tlp"].value_counts().to_dict() if len(pulses_df) > 0 else {},
    "top_adversaries": pulses_df[pulses_df["adversary"] != ""]["adversary"].value_counts().head(10).to_dict() if len(pulses_df) > 0 else {},
    "severity_distribution": indicators_df["severity"].value_counts().to_dict() if len(indicators_df) > 0 else {},
    "malware_families": list(set(",".join(pulses_df["malware_families"]).split(","))),
    "attack_ids": list(set(",".join(pulses_df["attack_ids"]).split(",")))
}

summary_json = f"out/cti_summary_{ts}.json"
with open(summary_json, "w") as f:
    json.dump(summary, f, indent=2)
print(f"✅ Saved summary: {summary_json}")

# ============================================================================
# 4. GRAFANA-READY JSON - Time-series data format
# ============================================================================
grafana_data = {
    "fetch_timestamp": fetch_date,
    "metrics": {
        "pulses_count": len(pulses_df),
        "indicators_count": len(indicators_df),
        "avg_indicators_per_pulse": round(len(indicators_df) / max(len(pulses_df), 1), 2)
    },
    "indicator_types": [
        {
            "type": ind_type,
            "count": int(count)
        }
        for ind_type, count in indicators_df["indicator_type"].value_counts().to_dict().items()
    ] if len(indicators_df) > 0 else [],
    "tlp_levels": [
        {
            "tlp": tlp,
            "count": int(count)
        }
        for tlp, count in pulses_df["tlp"].value_counts().to_dict().items()
    ] if len(pulses_df) > 0 else [],
    "adversaries": [
        {
            "name": adversary,
            "count": int(count)
        }
        for adversary, count in pulses_df[pulses_df["adversary"] != ""]["adversary"].value_counts().head(15).to_dict().items()
    ] if len(pulses_df) > 0 else [],
    "recent_pulses": pulses_df.sort_values("created_date", ascending=False).head(10).to_dict("records")
}

grafana_json = f"out/cti_grafana_{ts}.json"
with open(grafana_json, "w") as f:
    json.dump(grafana_data, f, indent=2)
print(f"✅ Saved Grafana-ready data: {grafana_json}")

# ============================================================================
# 5. FULL RAW JSON - Complete API response for reference
# ============================================================================
raw_json = f"out/cti_raw_{ts}.json"
with open(raw_json, "w") as f:
    json.dump(data, f, indent=2)
print(f"✅ Saved raw JSON: {raw_json}")

def create_latest_links():
    """Create 'latest' copies of the most recent files for easy access"""
    print("🔗 Creating latest file links...")
    
    file_mappings = {
        "out/cti_pulses_*.csv": "out/cti_pulses_latest.csv",
        "out/cti_indicators_*.csv": "out/cti_indicators_latest.csv", 
        "out/cti_summary_*.json": "out/cti_summary_latest.json",
        "out/cti_grafana_*.json": "out/cti_grafana_latest.json",
        "out/cti_raw_*.json": "out/cti_raw_latest.json"
    }
    
    for pattern, latest_name in file_mappings.items():
        files = glob.glob(pattern)
        if files:
            # Get the most recent file
            latest_file = max(files, key=os.path.getmtime)
            try:
                # Copy to latest filename
                import shutil
                shutil.copy2(latest_file, latest_name)
                print(f"   Created: {latest_name} → {os.path.basename(latest_file)}")
            except Exception as e:
                print(f"   ⚠️  Could not create {latest_name}: {e}")

print("\n" + "="*60)
print("✅ CTI data collection complete!")
print("="*60)
print(f"📊 Summary:")
print(f"   • Pulses: {len(pulses_df)}")
print(f"   • Indicators: {len(indicators_df)}")
print(f"   • Indicator types: {len(indicators_df['indicator_type'].unique()) if len(indicators_df) > 0 else 0}")
print(f"   • TLP levels: {', '.join(pulses_df['tlp'].unique())}")

# Create latest file links for easy access
create_latest_links()

print("="*60)