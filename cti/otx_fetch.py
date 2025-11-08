#!/usr/bin/env python3
import os
import json
import requests
import pandas as pd
import glob
import shutil
from datetime import datetime

# Track execution time
start_time = datetime.utcnow()

def cleanup_old_files():
    """Remove old CTI output files, keeping only the most recent 3 of each type"""
    print("🧹 Cleaning up old output files...")
    
    file_patterns = [
        "out/cti_pulses_*.csv",
        "out/cti_indicators_*.csv", 
        "out/cti_summary_*.json",
        "out/cti_grafana_*.json",
        "out/cti_raw_*.json",
        "out/cti_ml_features_*.csv",
        "out/ml_training_data_*.json",
        "out/otx_indicators_*.csv",  # Legacy files
        "out/otx_pulses_*.json"      # Legacy files
    ]
    
    total_deleted = 0
    for pattern in file_patterns:
        files = glob.glob(pattern)
        if len(files) > 3:  # Keep most recent 3 files
            files.sort(key=os.path.getmtime, reverse=True)
            files_to_delete = files[3:]
            
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

def validate_data(pulses_df, indicators_df):
    """Validate collected data"""
    print("\n🔍 Validating data...")
    issues = []
    
    # Check if we got data
    if len(pulses_df) == 0:
        issues.append("⚠️  No pulses collected")
    
    if len(indicators_df) == 0:
        issues.append("⚠️  No indicators collected")
    
    # Check for required columns
    required_pulse_cols = ['pulse_id', 'pulse_name', 'tlp', 'created_date']
    missing_cols = [col for col in required_pulse_cols if col not in pulses_df.columns]
    if missing_cols:
        issues.append(f"⚠️  Missing pulse columns: {missing_cols}")
    
    # Check data quality
    if len(pulses_df) > 0:
        null_tlp = pulses_df['tlp'].isna().sum()
        if null_tlp > 0:
            issues.append(f"⚠️  {null_tlp} pulses with missing TLP")
    
    if issues:
        for issue in issues:
            print(f"   {issue}")
        return False
    else:
        print("   ✅ All validation checks passed")
        return True

def extract_ml_features(pulses_df, indicators_df, ts, fetch_date):
    """Extract features for machine learning"""
    print("\n🤖 Extracting ML features...")
    
    ml_features = []
    
    for _, pulse in pulses_df.iterrows():
        # Get indicators for this pulse
        pulse_indicators = indicators_df[indicators_df['pulse_id'] == pulse['pulse_id']]
        
        # Calculate pulse age
        try:
            pulse_age_hours = (datetime.utcnow() - pd.to_datetime(pulse['created_date'])).total_seconds() / 3600
        except:
            pulse_age_hours = 0
        
        features = {
            'pulse_id': pulse['pulse_id'],
            'pulse_name': pulse['pulse_name'],
            'indicator_count': pulse['indicator_count'],
            'tlp_level': {'white': 0, 'green': 1, 'amber': 2, 'red': 3}.get(pulse['tlp'], 0),
            'tlp': pulse['tlp'],
            'has_adversary': int(pulse['adversary'] != ''),
            'adversary': pulse['adversary'],
            'has_malware': int(pulse['malware_families'] != ''),
            'malware_families': pulse['malware_families'],
            'tag_count': len(pulse['tags'].split(',')) if pulse['tags'] else 0,
            'reference_count': len(pulse['references'].split(',')) if pulse['references'] else 0,
            'attack_ids_count': len(pulse['attack_ids'].split(',')) if pulse['attack_ids'] else 0,
            'pulse_age_hours': round(pulse_age_hours, 2),
            
            # Indicator type distribution
            'ip_count': len(pulse_indicators[pulse_indicators['indicator_type'].str.contains('IP', na=False)]),
            'domain_count': len(pulse_indicators[pulse_indicators['indicator_type'].str.contains('domain', na=False)]),
            'hash_count': len(pulse_indicators[pulse_indicators['indicator_type'].str.contains('Hash', na=False)]),
            'url_count': len(pulse_indicators[pulse_indicators['indicator_type'] == 'URL']),
            'file_count': len(pulse_indicators[pulse_indicators['indicator_type'].str.contains('File', na=False)]),
            
            # Labels for supervised learning
            'threat_level': {'white': 0, 'green': 1, 'amber': 2, 'red': 3}.get(pulse['tlp'], 0),
            'requires_action': int(pulse['tlp'] in ['red', 'amber']),
            'is_high_priority': int(pulse['tlp'] == 'red' or (pulse['tlp'] == 'amber' and pulse['adversary'] != '')),
            
            'created_date': pulse['created_date'],
            'fetch_timestamp': fetch_date
        }
        
        ml_features.append(features)
    
    ml_df = pd.DataFrame(ml_features)
    ml_csv = f"out/cti_ml_features_{ts}.csv"
    ml_df.to_csv(ml_csv, index=False)
    print(f"✅ Saved ML features: {ml_csv} | rows={len(ml_df)}")
    
    return ml_df

def prepare_ml_training_data(ml_features_df, pulses_df, ts, fetch_date):
    """Prepare combined dataset for ML training"""
    print("\n📦 Preparing ML training package...")
    
    ml_training_data = {
        "metadata": {
            "collection_timestamp": fetch_date,
            "dataset_version": "1.0",
            "total_samples": len(pulses_df),
            "feature_count": len(ml_features_df.columns) - 3  # Exclude metadata columns
        },
        "features": ml_features_df.to_dict('records'),
        "statistics": {
            "threat_distribution": pulses_df['tlp'].value_counts().to_dict() if len(pulses_df) > 0 else {},
            "avg_indicators_per_pulse": round(ml_features_df['indicator_count'].mean(), 2) if len(ml_features_df) > 0 else 0,
            "adversary_count": len(pulses_df[pulses_df['adversary'] != '']),
            "malware_families_count": len(set(pulses_df['malware_families'].str.split(',').sum()))
        },
        "label_distribution": {
            "requires_action": int(ml_features_df['requires_action'].sum()) if len(ml_features_df) > 0 else 0,
            "monitoring_only": int((ml_features_df['requires_action'] == 0).sum()) if len(ml_features_df) > 0 else 0
        }
    }
    
    ml_json = f"out/ml_training_data_{ts}.json"
    with open(ml_json, "w") as f:
        json.dump(ml_training_data, f, indent=2)
    
    print(f"✅ ML training package: {ml_json}")
    return ml_training_data

def save_collection_metrics(pulses_df, indicators_df, fetch_date):
    """Save metrics about data collection"""
    print("\n📈 Saving collection metrics...")
    
    execution_time = (datetime.utcnow() - start_time).total_seconds()
    
    metrics = {
        "timestamp": fetch_date,
        "execution_time_seconds": round(execution_time, 2),
        "pulses_collected": len(pulses_df),
        "indicators_collected": len(indicators_df),
        "unique_adversaries": int(pulses_df[pulses_df['adversary'] != '']['adversary'].nunique()) if len(pulses_df) > 0 else 0,
        "unique_indicator_types": int(indicators_df['indicator_type'].nunique()) if len(indicators_df) > 0 else 0,
        "tlp_distribution": {k: int(v) for k, v in pulses_df['tlp'].value_counts().to_dict().items()} if len(pulses_df) > 0 else {},
        "avg_indicators_per_pulse": round(len(indicators_df) / max(len(pulses_df), 1), 2)
    }
    
    # Append to metrics log (JSONL format)
    metrics_file = "out/collection_metrics.jsonl"
    with open(metrics_file, "a") as f:
        f.write(json.dumps(metrics) + "\n")
    
    print(f"✅ Metrics appended to {metrics_file}")
    return metrics

def create_latest_links():
    """Create 'latest' copies of the most recent files for easy access"""
    print("\n🔗 Creating latest file links...")
    
    file_mappings = {
        "out/cti_pulses_*.csv": "out/cti_pulses_latest.csv",
        "out/cti_indicators_*.csv": "out/cti_indicators_latest.csv", 
        "out/cti_summary_*.json": "out/cti_summary_latest.json",
        "out/cti_grafana_*.json": "out/cti_grafana_latest.json",
        "out/cti_raw_*.json": "out/cti_raw_latest.json",
        "out/cti_ml_features_*.csv": "out/cti_ml_features_latest.csv",
        "out/ml_training_data_*.json": "out/ml_training_data_latest.json"
    }
    
    for pattern, latest_name in file_mappings.items():
        files = glob.glob(pattern)
        if files:
            latest_file = max(files, key=os.path.getmtime)
            try:
                shutil.copy2(latest_file, latest_name)
                print(f"   Created: {latest_name}")
            except Exception as e:
                print(f"   ⚠️  Could not create {latest_name}: {e}")

# ============================================================================
# MAIN EXECUTION
# ============================================================================

# Load environment variables from .env file if present
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

# Fetch data with error handling
print("Fetching CTI data from AlienVault OTX...")
try:
    r = requests.get(url, headers=headers, timeout=45)
    r.raise_for_status()
    data = r.json()
    print(f"✅ Fetched {len(data.get('results', []))} pulses from OTX API")
except requests.exceptions.HTTPError as e:
    print(f"⚠️  API Error: {e.response.status_code}")
    print("Using empty dataset for this run.")
    data = {"results": []}
except Exception as e:
    print(f"⚠️  Unexpected error: {e}")
    print("Using empty dataset for this run.")
    data = {"results": []}

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
        "tlp": pulse.get("tlp") or "white",
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
    tlp = pulse.get("tlp") or "white"
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

# Validate data
data_valid = validate_data(pulses_df, indicators_df)

# ============================================================================
# 3. ML FEATURES - Extract features for machine learning
# ============================================================================
if len(pulses_df) > 0 and len(indicators_df) > 0:
    ml_features_df = extract_ml_features(pulses_df, indicators_df, ts, fetch_date)
    ml_training_data = prepare_ml_training_data(ml_features_df, pulses_df, ts, fetch_date)
else:
    print("\n⚠️  Skipping ML feature extraction (no data)")
    ml_features_df = pd.DataFrame()

# ============================================================================
# 4. SUMMARY STATISTICS - Aggregated metrics for dashboards
# ============================================================================
summary = {
    "fetch_timestamp": fetch_date,
    "total_pulses": len(pulses_df),
    "total_indicators": len(indicators_df),
    "indicator_types": indicators_df["indicator_type"].value_counts().to_dict() if len(indicators_df) > 0 else {},
    "tlp_distribution": pulses_df["tlp"].value_counts().to_dict() if len(pulses_df) > 0 else {},
    "top_adversaries": pulses_df[pulses_df["adversary"] != ""]["adversary"].value_counts().head(10).to_dict() if len(pulses_df) > 0 else {},
    "severity_distribution": indicators_df["severity"].value_counts().to_dict() if len(indicators_df) > 0 else {},
    "malware_families": list(set([mf for mf in ",".join(pulses_df["malware_families"]).split(",") if mf])),
    "attack_ids": list(set([aid for aid in ",".join(pulses_df["attack_ids"]).split(",") if aid]))
}

summary_json = f"out/cti_summary_{ts}.json"
with open(summary_json, "w") as f:
    json.dump(summary, f, indent=2)
print(f"✅ Saved summary: {summary_json}")

# ============================================================================
# 5. GRAFANA-READY JSON - Time-series data format
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
    "recent_pulses": pulses_df.sort_values("created_date", ascending=False).head(10).to_dict("records") if len(pulses_df) > 0 else []
}

grafana_json = f"out/cti_grafana_{ts}.json"
with open(grafana_json, "w") as f:
    json.dump(grafana_data, f, indent=2)
print(f"✅ Saved Grafana-ready data: {grafana_json}")

# ============================================================================
# 6. FULL RAW JSON - Complete API response for reference
# ============================================================================
raw_json = f"out/cti_raw_{ts}.json"
with open(raw_json, "w") as f:
    json.dump(data, f, indent=2)
print(f"✅ Saved raw JSON: {raw_json}")

# Save collection metrics
metrics = save_collection_metrics(pulses_df, indicators_df, fetch_date)

# Create latest file links for easy access
create_latest_links()

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "="*70)
print("✅ CTI DATA COLLECTION COMPLETE!")
print("="*70)
print(f"📊 Summary:")
print(f"   • Execution time: {metrics['execution_time_seconds']}s")
print(f"   • Pulses: {len(pulses_df)}")
print(f"   • Indicators: {len(indicators_df)}")
print(f"   • ML Features: {len(ml_features_df)} samples" if len(ml_features_df) > 0 else "   • ML Features: 0 samples (no data)")
print(f"   • Indicator types: {len(indicators_df['indicator_type'].unique()) if len(indicators_df) > 0 else 0}")
print(f"   • TLP levels: {', '.join(pulses_df['tlp'].unique())}" if len(pulses_df) > 0 else "   • TLP levels: none")
print(f"   • Adversaries: {metrics['unique_adversaries']}")
print(f"\n📁 Output files:")
print(f"   • CTI data: out/cti_*_latest.*")
print(f"   • ML features: out/cti_ml_features_latest.csv")
print(f"   • Training data: out/ml_training_data_latest.json")
print(f"   • Metrics log: out/collection_metrics.jsonl")
print("="*70)