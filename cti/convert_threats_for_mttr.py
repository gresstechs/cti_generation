#!/usr/bin/env python3
"""
Convert OTX AndMal predictions to MTTR-compatible format
Transforms out/otx_andmal_predictions.csv -> cti/classified_threats.csv
"""

import pandas as pd
import os
from datetime import datetime

# Input and output paths
INPUT_FILE = '../out/otx_andmal_predictions.csv'
OUTPUT_FILE = 'classified_threats.csv'

def main():
    print("=" * 60)
    print("Converting Threat Predictions for MTTR Calculator")
    print("=" * 60)

    # Check input file
    if not os.path.exists(INPUT_FILE):
        print(f"Error: Input file not found: {INPUT_FILE}")
        print("\nPlease run predict_otx_with_andmal.py first to generate predictions.")
        return

    # Load predictions
    print(f"\n1. Loading predictions from {INPUT_FILE}...")
    predictions = pd.read_csv(INPUT_FILE)
    print(f"   Loaded {len(predictions)} threat predictions")

    # Transform to MTTR format
    print("\n2. Transforming to MTTR format...")

    # Create classification based on malware_probability
    def classify_threat(prob):
        if prob >= 0.7:
            return "Malicious"
        elif prob >= 0.5:
            return "Suspicious"
        else:
            return "Benign"

    # Map risk_level to severity (High/Medium/Low/Critical)
    # The predictions already use CRITICAL/HIGH/MEDIUM/LOW

    new_threats = pd.DataFrame({
        'timestamp': pd.to_datetime(predictions['prediction_timestamp']).dt.strftime('%Y-%m-%d %H:%M:%S'),
        'threat_id': predictions['pulse_id'],
        'severity': predictions['risk_level'],
        'confidence': predictions['confidence'] / 100,  # Convert to 0-1 scale
        'classification': predictions['malware_probability'].apply(classify_threat)
    })

    # Append to existing data or create new file
    print(f"\n3. Appending to {OUTPUT_FILE}...")

    if os.path.exists(OUTPUT_FILE):
        # Load existing data
        existing_threats = pd.read_csv(OUTPUT_FILE)
        print(f"   Found {len(existing_threats)} existing threats")

        # Get existing threat IDs to avoid duplicates
        existing_ids = set(existing_threats['threat_id'].values)

        # Filter out duplicates (threats we've already seen)
        new_unique_threats = new_threats[~new_threats['threat_id'].isin(existing_ids)]

        if len(new_unique_threats) > 0:
            # Append new threats
            mttr_data = pd.concat([existing_threats, new_unique_threats], ignore_index=True)
            mttr_data.to_csv(OUTPUT_FILE, index=False)
            print(f"   Added {len(new_unique_threats)} new threats")
            print(f"   Skipped {len(new_threats) - len(new_unique_threats)} duplicates")
            print(f"   Total threats now: {len(mttr_data)}")
        else:
            print(f"   No new threats to add (all {len(new_threats)} already exist)")
            mttr_data = existing_threats
    else:
        # Create new file
        mttr_data = new_threats
        mttr_data.to_csv(OUTPUT_FILE, index=False)
        print(f"   Created new file with {len(mttr_data)} threats")

    # Show summary
    print("\n" + "=" * 60)
    print("Conversion Summary:")
    print("=" * 60)
    print(f"Total threats in database: {len(mttr_data)}")

    # Show time range
    mttr_data['timestamp'] = pd.to_datetime(mttr_data['timestamp'])
    earliest = mttr_data['timestamp'].min()
    latest = mttr_data['timestamp'].max()
    print(f"Time range: {earliest} to {latest}")

    print(f"\nSeverity breakdown:")
    for severity, count in mttr_data['severity'].value_counts().items():
        print(f"  {severity}: {count}")

    print(f"\nClassification breakdown:")
    for classification, count in mttr_data['classification'].value_counts().items():
        print(f"  {classification}: {count}")

    print("\n" + "=" * 60)
    print("Conversion complete!")
    print("=" * 60)
    print(f"\nYou can now run: python calculate_mttr.py")
    print("\nNote: Threats accumulate over time to track MTTR trends.")
    print("      Run this script after each prediction to update the database.")
    print("=" * 60)

if __name__ == '__main__':
    main()
