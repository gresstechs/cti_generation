#!/usr/bin/env python3
"""
MTTR Calculator for CTI Project
Calculates Mean Time To Respond and exports to Grafana CSV

Usage: python calculate_mttr.py
"""

import pandas as pd
from datetime import datetime, timedelta
import os

# Configuration
# Can be overridden with environment variable: GRAFANA_CSV_DIR
CSV_OUTPUT_DIR = os.getenv('GRAFANA_CSV_DIR', '../out/grafana_csv')
THREATS_INPUT = 'classified_threats.csv'  # Your threat data
MTTR_OUTPUT = os.path.join(CSV_OUTPUT_DIR, 'mttr_metrics.csv')
MTTR_HISTORY = os.path.join(CSV_OUTPUT_DIR, 'mttr_history.csv')
MTTR_BY_SEVERITY = os.path.join(CSV_OUTPUT_DIR, 'mttr_by_severity.csv')

# Ensure output directory exists
os.makedirs(CSV_OUTPUT_DIR, exist_ok=True)

# Baseline (pre-automation) - adjust these to your actual values
BASELINE_MTTR_HOURS = 7.0  # Average of 6-8 hours manual process

def calculate_response_duration(threats_df):
    """
    Calculate response duration for each threat
    
    Assumes:
    - detection_time column exists (when threat was detected)
    - Either response_time column exists OR we estimate based on recommendations
    """
    threats_df = threats_df.copy()
    
    # Convert detection time to datetime
    threats_df['detection_time'] = pd.to_datetime(threats_df['timestamp'])
    
    # If you have actual response_time, use it
    if 'response_time' in threats_df.columns:
        threats_df['response_time'] = pd.to_datetime(threats_df['response_time'])
    else:
        # Estimate response time based on your system
        # Automated recommendation + analyst review = ~5 minutes average
        threats_df['response_time'] = threats_df['detection_time'] + timedelta(minutes=5)
    
    # Calculate duration in hours
    threats_df['response_duration_hours'] = (
        threats_df['response_time'] - threats_df['detection_time']
    ).dt.total_seconds() / 3600
    
    return threats_df

def calculate_current_mttr(threats_df):
    """Calculate overall MTTR"""
    if len(threats_df) == 0:
        return 0.0
    
    return threats_df['response_duration_hours'].mean()

def calculate_mttr_metrics(threats_df):
    """
    Calculate comprehensive MTTR metrics
    """
    current_mttr = calculate_current_mttr(threats_df)
    
    # Calculate improvement
    reduction_hours = BASELINE_MTTR_HOURS - current_mttr
    reduction_percent = (reduction_hours / BASELINE_MTTR_HOURS) * 100 if BASELINE_MTTR_HOURS > 0 else 0
    
    # Additional statistics
    metrics = {
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'current_mttr_hours': round(current_mttr, 2),
        'baseline_mttr_hours': BASELINE_MTTR_HOURS,
        'reduction_hours': round(reduction_hours, 2),
        'reduction_percent': round(reduction_percent, 1),
        'incidents_processed': len(threats_df),
        'min_response_hours': round(threats_df['response_duration_hours'].min(), 2),
        'max_response_hours': round(threats_df['response_duration_hours'].max(), 2),
        'median_response_hours': round(threats_df['response_duration_hours'].median(), 2),
        'std_response_hours': round(threats_df['response_duration_hours'].std(), 2)
    }
    
    return metrics

def save_current_mttr(metrics):
    """Save current MTTR metrics for Grafana stat panel"""
    df = pd.DataFrame([metrics])
    df.to_csv(MTTR_OUTPUT, index=False)
    print(f"Saved current MTTR to {MTTR_OUTPUT}")
    print(f"  Current MTTR: {metrics['current_mttr_hours']} hours")
    print(f"  Baseline MTTR: {metrics['baseline_mttr_hours']} hours")
    print(f"  Reduction: {metrics['reduction_percent']}%")

def save_mttr_history(metrics):
    """Append to MTTR history for time-series trending"""
    history_entry = pd.DataFrame([metrics])

    try:
        # Try to read existing history
        existing = pd.read_csv(MTTR_HISTORY)
        combined = pd.concat([existing, history_entry], ignore_index=True)

        # Keep last 1000 entries (prevent file from growing too large)
        if len(combined) > 1000:
            combined = combined.tail(1000)

        combined.to_csv(MTTR_HISTORY, index=False)
        print(f"Appended to MTTR history: {MTTR_HISTORY}")
    except FileNotFoundError:
        # Create new file
        history_entry.to_csv(MTTR_HISTORY, index=False)
        print(f"Created new MTTR history: {MTTR_HISTORY}")

def calculate_mttr_by_severity(threats_df):
    """Calculate MTTR grouped by severity level"""
    if 'severity' not in threats_df.columns:
        print("WARNING: No severity column found, skipping severity breakdown")
        return

    # Group by severity
    severity_mttr = threats_df.groupby('severity').agg({
        'response_duration_hours': ['mean', 'count', 'min', 'max', 'median']
    }).round(2)

    # Flatten column names
    severity_mttr.columns = ['mttr_hours', 'count', 'min_hours', 'max_hours', 'median_hours']
    severity_mttr = severity_mttr.reset_index()

    # Add timestamp
    severity_mttr['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    # Save
    severity_mttr.to_csv(MTTR_BY_SEVERITY, index=False)
    print(f"Saved MTTR by severity to {MTTR_BY_SEVERITY}")
    print("\nMTTR by Severity:")
    for _, row in severity_mttr.iterrows():
        print(f"  {row['severity']}: {row['mttr_hours']} hours ({int(row['count'])} incidents)")

def main():
    """Main execution"""
    print("=" * 60)
    print("MTTR Calculator for CTI Project")
    print("=" * 60)
    
    # Check if input file exists
    if not os.path.exists(THREATS_INPUT):
        print(f"Error: Input file not found: {THREATS_INPUT}")
        print("\nExpected format:")
        print("timestamp,threat_id,severity,confidence,classification")
        print("2025-12-19 10:00:00,T001,High,0.95,Malicious")
        print("\nRun convert_threats_for_mttr.py first to generate this file.")
        return
    
    # Load threat data
    print(f"\n1. Loading threat data from {THREATS_INPUT}...")
    try:
        threats = pd.read_csv(THREATS_INPUT)
        print(f"   Loaded {len(threats)} threats")
    except Exception as e:
        print(f"Error loading data: {e}")
        return
    
    # Calculate response durations
    print("\n2. Calculating response durations...")
    threats = calculate_response_duration(threats)
    
    # Calculate MTTR metrics
    print("\n3. Calculating MTTR metrics...")
    metrics = calculate_mttr_metrics(threats)
    
    # Save current MTTR
    print("\n4. Saving current MTTR...")
    save_current_mttr(metrics)
    
    # Save historical data
    print("\n5. Updating MTTR history...")
    save_mttr_history(metrics)
    
    # Calculate by severity
    print("\n6. Calculating MTTR by severity...")
    calculate_mttr_by_severity(threats)
    
    print("\n" + "=" * 60)
    print("MTTR calculation complete!")
    print("=" * 60)
    print("\nGrafana files created:")
    print(f"  - {MTTR_OUTPUT} (current metrics)")
    print(f"  - {MTTR_HISTORY} (time-series data)")
    print(f"  - {MTTR_BY_SEVERITY} (severity breakdown)")
    print("\nNext steps:")
    print("  1. Configure Grafana CSV data source")
    print("  2. Create panels pointing to these files")
    print("  3. Set auto-refresh to 30-60 seconds")
    print("\nFor AWS deployment:")
    print(f"  Set environment variable: GRAFANA_CSV_DIR=/var/lib/grafana/csv")
    print(f"  Or copy files to Grafana: cp {CSV_OUTPUT_DIR}/*.csv /var/lib/grafana/csv/")
    print("=" * 60)

if __name__ == '__main__':
    main()
