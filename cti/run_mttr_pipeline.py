#!/usr/bin/env python3
"""
MTTR Pipeline Automation
Runs the complete workflow: Fetch -> Predict -> Convert -> Calculate MTTR

Usage:
  python run_mttr_pipeline.py              # Run full pipeline
  python run_mttr_pipeline.py --skip-fetch # Skip OTX fetch (use existing data)
  python run_mttr_pipeline.py --mttr-only  # Only calculate MTTR from existing data
"""

import subprocess
import sys
import os
from datetime import datetime
import argparse

def run_command(script_name, description):
    """Run a Python script and return success status"""
    print("\n" + "=" * 70)
    print(f"STEP: {description}")
    print("=" * 70)

    try:
        result = subprocess.run(
            [sys.executable, script_name],
            check=True,
            capture_output=False,
            text=True
        )
        print(f"SUCCESS: {description} completed")
        return True
    except subprocess.CalledProcessError as e:
        print(f"ERROR: {description} failed with exit code {e.returncode}")
        return False
    except FileNotFoundError:
        print(f"ERROR: Script not found: {script_name}")
        return False

def main():
    parser = argparse.ArgumentParser(description='Run MTTR calculation pipeline')
    parser.add_argument('--skip-fetch', action='store_true',
                        help='Skip OTX data fetching (use existing predictions)')
    parser.add_argument('--mttr-only', action='store_true',
                        help='Only calculate MTTR from existing classified threats')
    args = parser.parse_args()

    print("=" * 70)
    print("MTTR CALCULATION PIPELINE")
    print("=" * 70)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    steps_completed = 0
    total_steps = 0

    # Step 1: Fetch OTX data (optional)
    if not args.skip_fetch and not args.mttr_only:
        total_steps += 1
        if run_command('otx_fetch.py', 'Fetch threat intelligence from OTX'):
            steps_completed += 1
        else:
            print("\nWARNING: OTX fetch failed, continuing with existing data...")

    # Step 2: Run ML predictions (optional)
    if not args.mttr_only:
        total_steps += 1
        if run_command('predict_otx_with_andmal.py', 'Predict threats with ML model'):
            steps_completed += 1
        else:
            print("\nERROR: ML prediction failed. Cannot continue.")
            sys.exit(1)

    # Step 3: Convert to MTTR format (optional)
    if not args.mttr_only:
        total_steps += 1
        if run_command('convert_threats_for_mttr.py', 'Convert predictions to MTTR format'):
            steps_completed += 1
        else:
            print("\nERROR: Conversion failed. Cannot continue.")
            sys.exit(1)

    # Step 4: Calculate MTTR metrics
    total_steps += 1
    if run_command('calculate_mttr.py', 'Calculate MTTR metrics for Grafana'):
        steps_completed += 1
    else:
        print("\nERROR: MTTR calculation failed.")
        sys.exit(1)

    # Summary
    print("\n" + "=" * 70)
    print("PIPELINE SUMMARY")
    print("=" * 70)
    print(f"Completed: {steps_completed}/{total_steps} steps")
    print(f"Status: {'SUCCESS' if steps_completed == total_steps else 'PARTIAL'}")
    print(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 70)

    if steps_completed == total_steps:
        print("\nMTTR metrics are ready for Grafana!")
        print("\nGrafana CSV files location:")
        csv_dir = os.getenv('GRAFANA_CSV_DIR', '../out/grafana_csv')
        print(f"  {csv_dir}/")
        print("    - mttr_metrics.csv")
        print("    - mttr_history.csv")
        print("    - mttr_by_severity.csv")
    else:
        sys.exit(1)

if __name__ == '__main__':
    main()
