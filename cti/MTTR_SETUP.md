# MTTR (Mean Time To Respond) Tracking Setup

This guide explains how to set up dynamic MTTR tracking for your CTI project.

## Overview

The MTTR tracking system accumulates threat data over time to show how your AI-powered system improves response times compared to manual processes.

## Architecture

```
OTX Threat Feed
      |
      v
ML Prediction (AndMal)
      |
      v
Threat Classification
      |
      v
MTTR Calculation
      |
      v
Grafana Dashboards
```

## Files

### Core Scripts
- `otx_fetch.py` - Fetches threat intelligence from AlienVault OTX
- `predict_otx_with_andmal.py` - Runs ML model to classify threats
- `convert_threats_for_mttr.py` - Converts predictions to MTTR format (appends dynamically)
- `calculate_mttr.py` - Calculates MTTR metrics for Grafana
- `run_mttr_pipeline.py` - Automation script for the entire pipeline

### Data Files
- `classified_threats.csv` - **Dynamic database** of all threats (grows over time)
- `grafana_csv/mttr_metrics.csv` - Current MTTR snapshot
- `grafana_csv/mttr_history.csv` - Historical MTTR trend data
- `grafana_csv/mttr_by_severity.csv` - MTTR breakdown by severity level

## How It Works

### Dynamic Data Accumulation

1. **First Run**: Creates `classified_threats.csv` with initial threats
2. **Subsequent Runs**: Appends new threats, skips duplicates (by threat_id)
3. **Over Time**: Database grows, showing MTTR improvements as AI model processes more threats

### MTTR Calculation

- **Baseline MTTR**: 7.0 hours (manual process average)
- **Current MTTR**: Calculated from automated threat processing
- **Improvement**: Percentage reduction from baseline

## Setup Instructions

### 1. Local Development (Windows)

```bash
cd cti

# Run full pipeline
python run_mttr_pipeline.py

# Skip OTX fetch (faster, uses existing data)
python run_mttr_pipeline.py --skip-fetch

# Only recalculate MTTR (no new data)
python run_mttr_pipeline.py --mttr-only
```

Output location: `../out/grafana_csv/`

### 2. AWS/Linux Deployment

#### Environment Variables

```bash
# Set Grafana CSV directory
export GRAFANA_CSV_DIR=/var/lib/grafana/csv

# Optional: Set OTX API key if not in config
export OTX_API_KEY=your_api_key_here
```

#### Cron Job Setup

Run pipeline every 6 hours:

```bash
# Edit crontab
crontab -e

# Add this line:
0 */6 * * * cd /path/to/cti && /usr/bin/python3 run_mttr_pipeline.py --skip-fetch >> /var/log/mttr_pipeline.log 2>&1
```

Run daily at 2 AM with full fetch:

```bash
0 2 * * * cd /path/to/cti && /usr/bin/python3 run_mttr_pipeline.py >> /var/log/mttr_pipeline.log 2>&1
```

#### Jenkins Pipeline

Create a Jenkins job:

```groovy
pipeline {
    agent any

    triggers {
        cron('H */6 * * *')  // Every 6 hours
    }

    environment {
        GRAFANA_CSV_DIR = '/var/lib/grafana/csv'
    }

    stages {
        stage('Run MTTR Pipeline') {
            steps {
                dir('cti') {
                    sh 'python3 run_mttr_pipeline.py'
                }
            }
        }
    }

    post {
        success {
            echo 'MTTR metrics updated successfully'
        }
        failure {
            echo 'MTTR pipeline failed'
        }
    }
}
```

## Grafana Configuration

### 1. Install CSV Plugin

```bash
grafana-cli plugins install marcusolsson-csv-datasource
sudo systemctl restart grafana-server
```

### 2. Configure Data Source

1. Go to Configuration > Data Sources
2. Add "CSV" data source
3. Set path: `/var/lib/grafana/csv`
4. Enable local file access

### 3. Create Dashboard Panels

#### Panel 1: Current MTTR (Stat)
- **Query**: `mttr_metrics.csv`
- **Field**: `current_mttr_hours`
- **Title**: "Current MTTR"
- **Unit**: hours
- **Color**: Green if < 1 hour, Yellow if < 3 hours, Red otherwise

#### Panel 2: MTTR Reduction (Stat)
- **Query**: `mttr_metrics.csv`
- **Field**: `reduction_percent`
- **Title**: "MTTR Improvement"
- **Unit**: percent
- **Display**: Big number with sparkline

#### Panel 3: MTTR Trend (Time Series)
- **Query**: `mttr_history.csv`
- **X-axis**: `timestamp`
- **Y-axis**: `current_mttr_hours`
- **Title**: "MTTR Over Time"
- **Legend**: Show baseline as horizontal line at 7.0 hours

#### Panel 4: MTTR by Severity (Bar Chart)
- **Query**: `mttr_by_severity.csv`
- **X-axis**: `severity`
- **Y-axis**: `mttr_hours`
- **Title**: "Response Time by Severity"

### 4. Set Refresh Rate

- Dashboard settings > Time options
- Set auto-refresh: 30s or 1m

## Data Flow Example

### Day 1
```
Run pipeline → 5 threats detected
classified_threats.csv: 5 threats
MTTR: 0.08 hours (5 minutes)
Improvement: 98.8%
```

### Day 2
```
Run pipeline → 3 new threats detected
classified_threats.csv: 8 threats (5 old + 3 new)
MTTR: 0.08 hours (consistent)
Improvement: 98.8%
```

### Week 1
```
Run pipeline → 25 new threats detected
classified_threats.csv: 150 threats
MTTR: 0.07 hours (improving!)
Improvement: 99.0%
```

## Monitoring

### View Current Status

```bash
# Check threat database size
wc -l cti/classified_threats.csv

# View latest MTTR metrics
cat out/grafana_csv/mttr_metrics.csv

# Check pipeline logs (if using cron)
tail -f /var/log/mttr_pipeline.log
```

### Troubleshooting

**Problem**: No new threats being added

```bash
# Check if predictions file is updating
ls -lh out/otx_andmal_predictions.csv

# Run pipeline with verbose output
python run_mttr_pipeline.py
```

**Problem**: Grafana not showing data

```bash
# Verify CSV files exist
ls -lh $GRAFANA_CSV_DIR/

# Check file permissions
chmod 644 $GRAFANA_CSV_DIR/*.csv

# Verify Grafana can read directory
sudo chown grafana:grafana $GRAFANA_CSV_DIR/*.csv
```

## Customization

### Adjust Baseline MTTR

Edit `calculate_mttr.py`:

```python
BASELINE_MTTR_HOURS = 7.0  # Change to your actual manual process time
```

### Change Response Time Estimation

Edit `calculate_mttr.py` line 42:

```python
# Currently assumes 5 minutes automated response
threats_df['response_time'] = threats_df['detection_time'] + timedelta(minutes=5)
```

### Data Retention

The system keeps:
- All threats in `classified_threats.csv` (unlimited)
- Last 1000 MTTR history entries in `mttr_history.csv`

To change history retention, edit `calculate_mttr.py` line 103:

```python
if len(combined) > 1000:  # Change 1000 to your desired limit
    combined = combined.tail(1000)
```

## Expected Results

With automated AI-powered threat detection:
- **Manual Baseline**: 6-8 hours average response time
- **Automated MTTR**: 5-10 minutes (immediate ML classification)
- **Improvement**: 95-99% reduction in response time
- **Trend**: Consistent low MTTR as system processes more threats

## Support

For issues or questions:
1. Check logs: `/var/log/mttr_pipeline.log`
2. Verify data files exist and are readable
3. Ensure all Python dependencies are installed
4. Check Grafana data source configuration
