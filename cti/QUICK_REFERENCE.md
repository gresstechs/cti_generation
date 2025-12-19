# MTTR Pipeline - Quick Reference

## Daily Usage

### Local Development (Windows)
```bash
cd cti

# Full pipeline (fetch + predict + calculate)
python run_mttr_pipeline.py

# Skip OTX fetch (faster, recommended for frequent runs)
python run_mttr_pipeline.py --skip-fetch

# Just recalculate MTTR (data already exists)
python run_mttr_pipeline.py --mttr-only
```

### AWS/Linux Production
```bash
# Set environment variable first
export GRAFANA_CSV_DIR=/var/lib/grafana/csv

# Run pipeline
cd /path/to/cti
python3 run_mttr_pipeline.py
```

## Individual Scripts

```bash
# 1. Fetch threat intelligence
python otx_fetch.py

# 2. Run ML predictions
python predict_otx_with_andmal.py

# 3. Convert to MTTR format (appends new threats)
python convert_threats_for_mttr.py

# 4. Calculate MTTR metrics
python calculate_mttr.py
```

## Automation

### Cron (Every 6 hours)
```bash
crontab -e

# Add:
0 */6 * * * cd /path/to/cti && python3 run_mttr_pipeline.py --skip-fetch >> /var/log/mttr.log 2>&1
```

### Jenkins (Recommended)
- Create pipeline job
- Set trigger: `H */6 * * *` (every 6 hours)
- Shell: `python3 cti/run_mttr_pipeline.py`

## File Locations

| File | Purpose | Location |
|------|---------|----------|
| `classified_threats.csv` | **Dynamic threat database** (grows over time) | `cti/` |
| `mttr_metrics.csv` | Current MTTR snapshot | `out/grafana_csv/` |
| `mttr_history.csv` | MTTR trend data (time-series) | `out/grafana_csv/` |
| `mttr_by_severity.csv` | MTTR by severity breakdown | `out/grafana_csv/` |

## How Data Accumulates

```
Run 1: 5 threats   → classified_threats.csv has 5 entries
Run 2: 3 new       → classified_threats.csv has 8 entries (5 + 3)
Run 3: 0 new       → classified_threats.csv has 8 entries (no change)
Run 4: 10 new      → classified_threats.csv has 18 entries (8 + 10)
```

**Duplicate Detection**: Uses `threat_id` (pulse_id) to skip duplicates automatically

## Key Metrics

- **Baseline MTTR**: 7.0 hours (manual process)
- **Target MTTR**: < 0.1 hours (6 minutes with automation)
- **Expected Improvement**: 95-99% reduction

## Troubleshooting

### No new threats being added
```bash
# Check predictions file date
ls -lh ../out/otx_andmal_predictions.csv

# Re-run prediction
python predict_otx_with_andmal.py
```

### Grafana not showing data
```bash
# Check files exist
ls -lh $GRAFANA_CSV_DIR/

# Fix permissions
sudo chown grafana:grafana $GRAFANA_CSV_DIR/*.csv
sudo chmod 644 $GRAFANA_CSV_DIR/*.csv
```

### View current stats
```bash
# Total threats tracked
wc -l cti/classified_threats.csv

# Latest MTTR
tail -1 out/grafana_csv/mttr_history.csv

# MTTR by severity
cat out/grafana_csv/mttr_by_severity.csv
```

## Grafana Queries

### Current MTTR (Stat Panel)
- Data source: CSV
- File: `mttr_metrics.csv`
- Field: `current_mttr_hours`
- Unit: hours
- Decimals: 2

### MTTR Trend (Time Series)
- Data source: CSV
- File: `mttr_history.csv`
- X-axis: `timestamp`
- Y-axis: `current_mttr_hours`
- Transform: Add baseline field = 7.0

### Improvement % (Stat Panel)
- Data source: CSV
- File: `mttr_metrics.csv`
- Field: `reduction_percent`
- Unit: percent
- Color: Green threshold > 90%

## Environment Variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `GRAFANA_CSV_DIR` | `../out/grafana_csv` | Output location for CSV files |
| `OTX_API_KEY` | (from config) | AlienVault OTX API key |

## Workflow Summary

```mermaid
graph LR
    A[OTX Fetch] --> B[ML Predict]
    B --> C[Convert & Append]
    C --> D[Calculate MTTR]
    D --> E[Grafana CSV]
    E --> F[Dashboard]
```

1. **Fetch**: Get latest threats from OTX
2. **Predict**: ML model classifies threats
3. **Convert**: Append new threats to database
4. **Calculate**: Compute MTTR metrics
5. **Export**: Generate Grafana CSV files
6. **Visualize**: Display in dashboard

## Expected Timeline

| Time | Action | Result |
|------|--------|--------|
| Day 1 | Initial run | Baseline established |
| Week 1 | Daily runs | Trend becomes visible |
| Month 1 | Continuous tracking | Clear improvement metrics |
| Month 3 | Historical data | Comprehensive analysis |

## Support Checklist

Before asking for help:
- [ ] Check log files
- [ ] Verify input files exist
- [ ] Confirm environment variables set
- [ ] Test individual scripts
- [ ] Check file permissions
- [ ] Verify Grafana data source config
