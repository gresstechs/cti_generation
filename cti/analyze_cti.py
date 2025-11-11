#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import numpy as np
from collections import Counter
import glob
import os

# Find and load the most recent CSV
csv_files = glob.glob("out/otx_indicators_*.csv")
if not csv_files:
    print("❌ No CTI data files found. Please run otx_fetch.py first.")
    exit(1)

latest_csv = max(csv_files, key=os.path.getctime)
print(f"📁 Loading latest CTI data: {latest_csv}")

df = pd.read_csv(latest_csv)
print("✅ Data loaded:", df.shape, "records")

# Convert datetime columns
df['indicator_created'] = pd.to_datetime(df['indicator_created'], errors='coerce')
df['pulse_created'] = pd.to_datetime(df['pulse_created'], errors='coerce')

# --- Enhanced Quick Overview ---
print("\n" + "="*60)
print("🔍 ENHANCED CTI ANALYSIS OVERVIEW")
print("="*60)

print(f"\n📊 Dataset Summary:")
print(f"  Total Indicators: {len(df):,}")
print(f"  Unique Pulses: {df['pulse_name'].nunique():,}")
print(f"  Unique Authors: {df['author'].nunique():,}")
print(f"  Date Range: {df['indicator_created'].min()} to {df['indicator_created'].max()}")

# 1. Enhanced Indicator Type Analysis
print(f"\n🎯 Top Indicator Types:")
top_types = df['indicator_type'].value_counts().head(10)
for idx, (ioc_type, count) in enumerate(top_types.items(), 1):
    percentage = (count / len(df)) * 100
    print(f"  {idx:2d}. {ioc_type:15s}: {count:,} ({percentage:.1f}%)")

# 2. Threat Actor Analysis
print(f"\n👤 Top Threat Actors by Activity:")
author_stats = df.groupby('author').agg({
    'indicator': 'count',
    'pulse_name': 'nunique',
    'indicator_type': lambda x: Counter(x).most_common(1)[0][0]
}).sort_values('indicator', ascending=False).head(10)

for idx, (author, stats) in enumerate(author_stats.iterrows(), 1):
    print(f"  {idx:2d}. {author:25s}: {stats['indicator']:,} indicators, {stats['pulse_name']} pulses, top type: {stats['indicator_type']}")

# 3. Enhanced TLP Analysis
print(f"\n🔒 TLP (Traffic Light Protocol) Distribution:")
tlp_counts = df['tlp'].value_counts()
for tlp, count in tlp_counts.items():
    percentage = (count / len(df)) * 100
    print(f"  {tlp:10s}: {count:,} ({percentage:.1f}%)")

# 4. Temporal Analysis
print(f"\n📅 Temporal Patterns:")
if not df['indicator_created'].isna().all():
    # Recent activity (last 30 days)
    recent_df = df[df['indicator_created'] >= datetime.now() - timedelta(days=30)]
    print(f"  Recent activity (30 days): {len(recent_df):,} indicators")
    
    # Daily trends
    daily_trends = df.groupby(df['indicator_created'].dt.date).size()
    if len(daily_trends) > 1:
        avg_daily = daily_trends.mean()
        max_daily = daily_trends.max()
        max_date = daily_trends.idxmax()
        print(f"  Average daily indicators: {avg_daily:.1f}")
        print(f"  Peak activity: {max_daily} indicators on {max_date}")
    
    # Weekly patterns
    df['day_of_week'] = df['indicator_created'].dt.day_name()
    weekly_pattern = df['day_of_week'].value_counts()
    most_active_day = weekly_pattern.index[0]
    print(f"  Most active day: {most_active_day} ({weekly_pattern.iloc[0]} indicators)")

# 5. Tag Analysis
print(f"\n🏷️  Top Threat Tags:")
all_tags = df['tags'].fillna('').str.split(',').explode().str.strip()
tag_counts = all_tags[all_tags != ''].value_counts().head(15)
for idx, (tag, count) in enumerate(tag_counts.items(), 1):
    print(f"  {idx:2d}. {tag:20s}: {count:,}")

# 6. Infrastructure Analysis
print(f"\n🌐 Infrastructure Indicators:")
ip_count = len(df[df['indicator_type'].isin(['IPv4', 'IPv6'])])
domain_count = len(df[df['indicator_type'] == 'domain'])
url_count = len(df[df['indicator_type'] == 'URL'])
hash_count = len(df[df['indicator_type'].isin(['MD5', 'SHA1', 'SHA256'])])

print(f"  IP Addresses: {ip_count:,}")
print(f"  Domains: {domain_count:,}")
print(f"  URLs: {url_count:,}")
print(f"  File Hashes: {hash_count:,}")

# 7. Pulse Analysis
print(f"\n📡 Pulse Intelligence:")
pulse_stats = df.groupby('pulse_name').agg({
    'indicator': 'count',
    'indicator_type': lambda x: len(set(x)),
    'author': 'first',
    'pulse_created': 'first'
}).sort_values('indicator', ascending=False)

print(f"  Top 5 Most Comprehensive Pulses:")
for idx, (pulse_name, stats) in enumerate(pulse_stats.head(5).iterrows(), 1):
    print(f"    {idx}. {pulse_name[:50]}{('...' if len(pulse_name) > 50 else '')}")
    print(f"       Author: {stats['author']}, Indicators: {stats['indicator']}, Types: {stats['indicator_type']}")

# 8. Advanced Threat Hunting Insights
print(f"\n🔍 Threat Hunting Insights:")

# Find indicators with multiple types (potential false positives or IOC evolution)
indicator_type_variety = df.groupby('indicator')['indicator_type'].nunique()
multi_type_indicators = indicator_type_variety[indicator_type_variety > 1]
if len(multi_type_indicators) > 0:
    print(f"  Indicators with multiple types: {len(multi_type_indicators)} (potential IOC evolution)")

# Find prolific pulses (potentially automated/bulk uploads)
prolific_pulses = pulse_stats[pulse_stats['indicator'] > pulse_stats['indicator'].quantile(0.95)]
print(f"  High-volume pulses (95th percentile): {len(prolific_pulses)}")

# Recent surge detection
if len(recent_df) > 0:
    recent_daily = recent_df.groupby(recent_df['indicator_created'].dt.date).size()
    if len(recent_daily) > 7:  # Need at least a week of data
        recent_avg = recent_daily.mean()
        recent_max = recent_daily.max()
        if recent_max > recent_avg * 2:  # Significant spike
            spike_date = recent_daily.idxmax()
            print(f"  Recent activity spike detected: {recent_max} indicators on {spike_date} (avg: {recent_avg:.1f})")

# 9. Generate Summary Statistics
print(f"\n📈 SUMMARY STATISTICS")
print("="*30)
print(f"Data Quality Score: {((len(df) - df.isnull().sum().sum()) / (len(df) * len(df.columns))) * 100:.1f}%")
print(f"Threat Diversity Index: {df['indicator_type'].nunique()} types across {df['author'].nunique()} sources")
print(f"Coverage Period: {(df['indicator_created'].max() - df['indicator_created'].min()).days} days")

# 10. Generate Simple Visualization
plt.style.use('default')
fig, axes = plt.subplots(2, 2, figsize=(12, 10))
fig.suptitle('CTI Analysis Dashboard', fontsize=14, fontweight='bold')

# Plot 1: Daily trends
if len(daily_trends) > 1:
    axes[0, 0].plot(daily_trends.index, daily_trends.values, marker='o', linewidth=2, markersize=4)
    axes[0, 0].set_title('Daily Threat Activity')
    axes[0, 0].set_xlabel('Date')
    axes[0, 0].set_ylabel('Indicators')
    axes[0, 0].tick_params(axis='x', rotation=45)

# Plot 2: Indicator types
top_types_plot = top_types.head(8)
axes[0, 1].pie(top_types_plot.values, labels=top_types_plot.index, autopct='%1.1f%%', startangle=90)
axes[0, 1].set_title('Indicator Types')

# Plot 3: TLP distribution
axes[1, 0].bar(tlp_counts.index, tlp_counts.values, color=['red', 'amber', 'green', 'white'])
axes[1, 0].set_title('TLP Distribution')
axes[1, 0].set_xlabel('TLP Level')
axes[1, 0].set_ylabel('Count')

# Plot 4: Top authors
top_authors = author_stats.head(10)['indicator']
axes[1, 1].barh(range(len(top_authors)), top_authors.values)
axes[1, 1].set_yticks(range(len(top_authors)))
axes[1, 1].set_yticklabels([author[:20] + '...' if len(author) > 20 else author for author in top_authors.index])
axes[1, 1].set_title('Top Authors by Indicators')
axes[1, 1].set_xlabel('Indicator Count')

plt.tight_layout()

# Save visualization
timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
viz_path = f"out/cti_analysis_{timestamp}.png"
plt.savefig(viz_path, dpi=300, bbox_inches='tight')
print(f"\n📊 Analysis dashboard saved: {viz_path}")
plt.close()

print(f"\n✅ Enhanced CTI analysis complete!")
print(f"📈 Analyzed {len(df):,} indicators from {df['pulse_name'].nunique():,} pulses")
print(f"🎯 Key findings: {top_types.index[0]} is the most common indicator type ({top_types.iloc[0]:,} instances)")
print(f"👤 Most active author: {author_stats.index[0]} ({author_stats.iloc[0]['indicator']:,} indicators)")
 