#!/usr/bin/env python3
"""
Threat Intelligence Report Generator
Generates comprehensive CTI reports in multiple formats
"""

import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime, timedelta
import json
import glob
import os
from collections import Counter, defaultdict
import numpy as np

def generate_threat_intelligence_report():
    """Generate a comprehensive threat intelligence report"""
    
    # Find latest data
    csv_files = glob.glob("out/otx_indicators_*.csv")
    if not csv_files:
        print("❌ No CTI data files found. Please run otx_fetch.py first.")
        return
    
    latest_csv = max(csv_files, key=os.path.getctime)
    df = pd.read_csv(latest_csv)
    df['indicator_created'] = pd.to_datetime(df['indicator_created'], errors='coerce')
    df['pulse_created'] = pd.to_datetime(df['pulse_created'], errors='coerce')
    
    timestamp = datetime.now().strftime("%Y%m%dT%H%M%SZ")
    
    # Generate comprehensive report
    report = {
        "report_metadata": {
            "generated_at": datetime.now().isoformat(),
            "data_source": latest_csv,
            "analysis_period": {
                "start": df['indicator_created'].min().isoformat() if not df['indicator_created'].isna().all() else None,
                "end": df['indicator_created'].max().isoformat() if not df['indicator_created'].isna().all() else None
            },
            "total_records_analyzed": len(df)
        },
        
        "executive_summary": {
            "total_indicators": len(df),
            "unique_threat_pulses": df['pulse_name'].nunique(),
            "unique_threat_actors": df['author'].nunique(),
            "primary_threat_types": df['indicator_type'].value_counts().head(5).to_dict(),
            "threat_landscape_assessment": "DYNAMIC" if len(df) > 1000 else "MODERATE",
            "key_findings": []
        },
        
        "threat_actor_intelligence": {
            "most_active_actors": df.groupby('author').agg({
                'indicator': 'count',
                'pulse_name': 'nunique',
                'indicator_type': lambda x: Counter(x).most_common(1)[0][0]
            }).sort_values('indicator', ascending=False).head(10).to_dict('index'),
            
            "actor_specializations": {},
            "emerging_threat_actors": []
        },
        
        "infrastructure_analysis": {
            "ip_addresses": {
                "total": len(df[df['indicator_type'].isin(['IPv4', 'IPv6'])]),
                "unique": df[df['indicator_type'].isin(['IPv4', 'IPv6'])]['indicator'].nunique()
            },
            "domains": {
                "total": len(df[df['indicator_type'] == 'domain']),
                "unique": df[df['indicator_type'] == 'domain']['indicator'].nunique(),
                "top_tlds": []
            },
            "urls": {
                "total": len(df[df['indicator_type'] == 'URL']),
                "unique": df[df['indicator_type'] == 'URL']['indicator'].nunique()
            },
            "file_hashes": {
                "total": len(df[df['indicator_type'].isin(['MD5', 'SHA1', 'SHA256'])]),
                "by_type": df[df['indicator_type'].isin(['MD5', 'SHA1', 'SHA256'])]['indicator_type'].value_counts().to_dict()
            }
        },
        
        "temporal_analysis": {
            "activity_patterns": {},
            "trend_analysis": {},
            "anomaly_detection": {}
        },
        
        "threat_categorization": {
            "by_indicator_type": df['indicator_type'].value_counts().to_dict(),
            "by_tlp_level": df['tlp'].value_counts().to_dict(),
            "tag_analysis": {}
        },
        
        "recommendations": {
            "immediate_actions": [],
            "monitoring_priorities": [],
            "threat_hunting_focus": []
        }
    }
    
    # Enhanced analysis
    
    # Top TLDs for domains
    domain_indicators = df[df['indicator_type'] == 'domain']['indicator']
    if len(domain_indicators) > 0:
        tlds = [domain.split('.')[-1] for domain in domain_indicators if '.' in domain]
        tld_counts = Counter(tlds).most_common(10)
        report["infrastructure_analysis"]["domains"]["top_tlds"] = dict(tld_counts)
    
    # Tag analysis
    all_tags = df['tags'].fillna('').str.split(',').explode().str.strip()
    tag_counts = all_tags[all_tags != ''].value_counts().head(20)
    report["threat_categorization"]["tag_analysis"] = tag_counts.to_dict()
    
    # Temporal patterns
    if not df['indicator_created'].isna().all():
        daily_trends = df.groupby(df['indicator_created'].dt.date).size()
        weekly_patterns = df.groupby(df['indicator_created'].dt.day_name()).size()
        
        report["temporal_analysis"]["activity_patterns"] = {
            "most_active_day": weekly_patterns.idxmax(),
            "daily_average": daily_trends.mean(),
            "peak_daily_activity": daily_trends.max()
        }
        
        # Trend analysis
        if len(daily_trends) > 7:
            recent_trend = daily_trends.tail(7).mean()
            older_trend = daily_trends.head(7).mean() if len(daily_trends) > 14 else daily_trends.mean()
            trend_direction = "increasing" if recent_trend > older_trend else "decreasing"
            report["temporal_analysis"]["trend_analysis"] = {
                "direction": trend_direction,
                "recent_average": recent_trend,
                "change_percentage": ((recent_trend - older_trend) / older_trend * 100) if older_trend > 0 else 0
            }
    
    # Generate recommendations based on data
    
    # High-volume indicator types need monitoring
    top_indicator_type = df['indicator_type'].value_counts().index[0]
    report["recommendations"]["monitoring_priorities"].append(
        f"Focus monitoring on {top_indicator_type} indicators ({df['indicator_type'].value_counts().iloc[0]} instances)"
    )
    
    # Active threat actors need attention
    most_active_actor = df.groupby('author')['indicator'].count().idxmax()
    actor_indicator_count = df.groupby('author')['indicator'].count().max()
    report["recommendations"]["immediate_actions"].append(
        f"Investigate threat actor '{most_active_actor}' ({actor_indicator_count} indicators)"
    )
    
    # TLP analysis for action items
    if 'WHITE' in df['tlp'].values:
        white_count = len(df[df['tlp'] == 'WHITE'])
        report["recommendations"]["threat_hunting_focus"].append(
            f"Leverage {white_count} TLP:WHITE indicators for proactive hunting"
        )
    
    # Add key findings
    report["executive_summary"]["key_findings"] = [
        f"Primary threat vector: {top_indicator_type} ({df['indicator_type'].value_counts().iloc[0]} indicators)",
        f"Most prolific threat actor: {most_active_actor} ({actor_indicator_count} indicators)",
        f"Data freshness: Latest indicators from {df['indicator_created'].max().strftime('%Y-%m-%d') if not df['indicator_created'].isna().all() else 'Unknown'}",
        f"Geographic scope: {df['author'].nunique()} distinct threat intelligence sources"
    ]
    
    # Save report as JSON
    report_path = f"out/threat_intelligence_report_{timestamp}.json"
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)
    
    # Generate human-readable report
    markdown_report = generate_markdown_report(report)
    markdown_path = f"out/threat_intelligence_report_{timestamp}.md"
    with open(markdown_path, 'w') as f:
        f.write(markdown_report)
    
    # Generate threat hunting queries
    hunting_queries = generate_hunting_queries(df)
    queries_path = f"out/threat_hunting_queries_{timestamp}.txt"
    with open(queries_path, 'w') as f:
        f.write(hunting_queries)
    
    print(f"📊 Comprehensive threat intelligence report generated:")
    print(f"   📄 JSON Report: {report_path}")
    print(f"   📝 Markdown Report: {markdown_path}")
    print(f"   🔍 Hunting Queries: {queries_path}")
    
    return report

def generate_markdown_report(report):
    """Generate a human-readable markdown report"""
    
    md = f"""# Threat Intelligence Analysis Report

**Generated:** {report['report_metadata']['generated_at']}  
**Data Source:** {report['report_metadata']['data_source']}  
**Analysis Period:** {report['report_metadata']['analysis_period']['start']} to {report['report_metadata']['analysis_period']['end']}

## Executive Summary

- **Total Indicators Analyzed:** {report['executive_summary']['total_indicators']:,}
- **Unique Threat Pulses:** {report['executive_summary']['unique_threat_pulses']:,}
- **Unique Threat Actors:** {report['executive_summary']['unique_threat_actors']:,}
- **Threat Landscape Assessment:** {report['executive_summary']['threat_landscape_assessment']}

### Key Findings
"""
    
    for finding in report['executive_summary']['key_findings']:
        md += f"- {finding}\n"
    
    md += f"""
## Primary Threat Types

| Indicator Type | Count |
|---------------|-------|
"""
    
    for ioc_type, count in report['executive_summary']['primary_threat_types'].items():
        md += f"| {ioc_type} | {count:,} |\n"
    
    md += f"""
## Threat Actor Intelligence

### Most Active Threat Actors

| Actor | Indicators | Pulses | Primary Type |
|-------|-----------|--------|--------------|
"""
    
    for actor, stats in list(report['threat_actor_intelligence']['most_active_actors'].items())[:10]:
        md += f"| {actor} | {stats['indicator']} | {stats['pulse_name']} | {stats['indicator_type']} |\n"
    
    md += f"""
## Infrastructure Analysis

### Summary
- **IP Addresses:** {report['infrastructure_analysis']['ip_addresses']['total']:,} total, {report['infrastructure_analysis']['ip_addresses']['unique']:,} unique
- **Domains:** {report['infrastructure_analysis']['domains']['total']:,} total, {report['infrastructure_analysis']['domains']['unique']:,} unique
- **URLs:** {report['infrastructure_analysis']['urls']['total']:,} total, {report['infrastructure_analysis']['urls']['unique']:,} unique
- **File Hashes:** {report['infrastructure_analysis']['file_hashes']['total']:,} total

### Top Domain TLDs
"""
    
    if report['infrastructure_analysis']['domains']['top_tlds']:
        md += "| TLD | Count |\n|-----|-------|\n"
        for tld, count in report['infrastructure_analysis']['domains']['top_tlds'].items():
            md += f"| .{tld} | {count} |\n"
    
    md += f"""
## Temporal Analysis

**Most Active Day:** {report['temporal_analysis']['activity_patterns'].get('most_active_day', 'Unknown')}  
**Daily Average:** {report['temporal_analysis']['activity_patterns'].get('daily_average', 0):.1f} indicators  
**Peak Daily Activity:** {report['temporal_analysis']['activity_patterns'].get('peak_daily_activity', 0)} indicators  

## Recommendations

### Immediate Actions
"""
    
    for action in report['recommendations']['immediate_actions']:
        md += f"- {action}\n"
    
    md += f"""
### Monitoring Priorities
"""
    
    for priority in report['recommendations']['monitoring_priorities']:
        md += f"- {priority}\n"
    
    md += f"""
### Threat Hunting Focus
"""
    
    for focus in report['recommendations']['threat_hunting_focus']:
        md += f"- {focus}\n"
    
    md += f"""
## Threat Tags Analysis

### Top 15 Threat Tags
"""
    
    if report['threat_categorization']['tag_analysis']:
        md += "| Tag | Frequency |\n|-----|----------|\n"
        for tag, count in list(report['threat_categorization']['tag_analysis'].items())[:15]:
            md += f"| {tag} | {count} |\n"
    
    md += f"""
---
*Report generated by Advanced CTI Analysis System*
"""
    
    return md

def generate_hunting_queries(df):
    """Generate threat hunting queries for various platforms"""
    
    queries = f"""# Threat Hunting Queries
# Generated: {datetime.now().isoformat()}
# Based on {len(df):,} indicators

## Splunk Queries

### Malicious IP Detection
"""
    
    # IP queries
    ips = df[df['indicator_type'].isin(['IPv4', 'IPv6'])]['indicator'].unique()[:50]  # Limit for practicality
    if len(ips) > 0:
        ip_list = '", "'.join(ips)
        queries += f"""
index=* (src_ip IN ("{ip_list}") OR dest_ip IN ("{ip_list}") OR client_ip IN ("{ip_list}"))
| eval threat_type="Malicious IP"
| stats count by src_ip, dest_ip, threat_type
"""
    
    # Domain queries
    domains = df[df['indicator_type'] == 'domain']['indicator'].unique()[:30]
    if len(domains) > 0:
        domain_list = '", "'.join(domains)
        queries += f"""
### Malicious Domain Detection

index=* (url="*{domains[0]}*" OR query="*{domains[0]}*" OR host="{domains[0]}")
| eval threat_type="Malicious Domain"
| stats count by url, query, host, threat_type
"""
    
    # Hash queries
    hashes = df[df['indicator_type'].isin(['MD5', 'SHA1', 'SHA256'])]['indicator'].unique()[:20]
    if len(hashes) > 0:
        hash_list = '", "'.join(hashes)
        queries += f"""
### Malicious File Hash Detection

index=* (file_hash IN ("{hash_list}") OR md5 IN ("{hash_list}") OR sha1 IN ("{hash_list}") OR sha256 IN ("{hash_list}"))
| eval threat_type="Malicious File"
| stats count by file_hash, md5, sha1, sha256, threat_type
"""
    
    # Suricata rules
    queries += f"""
## Suricata Rules

### IP-based Rules
"""
    
    if len(ips) > 0:
        for i, ip in enumerate(ips[:10], 1):  # First 10 IPs
            queries += f'alert ip any any -> {ip} any (msg:"Malicious IP {ip} detected"; sid:1000{i:03d}; rev:1;)\n'
    
    # YARA rules for file hashes
    if len(hashes) > 0:
        queries += f"""
## YARA Rules

rule MaliciousFileHashes {{
    meta:
        description = "Detects files matching known malicious hashes"
        generated = "{datetime.now().isoformat()}"
    
    condition:
        hash.md5(0, filesize) == "{hashes[0] if len(hashes) > 0 and len(hashes[0]) == 32 else 'placeholder'}" or
        hash.sha1(0, filesize) == "{next((h for h in hashes if len(h) == 40), 'placeholder')}" or
        hash.sha256(0, filesize) == "{next((h for h in hashes if len(h) == 64), 'placeholder')}"
}}
"""
    
    # Sigma rules
    queries += f"""
## Sigma Rules

### Network Connection to Malicious IPs

title: Connection to Known Malicious IP
description: Detects network connections to known malicious IP addresses
status: experimental
references:
    - CTI Analysis {datetime.now().strftime('%Y-%m-%d')}
logsource:
    category: network_connection
detection:
    selection:
        DestinationIp:
"""
    
    for ip in ips[:10]:
        queries += f"            - '{ip}'\n"
    
    queries += f"""    condition: selection
fields:
    - SourceIp
    - DestinationIp
    - DestinationPort
falsepositives:
    - Unknown
level: high
"""
    
    return queries

if __name__ == "__main__":
    generate_threat_intelligence_report()
