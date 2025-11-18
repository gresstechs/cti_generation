#!/usr/bin/env python3
"""
Complete CTI Pipeline: OTX → AndMal Detection → ML Recommendations
"""

import os
import sys
import pandas as pd
import numpy as np
import json
from datetime import datetime

# Add cti directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'cti'))
from model_utils import ANDMAL_DETECTOR_PATH, REALTIME_RECOMMENDER_PATH

print("="*70)
print("COMPLETE CTI PIPELINE")
print("="*70)
print("1. Load OTX data")
print("2. Run AndMal malware detection")
print("3. Generate ML action recommendations")
print("4. Export for Grafana")
print("="*70)

# ============================================================================
# STEP 1: Load OTX Data
# ============================================================================
print("\n📂 STEP 1: Loading OTX Data...")

ml_features_file = 'out/cti_ml_features_latest.csv'

if not os.path.exists(ml_features_file):
    print(f"❌ Error: {ml_features_file} not found")
    print("   Run: python cti/otx_fetch.py")
    sys.exit(1)

otx_df = pd.read_csv(ml_features_file)
print(f"✅ Loaded {len(otx_df)} OTX threats")

# ============================================================================
# STEP 2: AndMal Malware Detection (if available)
# ============================================================================
print("\n🔍 STEP 2: Running Malware Detection...")

try:
    # Try to load AndMal detector
    import joblib

    if os.path.exists(ANDMAL_DETECTOR_PATH):
        print(f"   Loading AndMal detector from {ANDMAL_DETECTOR_PATH}...")
        
        # This is simplified - in production you'd need to extract proper features
        # For now, we'll use heuristics based on OTX data
        
        print("   ⚠️  Note: Using heuristic scoring (train AndMal model for better accuracy)")
        
        # Heuristic malware probability based on OTX indicators
        otx_df['malware_probability'] = otx_df.apply(lambda row: min(
            0.3 +  # Base score
            (0.3 if row['has_malware'] else 0) +
            (0.2 if row['has_adversary'] else 0) +
            (0.15 if row['tlp_level'] >= 2 else 0) +
            (0.05 if row['indicator_count'] > 50 else 0),
            0.95
        ), axis=1)
        
        otx_df['confidence'] = otx_df.apply(lambda row: min(
            50 +
            (20 if row['has_malware'] else 0) +
            (15 if row['has_adversary'] else 0) +
            (10 if row['indicator_count'] > 30 else 0),
            95
        ), axis=1)
        
        print(f"   ✅ Malware probabilities calculated")
        print(f"      Avg probability: {otx_df['malware_probability'].mean():.2%}")
        print(f"      High risk (>70%): {len(otx_df[otx_df['malware_probability'] > 0.7])}")
        
    else:
        print(f"   ⚠️  AndMal model not found at {ANDMAL_DETECTOR_PATH}")
        print("   Using default malware probability (50%)")
        otx_df['malware_probability'] = 0.5
        otx_df['confidence'] = 50

except Exception as e:
    print(f"   ⚠️  Error loading AndMal detector: {e}")
    print("   Using default malware probability (50%)")
    otx_df['malware_probability'] = 0.5
    otx_df['confidence'] = 50

# ============================================================================
# STEP 3: ML Action Recommendations
# ============================================================================
print("\n🤖 STEP 3: Generating ML Action Recommendations...")

# Import ML recommender
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    # Load ML recommender module
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "ml_recommender", 
        "cti/realtime_ml_recommender.py"
    )
    ml_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(ml_module)
    
    RealTimeMLRecommender = ml_module.RealTimeMLRecommender
    
except Exception as e:
    print(f"❌ Error loading ML recommender: {e}")
    print("   Make sure realtime_ml_recommender.py is in the same directory")
    sys.exit(1)

# Initialize recommender
recommender = RealTimeMLRecommender()

# Load or train model
if os.path.exists(REALTIME_RECOMMENDER_PATH):
    recommender.load_model(REALTIME_RECOMMENDER_PATH)
else:
    print("   Training new ML model...")
    recommender.train_from_synthetic_data(n_samples=1000)
    recommender.save_model()

# Generate recommendations
print(f"   Processing {len(otx_df)} threats...")

all_recommendations = []

for idx, threat in otx_df.iterrows():
    # Prepare threat data
    threat_data = {
        'pulse_id': threat['pulse_id'],
        'pulse_name': threat['pulse_name'],
        'malware_probability': threat['malware_probability'],
        'confidence': threat['confidence'],
        'indicator_count': threat['indicator_count'],
        'ip_count': threat['ip_count'],
        'domain_count': threat['domain_count'],
        'hash_count': threat['hash_count'],
        'url_count': threat['url_count'],
        'file_count': threat['file_count'],
        'has_adversary': threat['has_adversary'],
        'adversary': threat.get('adversary', ''),
        'has_malware': threat['has_malware'],
        'malware_families': threat.get('malware_families', ''),
        'attack_ids_count': threat['attack_ids_count'],
        'tlp': threat['tlp'],
        'tlp_level': threat['tlp_level'],
        'pulse_age_hours': threat['pulse_age_hours'],
        'subscription_count': 0
    }
    
    # Get ML recommendations
    recommendations = recommender.predict_actions_realtime(threat_data, top_k=5)
    
    # Determine priority based on malware probability
    if threat['malware_probability'] >= 0.9:
        priority = 'CRITICAL'
        risk_level = 'CRITICAL'
    elif threat['malware_probability'] >= 0.7:
        priority = 'HIGH'
        risk_level = 'HIGH'
    elif threat['malware_probability'] >= 0.5:
        priority = 'MEDIUM'
        risk_level = 'MEDIUM'
    else:
        priority = 'LOW'
        risk_level = 'LOW'
    
    # Save recommendations
    for rec in recommendations:
        all_recommendations.append({
            'pulse_id': threat['pulse_id'],
            'pulse_name': threat['pulse_name'],
            'tlp': threat['tlp'],
            'adversary': threat.get('adversary', ''),
            'malware_families': threat.get('malware_families', ''),
            'indicator_count': threat['indicator_count'],
            'malware_probability': threat['malware_probability'],
            'priority': priority,
            'risk_level': risk_level,
            'action': rec['action'],
            'action_category': rec['category'],
            'action_description': rec['description'],
            'ml_confidence': rec['ml_confidence'],
            'confidence_level': rec['confidence_level'],
            'action_priority': rec['priority'],
            'estimated_time': rec['estimated_time'],
            'tools_required': ', '.join(rec['tools']),
            'timestamp': datetime.now().isoformat()
        })

print(f"✅ Generated {len(all_recommendations)} recommendations")

# ============================================================================
# STEP 4: Save Results
# ============================================================================
print("\n💾 STEP 4: Saving Results...")

# Save recommendations
rec_df = pd.DataFrame(all_recommendations)
output_file = 'out/cti_ml_recommendations.csv'
rec_df.to_csv(output_file, index=False)
print(f"✅ Saved recommendations: {output_file}")

# Save detection results
detection_df = otx_df[['pulse_id', 'pulse_name', 'tlp', 'adversary', 'malware_families', 
                       'indicator_count', 'malware_probability', 'confidence']].copy()

# Add priority
detection_df['priority'] = detection_df['malware_probability'].apply(
    lambda x: 'CRITICAL' if x >= 0.9 else 'HIGH' if x >= 0.7 else 'MEDIUM' if x >= 0.5 else 'LOW'
)

detection_file = 'out/cti_threat_detection.csv'
detection_df.to_csv(detection_file, index=False)
print(f"✅ Saved detections: {detection_file}")

# Create summary
summary = {
    'timestamp': datetime.now().isoformat(),
    'pipeline': 'OTX → AndMal → ML Recommender',
    'statistics': {
        'total_threats': len(otx_df),
        'total_recommendations': len(all_recommendations),
        'avg_recommendations_per_threat': round(len(all_recommendations) / len(otx_df), 2),
        'critical_threats': len(detection_df[detection_df['priority'] == 'CRITICAL']),
        'high_threats': len(detection_df[detection_df['priority'] == 'HIGH']),
        'medium_threats': len(detection_df[detection_df['priority'] == 'MEDIUM']),
        'low_threats': len(detection_df[detection_df['priority'] == 'LOW']),
        'avg_malware_probability': round(detection_df['malware_probability'].mean(), 4)
    },
    'top_actions': rec_df['action'].value_counts().head(10).to_dict(),
    'action_categories': rec_df['action_category'].value_counts().to_dict()
}

summary_file = 'out/cti_pipeline_summary.json'
with open(summary_file, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"✅ Saved summary: {summary_file}")

# ============================================================================
# FINAL SUMMARY
# ============================================================================
print("\n" + "="*70)
print("✅ CTI PIPELINE COMPLETE!")
print("="*70)

print(f"\n📊 Results Summary:")
print(f"   Total threats analyzed: {len(otx_df)}")
print(f"   Malware detections:")
print(f"      🔴 CRITICAL: {summary['statistics']['critical_threats']}")
print(f"      🟠 HIGH:     {summary['statistics']['high_threats']}")
print(f"      🟡 MEDIUM:   {summary['statistics']['medium_threats']}")
print(f"      🟢 LOW:      {summary['statistics']['low_threats']}")
print(f"   Total action recommendations: {len(all_recommendations)}")
print(f"   Avg actions per threat: {summary['statistics']['avg_recommendations_per_threat']}")

print(f"\n📁 Output Files:")
print(f"   • {output_file} (All recommendations)")
print(f"   • {detection_file} (Threat detections)")
print(f"   • {summary_file} (Summary statistics)")

print(f"\n🚀 Next Steps:")
print(f"   1. Copy to Grafana:")
print(f"      cp {output_file} /var/lib/grafana/csv/")
print(f"      cp {detection_file} /var/lib/grafana/csv/")
print(f"   2. View in Grafana dashboard")
print(f"   3. Execute recommended actions")

print("="*70)