#!/usr/bin/env python3
"""
Predict OTX Threat Levels Using Trained ML Model
Analyzes AlienVault OTX threat intelligence using OTX-trained classifier.
Falls back to heuristics if model not available.
"""

import pandas as pd
import numpy as np
import joblib
import json
import sys
from datetime import datetime
from pathlib import Path

# Get project root directory (parent of cti/)
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
OUT_DIR = PROJECT_ROOT / "out"
MODELS_DIR = PROJECT_ROOT / "models"

# Model paths
OTX_MODEL_PATH = MODELS_DIR / "otx_threat_classifier_v1.pkl"

# Feature columns (must match training)
FEATURE_COLUMNS = [
    'indicator_count',
    'tlp_level',
    'has_adversary',
    'has_malware',
    'tag_count',
    'reference_count',
    'attack_ids_count',
    'pulse_age_hours',
    'ip_count',
    'domain_count',
    'hash_count',
    'url_count',
    'file_count'
]

print("="*70)
print("OTX THREAT PREDICTION WITH ML MODEL")
print("="*70)

# Check if OTX features exist (use absolute path)
OTX_FEATURES_FILE = OUT_DIR / "cti_ml_features_latest.csv"
if not OTX_FEATURES_FILE.exists():
    print("\n❌ OTX features not found!")
    print(f"   Expected: {OTX_FEATURES_FILE}")
    print("   Fetch OTX data first:")
    print("   python cti/otx_fetch.py")
    sys.exit(1)

# Load OTX features
print("\n📂 Loading OTX threat features...")
otx_features = pd.read_csv(OTX_FEATURES_FILE)
print(f"   ✅ Loaded {len(otx_features)} threats")

print("\n📊 OTX Threats Summary:")
print(f"   Total pulses: {len(otx_features)}")
if 'tlp' in otx_features.columns:
    print(f"   TLP distribution: {otx_features['tlp'].value_counts().to_dict()}")
if 'has_adversary' in otx_features.columns:
    print(f"   With adversary: {int(otx_features['has_adversary'].sum())}")
if 'has_malware' in otx_features.columns:
    print(f"   With malware: {int(otx_features['has_malware'].sum())}")

# Check if OTX model exists
USE_ML_MODEL = OTX_MODEL_PATH.exists()

if USE_ML_MODEL:
    print("\n📂 Loading trained OTX threat model...")
    try:
        model_data = joblib.load(OTX_MODEL_PATH)
        models = model_data['models']
        scalers = model_data['scalers']
        feature_names = model_data['feature_names']

        print(f"   ✅ Model: {model_data['model_name']} v{model_data['version']}")
        print(f"   ✅ Dataset: {model_data['dataset']}")
        print(f"   ✅ Features: {len(feature_names)}")
        print(f"   ✅ Trained: {model_data['trained_date'][:10]}")

        # Show model metrics
        if 'metrics' in model_data:
            print(f"\n📈 Model Performance:")
            for target, m in model_data['metrics'].items():
                print(f"      {target}: accuracy={m['accuracy']:.4f}")

    except Exception as e:
        print(f"   ⚠️  Error loading model: {e}")
        print("   Falling back to heuristic scoring")
        USE_ML_MODEL = False
else:
    print("\n⚠️  OTX ML model not found")
    print(f"   Expected: {OTX_MODEL_PATH}")
    print("   Train the model first: python cti/train_otx_threat_model.py")
    print("   Using heuristic scoring instead")


def predict_with_ml(threat_features):
    """Use trained ML model for prediction"""
    # Prepare feature vector
    X = np.array([[
        threat_features.get(col, 0) for col in FEATURE_COLUMNS
    ]])

    # Get predictions from all models
    threat_level_scaled = scalers['threat_level'].transform(X)
    threat_level_pred = models['threat_level'].predict(threat_level_scaled)[0]
    threat_level_proba = models['threat_level'].predict_proba(threat_level_scaled)[0]

    action_scaled = scalers['requires_action'].transform(X)
    requires_action_pred = models['requires_action'].predict(action_scaled)[0]
    requires_action_proba = models['requires_action'].predict_proba(action_scaled)[0]

    priority_scaled = scalers['is_high_priority'].transform(X)
    is_high_priority_pred = models['is_high_priority'].predict(priority_scaled)[0]
    priority_proba = models['is_high_priority'].predict_proba(priority_scaled)[0]

    # Calculate overall malware probability
    # Weighted combination of model predictions
    malware_prob = (
        threat_level_proba[min(3, len(threat_level_proba)-1)] * 0.4 +  # P(threat_level=3)
        (threat_level_proba[2] if len(threat_level_proba) > 2 else 0) * 0.2 +  # P(threat_level=2)
        requires_action_proba[1] * 0.2 +  # P(requires_action=1)
        priority_proba[1] * 0.2  # P(is_high_priority=1)
    )

    # Determine risk level based on threat_level prediction
    risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    risk_level = risk_levels[min(threat_level_pred, 3)]

    # Confidence is the max probability from threat level prediction
    confidence = max(threat_level_proba) * 100

    return {
        'malware_probability': float(malware_prob),
        'confidence': float(confidence),
        'risk_level': risk_level,
        'threat_level_pred': int(threat_level_pred),
        'requires_action': int(requires_action_pred),
        'is_high_priority': int(is_high_priority_pred),
        'method': 'ML'
    }


def predict_with_heuristics(threat_features):
    """Fallback heuristic-based prediction"""
    malware_prob = 0.0

    # Base probability from TLP
    tlp = threat_features.get('tlp', 'white')
    tlp_probs = {'white': 0.1, 'green': 0.3, 'amber': 0.6, 'red': 0.8}
    malware_prob = tlp_probs.get(tlp, 0.1)

    # Boost if malware families present
    if threat_features.get('has_malware', 0):
        malware_prob = min(1.0, malware_prob + 0.3)

    # Boost if known adversary
    if threat_features.get('has_adversary', 0):
        malware_prob = min(1.0, malware_prob + 0.2)

    # Boost for high indicator counts
    indicator_count = threat_features.get('indicator_count', 0)
    if indicator_count > 50:
        malware_prob = min(1.0, malware_prob + 0.15)

    # Boost for file-based indicators (hashes)
    hash_count = threat_features.get('hash_count', 0)
    if hash_count > 10:
        malware_prob = min(1.0, malware_prob + 0.15)

    # Boost for multi-vector attacks
    indicator_diversity = sum([
        threat_features.get('ip_count', 0) > 0,
        threat_features.get('domain_count', 0) > 0,
        threat_features.get('hash_count', 0) > 0,
        threat_features.get('url_count', 0) > 0,
        threat_features.get('file_count', 0) > 0
    ])
    if indicator_diversity >= 4:
        malware_prob = min(1.0, malware_prob + 0.1)

    # Determine risk level
    if malware_prob >= 0.9:
        risk_level = 'CRITICAL'
        threat_level = 3
    elif malware_prob >= 0.7:
        risk_level = 'HIGH'
        threat_level = 2
    elif malware_prob >= 0.5:
        risk_level = 'MEDIUM'
        threat_level = 1
    else:
        risk_level = 'LOW'
        threat_level = 0

    return {
        'malware_probability': float(malware_prob),
        'confidence': float(malware_prob * 100),
        'risk_level': risk_level,
        'threat_level_pred': threat_level,
        'requires_action': 1 if threat_level >= 2 else 0,
        'is_high_priority': 1 if risk_level == 'CRITICAL' else 0,
        'method': 'Heuristic'
    }


# Process all threats
print(f"\n🔮 Calculating threat predictions using {'ML model' if USE_ML_MODEL else 'heuristics'}...")

results = []

for idx, threat in otx_features.iterrows():
    # Prepare threat features
    threat_features = {
        'indicator_count': threat.get('indicator_count', 0),
        'tlp_level': threat.get('tlp_level', 0),
        'tlp': threat.get('tlp', 'white'),
        'has_adversary': threat.get('has_adversary', 0),
        'has_malware': threat.get('has_malware', 0),
        'tag_count': threat.get('tag_count', 0),
        'reference_count': threat.get('reference_count', 0),
        'attack_ids_count': threat.get('attack_ids_count', 0),
        'pulse_age_hours': threat.get('pulse_age_hours', 0),
        'ip_count': threat.get('ip_count', 0),
        'domain_count': threat.get('domain_count', 0),
        'hash_count': threat.get('hash_count', 0),
        'url_count': threat.get('url_count', 0),
        'file_count': threat.get('file_count', 0)
    }

    # Get prediction
    if USE_ML_MODEL:
        prediction = predict_with_ml(threat_features)
    else:
        prediction = predict_with_heuristics(threat_features)

    # Determine priority and action
    if prediction['risk_level'] == 'CRITICAL':
        priority = 'CRITICAL'
        action = 'IMMEDIATE_RESPONSE'
    elif prediction['risk_level'] == 'HIGH':
        priority = 'HIGH'
        action = 'INVESTIGATE_URGENTLY'
    elif prediction['risk_level'] == 'MEDIUM':
        priority = 'MEDIUM'
        action = 'INVESTIGATE'
    else:
        priority = 'LOW'
        action = 'MONITOR'

    # Build risk factors explanation
    factors = []
    if threat_features['has_malware']:
        factors.append("Known malware families")
    if threat_features['has_adversary']:
        factors.append("Known threat actor")
    if threat_features['tlp'] in ['red', 'amber']:
        factors.append(f"High TLP ({threat_features['tlp']})")
    if threat_features['indicator_count'] > 50:
        factors.append(f"High IOC count ({threat_features['indicator_count']})")
    if threat_features['hash_count'] > 10:
        factors.append(f"Multiple file hashes ({threat_features['hash_count']})")

    results.append({
        'pulse_id': threat.get('pulse_id'),
        'pulse_name': threat.get('pulse_name'),
        'tlp': threat.get('tlp'),
        'adversary': threat.get('adversary', ''),
        'malware_families': threat.get('malware_families', ''),
        'indicator_count': int(threat_features['indicator_count']),
        'malware_probability': prediction['malware_probability'],
        'confidence': prediction['confidence'],
        'risk_level': prediction['risk_level'],
        'priority': priority,
        'recommended_action': action,
        'risk_factors': '; '.join(factors) if factors else 'Low threat indicators',
        'prediction_method': prediction['method'],
        'model_version': model_data['model_name'] if USE_ML_MODEL else 'Heuristic v1.0',
        'prediction_timestamp': datetime.utcnow().isoformat()
    })

# Convert to DataFrame
results_df = pd.DataFrame(results)
results_df = results_df.sort_values('malware_probability', ascending=False)

# Save predictions
OUT_DIR.mkdir(parents=True, exist_ok=True)
output_csv = OUT_DIR / 'otx_andmal_predictions.csv'
results_df.to_csv(output_csv, index=False)
print(f"\n✅ Saved predictions to: {output_csv}")

# Create summary
summary = {
    'timestamp': datetime.utcnow().isoformat(),
    'model': model_data['model_name'] if USE_ML_MODEL else 'Heuristic Scorer',
    'model_version': model_data.get('version', '1.0') if USE_ML_MODEL else '1.0',
    'prediction_method': 'ML' if USE_ML_MODEL else 'Heuristic',
    'dataset': 'OTX Threat Intelligence',
    'total_threats': len(results_df),
    'priority_distribution': results_df['priority'].value_counts().to_dict(),
    'risk_level_distribution': results_df['risk_level'].value_counts().to_dict(),
    'avg_malware_probability': float(results_df['malware_probability'].mean()),
    'high_risk_threats': int(sum(results_df['malware_probability'] >= 0.7)),
    'critical_threats': int(sum(results_df['priority'] == 'CRITICAL'))
}

summary_json = OUT_DIR / 'otx_andmal_summary.json'
with open(summary_json, 'w') as f:
    json.dump(summary, f, indent=2)
print(f"✅ Saved summary to: {summary_json}")

# Display results
print(f"\n📊 Prediction Summary:")
print(f"   Method: {summary['prediction_method']}")
print(f"   Total threats: {summary['total_threats']}")
print(f"   High risk (≥70%): {summary['high_risk_threats']}")
print(f"   Critical threats: {summary['critical_threats']}")
print(f"   Avg malware probability: {summary['avg_malware_probability']:.1%}")

print(f"\n🎯 Priority Distribution:")
for priority, count in results_df['priority'].value_counts().items():
    pct = (count / len(results_df)) * 100
    print(f"   {priority:12s}: {count:3d} ({pct:5.1f}%)")

# Show top 10 threats
print(f"\n🔍 Top 10 Highest Risk Threats:")
print("="*70)

for idx, threat in results_df.head(10).iterrows():
    if threat['malware_probability'] >= 0.9:
        color = '🔴'
    elif threat['malware_probability'] >= 0.7:
        color = '🟠'
    elif threat['malware_probability'] >= 0.5:
        color = '🟡'
    else:
        color = '🟢'

    print(f"\n{color} {threat['pulse_name'][:65]}")
    print(f"   Malware Probability: {threat['malware_probability']:.1%}")
    print(f"   Priority: {threat['priority']} | Action: {threat['recommended_action']}")
    print(f"   TLP: {threat['tlp']} | IOCs: {threat['indicator_count']}")
    if threat['adversary']:
        print(f"   Adversary: {threat['adversary']}")
    if threat['malware_families']:
        print(f"   Malware: {threat['malware_families']}")
    if threat['risk_factors']:
        print(f"   Factors: {threat['risk_factors']}")

# Show critical threats
critical = results_df[results_df['priority'] == 'CRITICAL']
if len(critical) > 0:
    print(f"\n{'='*70}")
    print(f"🚨 CRITICAL THREATS: {len(critical)}")
    print(f"{'='*70}")

    for _, threat in critical.iterrows():
        print(f"\n🔴 {threat['pulse_name']}")
        print(f"   Probability: {threat['malware_probability']:.1%}")
        print(f"   Action: {threat['recommended_action']}")
        print(f"   IOCs: {threat['indicator_count']}")
        if threat['adversary']:
            print(f"   Threat Actor: {threat['adversary']}")

print(f"\n{'='*70}")
print(f"💾 Output Files:")
print(f"   • {output_csv}")
print(f"   • {summary_json}")
print(f"\n📊 Prediction Method: {summary['prediction_method']}")
if USE_ML_MODEL:
    print(f"   Model: {model_data['model_name']} v{model_data['version']}")
else:
    print("   ⚠️  Train model for better accuracy: python cti/train_otx_threat_model.py")
print("="*70)
