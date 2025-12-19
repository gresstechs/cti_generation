#!/usr/bin/env python3
"""
Train OTX Threat Classification Model
Uses OTX threat intelligence features to predict threat levels and priorities.
"""

import pandas as pd
import numpy as np
import joblib
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# Get project paths
SCRIPT_DIR = Path(__file__).parent
PROJECT_ROOT = SCRIPT_DIR.parent
OUT_DIR = PROJECT_ROOT / "out"
MODELS_DIR = PROJECT_ROOT / "models"

# Model output path
OTX_MODEL_PATH = MODELS_DIR / "otx_threat_classifier_v1.pkl"

print("="*70)
print("OTX THREAT CLASSIFICATION MODEL TRAINING")
print("="*70)

# Feature columns used for training
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

# Target columns
TARGET_COLUMNS = ['threat_level', 'requires_action', 'is_high_priority']


def load_otx_training_data():
    """Load OTX ML features from collected data"""
    print("\n📂 Loading OTX training data...")

    # Try to load existing OTX features
    features_file = OUT_DIR / "cti_ml_features_latest.csv"

    if features_file.exists():
        df = pd.read_csv(features_file)
        print(f"   ✅ Loaded {len(df)} samples from {features_file}")
        return df

    # Try to load historical data
    historical_files = list(OUT_DIR.glob("cti_ml_features_*.csv"))
    if historical_files:
        dfs = []
        for f in historical_files:
            try:
                dfs.append(pd.read_csv(f))
            except Exception as e:
                print(f"   ⚠️  Could not load {f}: {e}")

        if dfs:
            df = pd.concat(dfs, ignore_index=True)
            # Remove duplicates based on pulse_id
            df = df.drop_duplicates(subset=['pulse_id'], keep='last')
            print(f"   ✅ Loaded {len(df)} samples from {len(historical_files)} files")
            return df

    print("   ⚠️  No OTX data found")
    return None


def generate_synthetic_training_data(n_samples=2000):
    """
    Generate synthetic training data based on realistic OTX threat distributions.
    This provides a baseline model that can be improved with real data.
    """
    print(f"\n🔧 Generating {n_samples} synthetic training samples...")

    np.random.seed(42)

    data = []

    for i in range(n_samples):
        # Randomly assign a base threat profile
        threat_profile = np.random.choice(['low', 'medium', 'high', 'critical'],
                                          p=[0.4, 0.3, 0.2, 0.1])

        if threat_profile == 'low':
            tlp_level = np.random.choice([0, 1], p=[0.7, 0.3])  # white/green
            has_adversary = np.random.choice([0, 1], p=[0.95, 0.05])
            has_malware = np.random.choice([0, 1], p=[0.9, 0.1])
            indicator_count = np.random.randint(1, 20)
            attack_ids_count = np.random.randint(0, 2)

        elif threat_profile == 'medium':
            tlp_level = np.random.choice([1, 2], p=[0.4, 0.6])  # green/amber
            has_adversary = np.random.choice([0, 1], p=[0.7, 0.3])
            has_malware = np.random.choice([0, 1], p=[0.6, 0.4])
            indicator_count = np.random.randint(10, 50)
            attack_ids_count = np.random.randint(0, 5)

        elif threat_profile == 'high':
            tlp_level = np.random.choice([2, 3], p=[0.6, 0.4])  # amber/red
            has_adversary = np.random.choice([0, 1], p=[0.4, 0.6])
            has_malware = np.random.choice([0, 1], p=[0.3, 0.7])
            indicator_count = np.random.randint(30, 150)
            attack_ids_count = np.random.randint(2, 10)

        else:  # critical
            tlp_level = 3  # red
            has_adversary = np.random.choice([0, 1], p=[0.2, 0.8])
            has_malware = np.random.choice([0, 1], p=[0.1, 0.9])
            indicator_count = np.random.randint(50, 500)
            attack_ids_count = np.random.randint(5, 20)

        # Generate correlated features
        tag_count = np.random.randint(1, max(2, indicator_count // 5))
        reference_count = np.random.randint(0, max(1, indicator_count // 10))
        pulse_age_hours = np.random.exponential(scale=200)  # Newer threats more common

        # Indicator type distribution (correlated with threat type)
        total_indicators = indicator_count
        if has_malware:
            hash_count = int(total_indicators * np.random.uniform(0.3, 0.6))
            file_count = int(total_indicators * np.random.uniform(0.1, 0.3))
        else:
            hash_count = int(total_indicators * np.random.uniform(0, 0.2))
            file_count = int(total_indicators * np.random.uniform(0, 0.1))

        remaining = total_indicators - hash_count - file_count
        ip_count = int(remaining * np.random.uniform(0.2, 0.5))
        domain_count = int(remaining * np.random.uniform(0.2, 0.4))
        url_count = remaining - ip_count - domain_count

        # Calculate labels
        threat_level = tlp_level
        requires_action = 1 if tlp_level >= 2 else 0
        is_high_priority = 1 if (tlp_level == 3 or (tlp_level == 2 and has_adversary)) else 0

        data.append({
            'pulse_id': f'SYNTH_{i:05d}',
            'pulse_name': f'Synthetic Threat {i}',
            'indicator_count': indicator_count,
            'tlp_level': tlp_level,
            'tlp': ['white', 'green', 'amber', 'red'][tlp_level],
            'has_adversary': has_adversary,
            'adversary': f'APT-{np.random.randint(1, 50)}' if has_adversary else '',
            'has_malware': has_malware,
            'malware_families': f'Malware-{np.random.randint(1, 100)}' if has_malware else '',
            'tag_count': tag_count,
            'reference_count': reference_count,
            'attack_ids_count': attack_ids_count,
            'pulse_age_hours': round(pulse_age_hours, 2),
            'ip_count': ip_count,
            'domain_count': domain_count,
            'hash_count': hash_count,
            'url_count': url_count,
            'file_count': file_count,
            'threat_level': threat_level,
            'requires_action': requires_action,
            'is_high_priority': is_high_priority
        })

    df = pd.DataFrame(data)
    print(f"   ✅ Generated {len(df)} synthetic samples")
    print(f"   Threat distribution: {df['threat_level'].value_counts().to_dict()}")

    return df


def augment_with_synthetic(real_df, target_samples=2000):
    """Augment real data with synthetic samples to reach target size"""
    print(f"\n🔄 Augmenting data to reach {target_samples} samples...")

    current_count = len(real_df)
    if current_count >= target_samples:
        print(f"   ✅ Already have {current_count} samples, no augmentation needed")
        return real_df

    synthetic_needed = target_samples - current_count
    synthetic_df = generate_synthetic_training_data(synthetic_needed)

    # Combine real and synthetic data
    combined_df = pd.concat([real_df, synthetic_df], ignore_index=True)
    print(f"   ✅ Combined: {current_count} real + {synthetic_needed} synthetic = {len(combined_df)} total")

    return combined_df


def prepare_features(df):
    """Prepare feature matrix and target variables"""
    print("\n🔧 Preparing features...")

    # Ensure all feature columns exist
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            print(f"   ⚠️  Missing column: {col}, filling with 0")
            df[col] = 0

    # Extract features
    X = df[FEATURE_COLUMNS].copy()

    # Handle missing values
    X = X.fillna(0)

    # Extract targets
    y_threat_level = df['threat_level'].values
    y_requires_action = df['requires_action'].values
    y_is_high_priority = df['is_high_priority'].values

    print(f"   ✅ Features shape: {X.shape}")
    print(f"   ✅ Feature columns: {FEATURE_COLUMNS}")

    return X, y_threat_level, y_requires_action, y_is_high_priority


def train_model(X, y, model_name="threat_level"):
    """Train a classifier for the given target"""
    print(f"\n🎯 Training {model_name} classifier...")

    # Split data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Scale features
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    # Train Random Forest
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        random_state=42,
        n_jobs=-1
    )

    model.fit(X_train_scaled, y_train)

    # Evaluate
    y_pred = model.predict(X_test_scaled)
    accuracy = accuracy_score(y_test, y_pred)

    # Cross-validation
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)

    print(f"   Test Accuracy: {accuracy:.4f}")
    print(f"   CV Score: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")

    # Feature importance
    feature_importance = dict(zip(FEATURE_COLUMNS, model.feature_importances_))
    top_features = sorted(feature_importance.items(), key=lambda x: x[1], reverse=True)[:5]
    print(f"   Top features: {[f[0] for f in top_features]}")

    return model, scaler, {
        'accuracy': accuracy,
        'cv_mean': cv_scores.mean(),
        'cv_std': cv_scores.std(),
        'feature_importance': feature_importance
    }


def save_model(models, scalers, metrics, training_info):
    """Save the trained model package"""
    print("\n💾 Saving model...")

    MODELS_DIR.mkdir(parents=True, exist_ok=True)

    model_package = {
        'model_name': 'OTX Threat Classifier',
        'version': '1.0',
        'dataset': 'OTX Threat Intelligence',
        'trained_date': datetime.utcnow().isoformat(),
        'feature_names': FEATURE_COLUMNS,
        'models': models,
        'scalers': scalers,
        'metrics': metrics,
        'training_info': training_info
    }

    joblib.dump(model_package, OTX_MODEL_PATH)
    print(f"   ✅ Saved to: {OTX_MODEL_PATH}")

    # Also save metadata as JSON for easy inspection
    metadata = {
        'model_name': model_package['model_name'],
        'version': model_package['version'],
        'dataset': model_package['dataset'],
        'trained_date': model_package['trained_date'],
        'feature_names': model_package['feature_names'],
        'metrics': {k: {mk: float(mv) if isinstance(mv, (int, float, np.floating)) else mv
                       for mk, mv in v.items() if mk != 'feature_importance'}
                   for k, v in metrics.items()},
        'training_info': training_info
    }

    metadata_path = MODELS_DIR / "otx_threat_classifier_metadata.json"
    with open(metadata_path, 'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"   ✅ Metadata saved to: {metadata_path}")

    return OTX_MODEL_PATH


def main():
    """Main training pipeline"""

    # Load or generate training data
    real_data = load_otx_training_data()

    if real_data is not None and len(real_data) > 0:
        # Augment with synthetic data if needed
        training_data = augment_with_synthetic(real_data, target_samples=2000)
        data_source = f"mixed (real: {len(real_data)}, synthetic: {len(training_data) - len(real_data)})"
    else:
        # Use purely synthetic data
        print("\n⚠️  No real OTX data available, using synthetic data only")
        training_data = generate_synthetic_training_data(2000)
        data_source = "synthetic"

    # Prepare features
    X, y_threat, y_action, y_priority = prepare_features(training_data)

    # Train models
    models = {}
    scalers = {}
    metrics = {}

    # Train threat level classifier (multi-class: 0-3)
    models['threat_level'], scalers['threat_level'], metrics['threat_level'] = \
        train_model(X, y_threat, "threat_level")

    # Train requires_action classifier (binary)
    models['requires_action'], scalers['requires_action'], metrics['requires_action'] = \
        train_model(X, y_action, "requires_action")

    # Train is_high_priority classifier (binary)
    models['is_high_priority'], scalers['is_high_priority'], metrics['is_high_priority'] = \
        train_model(X, y_priority, "is_high_priority")

    # Training info
    training_info = {
        'total_samples': len(training_data),
        'data_source': data_source,
        'feature_count': len(FEATURE_COLUMNS),
        'target_columns': TARGET_COLUMNS
    }

    # Save model
    model_path = save_model(models, scalers, metrics, training_info)

    # Summary
    print("\n" + "="*70)
    print("✅ OTX THREAT MODEL TRAINING COMPLETE!")
    print("="*70)
    print(f"\n📊 Training Summary:")
    print(f"   Total samples: {training_info['total_samples']}")
    print(f"   Data source: {training_info['data_source']}")
    print(f"   Features: {training_info['feature_count']}")
    print(f"\n📈 Model Performance:")
    for target, m in metrics.items():
        print(f"   {target}: accuracy={m['accuracy']:.4f}, cv={m['cv_mean']:.4f}")
    print(f"\n📁 Model saved to: {model_path}")
    print("="*70)

    return model_path


if __name__ == "__main__":
    main()
