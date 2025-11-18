#!/usr/bin/env python3
import numpy as np
import joblib
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'ml_models'))
sys.path.insert(0, os.path.dirname(__file__))

from intrusion_detector import IntrusionDetector
from model_utils import INTRUSION_DETECTOR_PATH

print("="*70)
print("TESTING CTI INTRUSION DETECTOR")
print("="*70)

# Load model
print("\n📂 Loading trained model...")
detector = IntrusionDetector()
detector.load_model(INTRUSION_DETECTOR_PATH)

# Load test data
print("📂 Loading test data...")
X_test = np.load('data/cic_processed/X_test.npy')
y_test = np.load('data/cic_processed/y_test.npy')

# Test on 20 random samples
print(f"\n🧪 Testing on 20 random samples:\n")
import random
indices = random.sample(range(len(X_test)), 20)

for i, idx in enumerate(indices, 1):
    X_sample = X_test[idx:idx+1]
    y_actual = y_test[idx]
    
    prediction = detector.model.predict(X_sample)[0]
    probability = detector.model.predict_proba(X_sample)[0]
    
    pred_label = "🔴 Attack" if prediction == 1 else "🟢 Normal"
    actual_label = "Attack" if y_actual == 1 else "Normal"
    confidence = probability[prediction] * 100
    
    status = "✅" if prediction == y_actual else "❌"
    
    print(f"{status} Sample {i:2d}: Predicted={pred_label} ({confidence:.1f}%) | Actual={actual_label}")

print("\n" + "="*70)
print("✅ Model test complete!")
print("="*70)