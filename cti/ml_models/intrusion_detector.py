#!/usr/bin/env python3
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib
import time
import os
import sys

# Import model paths
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from model_utils import INTRUSION_DETECTOR_PATH, CIC_FEATURE_NAMES_PATH

class IntrusionDetector:
    """CTI-IntrusionDetector-v1 - Network Intrusion Detection Model"""
    
    def __init__(self):
        self.model_name = 'CTI-IntrusionDetector-v1'
        self.version = '1.0.0'
        
        self.model = RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=10,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
    
    def load_data(self):
        """Load processed CIC dataset"""
        print(f"\n📂 Loading processed data...")
        
        X_train = np.load('data/cic_processed/X_train.npy')
        X_test = np.load('data/cic_processed/X_test.npy')
        y_train = np.load('data/cic_processed/y_train.npy')
        y_test = np.load('data/cic_processed/y_test.npy')
        
        print(f"   ✅ Training set: {X_train.shape}")
        print(f"   ✅ Test set: {X_test.shape}")
        
        return X_train, X_test, y_train, y_test
    
    def train(self, X_train, y_train):
        """Train the model"""
        print(f"\n🚀 Training {self.model_name}...")
        print(f"   Training samples: {len(X_train):,}")
        print(f"   Features: {X_train.shape[1]}")
        
        start_time = time.time()
        self.model.fit(X_train, y_train)
        training_time = time.time() - start_time
        
        print(f"✅ Training complete in {training_time:.2f} seconds")
        return training_time
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        print(f"\n📊 Evaluating {self.model_name}...")
        
        y_pred = self.model.predict(X_test)
        
        # Accuracy
        accuracy = accuracy_score(y_test, y_pred)
        print(f"\n🎯 Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        # Classification report
        print("\n=== Classification Report ===")
        print(classification_report(y_test, y_pred, 
                                   target_names=['Normal', 'Attack'],
                                   digits=4))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\n=== Confusion Matrix ===")
        print("                 Predicted")
        print("                Normal  Attack")
        print(f"Actual Normal   {cm[0][0]:6,}  {cm[0][1]:6,}")
        print(f"       Attack   {cm[1][0]:6,}  {cm[1][1]:6,}")
        
        # Calculate metrics
        tn, fp, fn, tp = cm.ravel()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        
        print(f"\n📈 Detailed Metrics:")
        print(f"   True Positives:  {tp:6,} (Correctly identified attacks)")
        print(f"   True Negatives:  {tn:6,} (Correctly identified normal)")
        print(f"   False Positives: {fp:6,} (Normal flagged as attack)")
        print(f"   False Negatives: {fn:6,} (Missed attacks)")
        print(f"\n   Precision: {precision:.4f} (When it predicts attack, how often is it right?)")
        print(f"   Recall:    {recall:.4f} (Of all actual attacks, how many did we catch?)")
        print(f"   F1-Score:  {f1:.4f} (Harmonic mean of precision and recall)")
        
        # Feature importance
        if hasattr(self.model, 'feature_importances_'):
            print("\n=== Top 10 Most Important Features ===")
            
            # Load feature names
            try:
                feature_names = joblib.load(CIC_FEATURE_NAMES_PATH)
                importances = self.model.feature_importances_
                
                # Create dataframe and sort
                importance_df = pd.DataFrame({
                    'feature': feature_names,
                    'importance': importances
                }).sort_values('importance', ascending=False)
                
                for i, row in importance_df.head(10).iterrows():
                    print(f"   {row['feature']:40s}: {row['importance']:.4f}")
            except:
                print("   (Feature names not available)")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'confusion_matrix': cm
        }
    
    def save_model(self):
        """Save trained model"""
        # Create model directory if needed
        model_dir = os.path.dirname(INTRUSION_DETECTOR_PATH)
        os.makedirs(model_dir, exist_ok=True)

        model_data = {
            'model': self.model,
            'model_name': self.model_name,
            'version': self.version
        }

        joblib.dump(model_data, INTRUSION_DETECTOR_PATH)
        print(f"\n💾 Model saved: {INTRUSION_DETECTOR_PATH}")
    
    def load_model(self, path=None):
        """Load trained model"""
        if path is None:
            path = INTRUSION_DETECTOR_PATH
        model_data = joblib.load(path)
        self.model = model_data['model']
        self.model_name = model_data['model_name']
        self.version = model_data['version']
        
        print(f"✅ Loaded {self.model_name} v{self.version}")

if __name__ == "__main__":
    print("="*70)
    print("TRAINING CTI INTRUSION DETECTION MODEL")
    print("="*70)
    
    try:
        # Initialize detector
        detector = IntrusionDetector()
        
        # Load data
        X_train, X_test, y_train, y_test = detector.load_data()
        
        # Train
        training_time = detector.train(X_train, y_train)
        
        # Evaluate
        metrics = detector.evaluate(X_test, y_test)
        
        # Save
        detector.save_model()
        
        # Final summary
        print("\n" + "="*70)
        print("✅ MODEL TRAINING COMPLETE!")
        print("="*70)
        print(f"\n📊 Summary:")
        print(f"   Model: {detector.model_name} v{detector.version}")
        print(f"   Training time: {training_time:.2f} seconds")
        print(f"   Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"   Precision: {metrics['precision']*100:.2f}%")
        print(f"   Recall: {metrics['recall']*100:.2f}%")
        print(f"   F1-Score: {metrics['f1_score']:.4f}")
        print(f"\n💾 Saved to: {INTRUSION_DETECTOR_PATH}")
        print(f"\n🚀 Ready for deployment!")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()