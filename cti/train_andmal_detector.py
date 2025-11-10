#!/usr/bin/env python3
"""
Train Malware Detector on CCCS-CIC-AndMal-2020
FIXED VERSION - correct paths for cti/data structure
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import joblib
import time
import os
import json
from datetime import datetime

class AndMal2020Detector:
    """Malware Detector trained on CCCS-CIC-AndMal-2020 dataset"""
    
    def __init__(self):
        self.model_name = 'AndMal2020-Detector-v1'
        self.version = '1.0.0'
        self.dataset = 'CCCS-CIC-AndMal-2020'
        
        self.model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            verbose=1
        )
        
        self.scaler = None
        self.feature_names = None
    
    def load_data(self):
        """Load preprocessed AndMal-2020 data"""
        # FIXED: Look in cti/data/andmal_processed
        data_dir = 'cti/data/andmal_processed'
        
        print(f"\n📂 Loading preprocessed data from {data_dir}/...")
        
        if not os.path.exists(data_dir):
            print(f"❌ Data directory not found: {data_dir}")
            print(f"   Expected: {os.path.abspath(data_dir)}")
            print(f"\n   Run this first:")
            print(f"   python cti/prepare_andmal_ml_data.py")
            return None, None, None, None
        
        try:
            X_train = np.load(f'{data_dir}/X_train.npy')
            X_test = np.load(f'{data_dir}/X_test.npy')
            y_train = np.load(f'{data_dir}/y_train.npy')
            y_test = np.load(f'{data_dir}/y_test.npy')
            
            print(f"   ✅ X_train: {X_train.shape}")
            print(f"   ✅ X_test:  {X_test.shape}")
            print(f"   ✅ y_train: {y_train.shape}")
            print(f"   ✅ y_test:  {y_test.shape}")
            
            # Load scaler and feature names
            self.scaler = joblib.load('models/andmal_scaler.pkl')
            self.feature_names = joblib.load('models/andmal_feature_names.pkl')
            
            print(f"   ✅ Scaler loaded")
            print(f"   ✅ Feature names loaded ({len(self.feature_names)} features)")
            
            return X_train, X_test, y_train, y_test
            
        except Exception as e:
            print(f"❌ Error loading data: {e}")
            return None, None, None, None
    
    def train(self, X_train, y_train):
        """Train the malware detection model"""
        print(f"\n🚀 Training {self.model_name}...")
        print(f"   Dataset: {self.dataset}")
        print(f"   Samples: {len(X_train):,}")
        print(f"   Features: {X_train.shape[1]}")
        
        benign = sum(y_train == 0)
        malware = sum(y_train == 1)
        print(f"   Benign:  {benign:,} ({benign/len(y_train)*100:.1f}%)")
        print(f"   Malware: {malware:,} ({malware/len(y_train)*100:.1f}%)")
        
        start_time = time.time()
        self.model.fit(X_train, y_train)
        training_time = time.time() - start_time
        
        print(f"✅ Training complete in {training_time:.1f} seconds ({training_time/60:.1f} minutes)")
        
        return training_time
    
    def evaluate(self, X_test, y_test):
        """Evaluate model performance"""
        print(f"\n📊 Evaluating {self.model_name}...")
        
        y_pred = self.model.predict(X_test)
        y_proba = self.model.predict_proba(X_test)[:, 1]
        
        accuracy = (y_pred == y_test).mean()
        print(f"\n🎯 Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)")
        
        try:
            auc = roc_auc_score(y_test, y_proba)
            print(f"📈 ROC-AUC: {auc:.4f}")
        except:
            auc = None
        
        print("\n" + "="*70)
        print("CLASSIFICATION REPORT")
        print("="*70)
        print(classification_report(y_test, y_pred,
                                   target_names=['Benign', 'Malware'],
                                   digits=4))
        
        cm = confusion_matrix(y_test, y_pred)
        print("="*70)
        print("CONFUSION MATRIX")
        print("="*70)
        print("                 Predicted")
        print("                Benign  Malware")
        print(f"Actual Benign   {cm[0][0]:6,}  {cm[0][1]:6,}")
        print(f"       Malware  {cm[1][0]:6,}  {cm[1][1]:6,}")
        
        tn, fp, fn, tp = cm.ravel()
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
        
        print(f"\n📈 Detailed Metrics:")
        print(f"   True Positives:  {tp:6,} (Correctly identified malware)")
        print(f"   True Negatives:  {tn:6,} (Correctly identified benign)")
        print(f"   False Positives: {fp:6,} (Benign flagged as malware)")
        print(f"   False Negatives: {fn:6,} (Missed malware)")
        print(f"\n   Precision: {precision:.4f}")
        print(f"   Recall:    {recall:.4f}")
        print(f"   F1-Score:  {f1:.4f}")
        print(f"   FPR:       {fpr:.4f}")
        
        if hasattr(self.model, 'feature_importances_') and self.feature_names:
            print("\n" + "="*70)
            print("TOP 20 MOST IMPORTANT FEATURES")
            print("="*70)
            
            importances = self.model.feature_importances_
            importance_df = pd.DataFrame({
                'feature': self.feature_names,
                'importance': importances
            }).sort_values('importance', ascending=False)
            
            for i, row in importance_df.head(20).iterrows():
                print(f"   {str(row['feature'])[:50]:50s}: {row['importance']:.6f}")
        
        return {
            'accuracy': accuracy,
            'precision': precision,
            'recall': recall,
            'f1_score': f1,
            'auc': auc,
            'fpr': fpr,
            'confusion_matrix': cm.tolist()
        }
    
    def save_model(self):
        """Save trained model and metadata"""
        os.makedirs('models', exist_ok=True)
        
        model_path = 'models/andmal2020_detector_v1.pkl'
        
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'model_name': self.model_name,
            'version': self.version,
            'dataset': self.dataset,
            'feature_names': self.feature_names,
            'trained_at': datetime.now().isoformat()
        }
        
        joblib.dump(model_data, model_path)
        print(f"\n💾 Model saved: {model_path}")
        
        metadata = {
            'model_name': self.model_name,
            'version': self.version,
            'dataset': self.dataset,
            'num_features': len(self.feature_names) if self.feature_names else 0,
            'trained_at': datetime.now().isoformat()
        }
        
        with open('models/andmal2020_metadata.json', 'w') as f:
            json.dump(metadata, f, indent=2)
        
        print(f"💾 Metadata saved: models/andmal2020_metadata.json")

if __name__ == "__main__":
    print("="*70)
    print("TRAINING ANDMAL-2020 MALWARE DETECTOR")
    print("="*70)
    
    try:
        detector = AndMal2020Detector()
        
        X_train, X_test, y_train, y_test = detector.load_data()
        
        if X_train is None:
            print("\n❌ Could not load data.")
            exit(1)
        
        training_time = detector.train(X_train, y_train)
        
        metrics = detector.evaluate(X_test, y_test)
        
        detector.save_model()
        
        print("\n" + "="*70)
        print("✅ MODEL TRAINING COMPLETE!")
        print("="*70)
        
        print(f"\n📊 Performance Summary:")
        print(f"   Model: {detector.model_name} v{detector.version}")
        print(f"   Training time: {training_time:.1f} seconds")
        print(f"   Accuracy: {metrics['accuracy']*100:.2f}%")
        print(f"   Precision: {metrics['precision']*100:.2f}%")
        print(f"   Recall: {metrics['recall']*100:.2f}%")
        print(f"   F1-Score: {metrics['f1_score']:.4f}")
        if metrics['auc']:
            print(f"   ROC-AUC: {metrics['auc']:.4f}")
        
        print(f"\n💾 Model saved to: models/andmal2020_detector_v1.pkl")
        print(f"\n🚀 Next: python cti/predict_otx_with_andmal.py")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)