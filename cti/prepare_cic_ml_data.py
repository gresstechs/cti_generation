#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
import sys

# Import model paths
from model_utils import CIC_SCALER_PATH, CIC_FEATURE_NAMES_PATH

def load_and_combine_data():
    """Load all CIC dataset files"""
    data_dir = 'cti/data/cicids2017'
    
    print(f"Looking in: {os.path.abspath(data_dir)}")
    
    if not os.path.exists(data_dir):
        print(f"❌ Directory not found: {data_dir}")
        return None
    
    csv_files = sorted([f for f in os.listdir(data_dir) if f.endswith('.csv')])
    
    if not csv_files:
        print("❌ No CSV files found!")
        return None
    
    print(f"📥 Found {len(csv_files)} CSV files:")
    for f in csv_files:
        print(f"   - {f}")
    
    print("\n🔄 Loading files...")
    dfs = []
    total_rows = 0
    
    for i, file in enumerate(csv_files, 1):
        filepath = os.path.join(data_dir, file)
        print(f"   {i}/{len(csv_files)}: {file}...", end=' ')
        
        try:
            # Try different encodings
            try:
                df = pd.read_csv(filepath, encoding='utf-8', low_memory=False)
            except:
                df = pd.read_csv(filepath, encoding='latin-1', low_memory=False)
            
            print(f"✅ ({len(df):,} rows)")
            total_rows += len(df)
            dfs.append(df)
        except Exception as e:
            print(f"❌ Error: {e}")
    
    if not dfs:
        return None
    
    print(f"\n🔗 Combining datasets... ({total_rows:,} total rows)")
    combined = pd.concat(dfs, ignore_index=True)
    print(f"✅ Combined successfully: {len(combined):,} rows")
    
    return combined

def clean_data(df):
    """Clean and preprocess the dataset"""
    print("\n🧹 Cleaning data...")
    
    original_size = len(df)
    
    # Standardize column names
    df.columns = df.columns.str.strip()
    print(f"   ✅ Standardized {len(df.columns)} column names")
    
    # Handle infinite values
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Fill NaN with 0
    null_counts = df.isnull().sum().sum()
    df = df.fillna(0)
    print(f"   ✅ Filled {null_counts:,} null values with 0")
    
    # Remove duplicates
    df = df.drop_duplicates()
    removed = original_size - len(df)
    print(f"   ✅ Removed {removed:,} duplicates")
    
    print(f"✅ Cleaning complete: {len(df):,} rows remain")
    
    return df

def prepare_features(df):
    """Prepare features for ML"""
    print("\n🔧 Preparing features...")
    
    # Identify label column
    label_col = None
    if 'Label' in df.columns:
        label_col = 'Label'
    elif ' Label' in df.columns:
        label_col = ' Label'
    else:
        raise ValueError("❌ Label column not found!")
    
    print(f"   Found label column: '{label_col}'")
    
    # Separate features and labels
    y = df[label_col].str.strip()
    X = df.drop(columns=[label_col])
    
    # Select only numeric columns
    numeric_cols = X.select_dtypes(include=[np.number]).columns.tolist()
    X = X[numeric_cols]
    
    print(f"   ✅ Features: {X.shape[1]} numeric columns")
    print(f"   ✅ Samples: {X.shape[0]:,} rows")
    
    # Show label distribution
    print(f"\n📊 Label Distribution:")
    label_counts = y.value_counts()
    for label, count in label_counts.items():
        pct = (count / len(y)) * 100
        print(f"   {label:40s}: {count:8,} ({pct:5.2f}%)")
    
    return X, y, numeric_cols

def create_binary_labels(y):
    """Convert to binary: Normal vs Attack"""
    print("\n🏷️  Creating binary labels (Normal vs Attack)...")
    
    y_binary = (y != 'BENIGN').astype(int)
    
    normal_count = sum(y_binary == 0)
    attack_count = sum(y_binary == 1)
    
    print(f"   Normal (0): {normal_count:8,} ({normal_count/len(y)*100:.2f}%)")
    print(f"   Attack (1): {attack_count:8,} ({attack_count/len(y)*100:.2f}%)")
    
    return y_binary

def balance_dataset(X, y):
    """Balance using undersampling"""
    print("\n⚖️  Balancing dataset...")
    
    from collections import Counter
    print(f"   Before: Normal={sum(y==0):,}, Attack={sum(y==1):,}")
    
    try:
        from imblearn.under_sampling import RandomUnderSampler
        sampler = RandomUnderSampler(random_state=42)
        X_balanced, y_balanced = sampler.fit_resample(X, y)
        print(f"   After:  Normal={sum(y_balanced==0):,}, Attack={sum(y_balanced==1):,}")
        return X_balanced, y_balanced
    except ImportError:
        print("   ⚠️  imbalanced-learn not installed")
        print("   Install with: pip install imbalanced-learn")
        print("   Continuing without balancing...")
        return X, y

def scale_features(X_train, X_test):
    """Scale features using StandardScaler"""
    print("\n📏 Scaling features...")
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    
    print("   ✅ Features scaled (mean=0, std=1)")
    
    return X_train_scaled, X_test_scaled, scaler

def save_processed_data(X_train, X_test, y_train, y_test, scaler, feature_names):
    """Save processed data"""
    output_dir = 'data/cic_processed'
    os.makedirs(output_dir, exist_ok=True)
    
    print(f"\n💾 Saving processed data to {output_dir}/...")
    
    # Save arrays
    np.save(f'{output_dir}/X_train.npy', X_train)
    np.save(f'{output_dir}/X_test.npy', X_test)
    np.save(f'{output_dir}/y_train.npy', y_train)
    np.save(f'{output_dir}/y_test.npy', y_test)
    
    print(f"   ✅ X_train: {X_train.shape} saved")
    print(f"   ✅ X_test:  {X_test.shape} saved")
    print(f"   ✅ y_train: {y_train.shape} saved")
    print(f"   ✅ y_test:  {y_test.shape} saved")
    
    # Save scaler and feature names
    model_dir = os.path.dirname(CIC_SCALER_PATH)
    os.makedirs(model_dir, exist_ok=True)

    joblib.dump(scaler, CIC_SCALER_PATH)
    joblib.dump(feature_names, CIC_FEATURE_NAMES_PATH)

    print(f"   ✅ Scaler saved to {CIC_SCALER_PATH}")
    print(f"   ✅ Feature names saved to {CIC_FEATURE_NAMES_PATH}")
    
    # Save summary
    summary = {
        'train_samples': int(X_train.shape[0]),
        'test_samples': int(X_test.shape[0]),
        'features': int(X_train.shape[1]),
        'train_normal': int(sum(y_train == 0)),
        'train_attack': int(sum(y_train == 1)),
        'test_normal': int(sum(y_test == 0)),
        'test_attack': int(sum(y_test == 1)),
        'feature_names': feature_names
    }
    
    import json
    with open(f'{output_dir}/dataset_summary.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"   ✅ Summary saved to {output_dir}/dataset_summary.json")

if __name__ == "__main__":
    print("="*70)
    print("CIC-IDS-2017 DATA PREPARATION FOR ML TRAINING")
    print("="*70)
    
    try:
        # Step 1: Load data
        df = load_and_combine_data()
        
        if df is None:
            print("\n❌ Failed to load data. Exiting.")
            exit(1)
        
        # Step 2: Clean data
        df_clean = clean_data(df)
        
        # Step 3: Prepare features
        X, y, feature_names = prepare_features(df_clean)
        
        # Step 4: Create binary labels
        y_binary = create_binary_labels(y)
        
        # Step 5: Split data (80% train, 20% test)
        print("\n✂️  Splitting data (80% train, 20% test)...")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y_binary, test_size=0.2, random_state=42, stratify=y_binary
        )
        print(f"   ✅ Train: {len(X_train):,} samples")
        print(f"   ✅ Test:  {len(X_test):,} samples")
        
        # Step 6: Balance training data
        X_train_balanced, y_train_balanced = balance_dataset(X_train, y_train)
        
        # Step 7: Scale features
        X_train_scaled, X_test_scaled, scaler = scale_features(
            X_train_balanced, X_test
        )
        
        # Step 8: Save everything
        save_processed_data(
            X_train_scaled, X_test_scaled,
            y_train_balanced, y_test,
            scaler, feature_names
        )
        
        # Final summary
        print("\n" + "="*70)
        print("✅ DATA PREPARATION COMPLETE!")
        print("="*70)
        print(f"\n📊 Final Dataset Summary:")
        print(f"   Training set:   {X_train_scaled.shape[0]:,} samples × {X_train_scaled.shape[1]} features")
        print(f"   Test set:       {X_test_scaled.shape[0]:,} samples × {X_test_scaled.shape[1]} features")
        print(f"   Class balance:  Normal={sum(y_train_balanced==0):,}, Attack={sum(y_train_balanced==1):,}")
        print(f"\n📁 Output location:")
        print(f"   data/cic_processed/")
        print(f"   models/cic_scaler.pkl")
        print(f"   models/cic_feature_names.pkl")
        print(f"\n🚀 Next step:")
        print(f"   python cti/ml_models/intrusion_detector.py")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error occurred: {e}")
        import traceback
        traceback.print_exc()
        exit(1)