#!/usr/bin/env python3
"""
CCCS-CIC-AndMal-2020 Data Preparation - MEMORY EFFICIENT VERSION
Samples data to avoid memory issues on systems with limited RAM
"""

import pandas as pd
import numpy as np
import os
import glob
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import joblib
from datetime import datetime
import sys

# Import model paths
from model_utils import ANDMAL_SCALER_PATH, ANDMAL_FEATURE_NAMES_PATH

def load_andmal2020_csvs_sampled(benign_dir='cti/data/CCCS-CIC-Benign-CSVs', 
                                  malicious_dir='cti/data/CCCS-CIC-Malicious-CSVs',
                                  sample_size_per_file=5000):
    """
    Load CCCS-CIC-AndMal-2020 CSV files with SAMPLING to reduce memory usage
    
    Args:
        benign_dir: Directory with benign CSV files
        malicious_dir: Directory with malicious CSV files
        sample_size_per_file: Number of rows to sample from each file (default: 5000)
    
    This loads a SAMPLE of data instead of all 400K samples to avoid memory issues
    """
    print("="*70)
    print("LOADING CCCS-CIC-AndMal-2020 DATASET (MEMORY EFFICIENT)")
    print("="*70)
    print(f"\n⚠️  Memory-Saving Mode: Sampling {sample_size_per_file:,} rows per file")
    print(f"   This is fine for training - you'll still get ~70K-100K samples total")
    
    # Check directories
    if not os.path.exists(benign_dir):
        print(f"❌ Benign directory not found: {benign_dir}")
        return None
    
    if not os.path.exists(malicious_dir):
        print(f"❌ Malicious directory not found: {malicious_dir}")
        return None
    
    # Load benign samples
    print(f"\n📂 Loading benign samples (sampling {sample_size_per_file:,} rows per file)...")
    benign_files = sorted(glob.glob(os.path.join(benign_dir, '*.csv')))
    
    if not benign_files:
        print(f"❌ No CSV files found")
        return None
    
    print(f"   Found {len(benign_files)} benign CSV file(s)")
    
    benign_dfs = []
    total_benign = 0
    
    for i, filepath in enumerate(benign_files, 1):
        filename = os.path.basename(filepath)
        print(f"   {i}/{len(benign_files)}: {filename}...", end=' ', flush=True)
        
        try:
            # Read only a sample of rows
            df = pd.read_csv(filepath, nrows=sample_size_per_file, low_memory=False)
            df['label'] = 0
            df['category'] = 'Benign'
            print(f"✅ ({len(df):,} samples)")
            total_benign += len(df)
            benign_dfs.append(df)
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Load malicious samples
    print(f"\n📂 Loading malicious samples (sampling {sample_size_per_file:,} rows per file)...")
    malicious_files = sorted(glob.glob(os.path.join(malicious_dir, '*.csv')))
    
    if not malicious_files:
        print(f"❌ No CSV files found")
        return None
    
    print(f"   Found {len(malicious_files)} malicious CSV files")
    
    malicious_dfs = []
    total_malicious = 0
    malware_categories = {}
    
    for i, filepath in enumerate(malicious_files, 1):
        filename = os.path.basename(filepath)
        print(f"   {i}/{len(malicious_files)}: {filename}...", end=' ', flush=True)
        
        try:
            # Read only a sample of rows
            df = pd.read_csv(filepath, nrows=sample_size_per_file, low_memory=False)
            df['label'] = 1
            
            category = filename.replace('.csv', '')
            df['category'] = category
            
            if category not in malware_categories:
                malware_categories[category] = 0
            malware_categories[category] += len(df)
            
            print(f"✅ ({len(df):,} samples)")
            total_malicious += len(df)
            malicious_dfs.append(df)
        except Exception as e:
            print(f"❌ Error: {e}")
    
    # Combine dataframes
    print(f"\n🔗 Combining samples...")
    all_dfs = benign_dfs + malicious_dfs
    
    if not all_dfs:
        print("❌ No data loaded")
        return None
    
    # Combine in chunks to save memory
    combined_df = pd.concat(all_dfs, ignore_index=True)
    
    # Clear memory
    del benign_dfs
    del malicious_dfs
    del all_dfs
    
    print(f"✅ Combined {len(combined_df):,} total samples")
    print(f"\n📊 Dataset Summary:")
    print(f"   Benign samples:    {total_benign:,}")
    print(f"   Malicious samples: {total_malicious:,}")
    print(f"   Total samples:     {len(combined_df):,}")
    
    print(f"\n🦠 Malware Categories:")
    for category, count in sorted(malware_categories.items()):
        pct = (count / total_malicious) * 100
        print(f"   {category:20s}: {count:6,} ({pct:5.1f}%)")
    
    return combined_df

def clean_and_prepare_data(df):
    """Clean and prepare dataset"""
    print("\n" + "="*70)
    print("CLEANING AND PREPARING DATA")
    print("="*70)
    
    original_size = len(df)
    
    # Remove empty rows
    df = df.dropna(how='all')
    print(f"✅ Removed {original_size - len(df)} empty rows")
    
    print(f"\n📊 Dataset Info:")
    print(f"   Total columns: {len(df.columns)}")
    print(f"   Total rows: {len(df):,}")
    
    # Get numeric columns
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    
    if 'label' in numeric_cols:
        numeric_cols.remove('label')
    
    print(f"   Numeric features: {len(numeric_cols)}")
    
    # Show sample features
    print(f"\n📋 Sample Features (first 10):")
    for i, col in enumerate(numeric_cols[:10], 1):
        print(f"   {i:2d}. {col}")
    
    # Handle missing values
    print(f"\n🔧 Handling missing values...")
    null_counts = df[numeric_cols].isnull().sum().sum()
    if null_counts > 0:
        print(f"   Found {null_counts:,} null values")
        df[numeric_cols] = df[numeric_cols].fillna(0)
        print(f"   ✅ Filled with 0")
    else:
        print(f"   ✅ No null values")
    
    # Handle infinite values
    print(f"\n🔧 Handling infinite values...")
    df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], 0)
    print(f"   ✅ Replaced inf with 0")
    
    # Remove duplicates
    print(f"\n🔧 Removing duplicates...")
    df = df.drop_duplicates()
    removed = original_size - len(df)
    print(f"   ✅ Removed {removed:,} duplicates")
    
    return df, numeric_cols

def create_train_test_split(df, numeric_cols, test_size=0.2):
    """Create train/test split"""
    print("\n" + "="*70)
    print("CREATING TRAIN/TEST SPLIT")
    print("="*70)
    
    X = df[numeric_cols].values
    y = df['label'].values
    
    print(f"\n📊 Dataset Shape:")
    print(f"   Features (X): {X.shape}")
    print(f"   Labels (y):   {y.shape}")
    
    print(f"\n⚖️  Class Distribution:")
    benign_count = sum(y == 0)
    malware_count = sum(y == 1)
    print(f"   Benign (0):  {benign_count:,} ({benign_count/len(y)*100:.1f}%)")
    print(f"   Malware (1): {malware_count:,} ({malware_count/len(y)*100:.1f}%)")
    
    # Split
    print(f"\n✂️  Splitting ({int((1-test_size)*100)}% train, {int(test_size*100)}% test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=42, stratify=y
    )
    
    print(f"   ✅ Train: {len(X_train):,} samples")
    print(f"   ✅ Test:  {len(X_test):,} samples")
    
    return X_train, X_test, y_train, y_test

def scale_features(X_train, X_test):
    """Scale features"""
    print("\n" + "="*70)
    print("SCALING FEATURES")
    print("="*70)
    
    scaler = StandardScaler()
    
    print(f"   Fitting scaler...")
    X_train_scaled = scaler.fit_transform(X_train)
    
    print(f"   Transforming test data...")
    X_test_scaled = scaler.transform(X_test)
    
    print(f"   ✅ Features scaled")
    
    return X_train_scaled, X_test_scaled, scaler

def save_processed_data(X_train, X_test, y_train, y_test, scaler, feature_names):
    """Save processed data"""
    output_dir = 'cti/data/andmal_processed'
    os.makedirs(output_dir, exist_ok=True)
    
    print("\n" + "="*70)
    print("SAVING PROCESSED DATA")
    print("="*70)
    
    print(f"\n💾 Saving to {output_dir}/...")
    
    np.save(f'{output_dir}/X_train.npy', X_train)
    np.save(f'{output_dir}/X_test.npy', X_test)
    np.save(f'{output_dir}/y_train.npy', y_train)
    np.save(f'{output_dir}/y_test.npy', y_test)
    
    print(f"   ✅ X_train: {X_train.shape}")
    print(f"   ✅ X_test:  {X_test.shape}")
    
    # Create model directory if needed
    model_dir = os.path.dirname(ANDMAL_SCALER_PATH)
    os.makedirs(model_dir, exist_ok=True)

    joblib.dump(scaler, ANDMAL_SCALER_PATH)
    joblib.dump(feature_names, ANDMAL_FEATURE_NAMES_PATH)
    
    print(f"   ✅ Scaler saved")
    print(f"   ✅ Features saved ({len(feature_names)} features)")
    
    import json
    summary = {
        'dataset': 'CCCS-CIC-AndMal-2020-Sampled',
        'timestamp': datetime.utcnow().isoformat(),
        'train_samples': int(X_train.shape[0]),
        'test_samples': int(X_test.shape[0]),
        'num_features': int(X_train.shape[1]),
        'train_benign': int(sum(y_train == 0)),
        'train_malware': int(sum(y_train == 1)),
        'test_benign': int(sum(y_test == 0)),
        'test_malware': int(sum(y_test == 1))
    }
    
    with open(f'{output_dir}/dataset_info.json', 'w') as f:
        json.dump(summary, f, indent=2)
    
    print(f"   ✅ Summary saved")
    
    return summary

if __name__ == "__main__":
    print("="*70)
    print("CCCS-CIC-AndMal-2020 DATA PREPARATION (MEMORY EFFICIENT)")
    print("="*70)
    
    try:
        # Load with sampling (5000 rows per file)
        # With 14 malware files + benign files, this gives ~70K-100K samples
        # Enough for good training without memory issues
        df = load_andmal2020_csvs_sampled(
            benign_dir='cti/data/CCCS-CIC-Benign-CSVs',
            malicious_dir='cti/data/CCCS-CIC-Malicious-CSVs',
            sample_size_per_file=5000  # Adjust this if still out of memory
        )
        
        if df is None:
            sys.exit(1)
        
        # Clean and prepare
        df_clean, numeric_cols = clean_and_prepare_data(df)
        
        # Split
        X_train, X_test, y_train, y_test = create_train_test_split(
            df_clean, numeric_cols, test_size=0.2
        )
        
        # Scale
        X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
        
        # Save
        summary = save_processed_data(
            X_train_scaled, X_test_scaled,
            y_train, y_test,
            scaler, numeric_cols
        )
        
        # Final summary
        print("\n" + "="*70)
        print("✅ DATA PREPARATION COMPLETE!")
        print("="*70)
        
        print(f"\n📊 Final Dataset:")
        print(f"   Training:   {summary['train_samples']:,} samples")
        print(f"   Test:       {summary['test_samples']:,} samples")
        print(f"   Features:   {summary['num_features']:,}")
        
        print(f"\n📁 Output:")
        print(f"   cti/data/andmal_processed/")
        print(f"   {ANDMAL_SCALER_PATH}")
        
        print(f"\n🚀 Next Step:")
        print(f"   python cti/train_andmal_detector_fixed.py")
        print("="*70)
        
    except Exception as e:
        print(f"\n❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)