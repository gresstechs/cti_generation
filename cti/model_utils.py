"""
Model path utility module
Centralizes model file paths to make it easy to switch between different storage locations.
This allows models to be stored in venv and referenced consistently across the codebase.
"""

import os
import sys
from pathlib import Path

# Determine the base path for models
# Priority: venv/models > ./models > ../models
def get_model_base_path():
    """
    Get the base directory for model files.
    Checks multiple locations in order of preference:
    1. cti/venv/models (deployed in production)
    2. ./models (development local)
    3. ../models (alternative relative path)
    """
    current_dir = Path(__file__).parent

    # Priority 1: Check venv/models
    venv_models = current_dir / "venv" / "models"
    if venv_models.exists():
        return str(venv_models)

    # Priority 2: Check ./models (relative to cti/)
    local_models = current_dir / "models"
    if local_models.exists():
        return str(local_models)

    # Priority 3: Check ../models (relative to project root)
    root_models = current_dir.parent / "models"
    if root_models.exists():
        return str(root_models)

    # Fallback: return venv path (will be created on deployment)
    return str(venv_models)


# Model file paths
MODEL_BASE_PATH = get_model_base_path()

# AndMal Detector Models
ANDMAL_DETECTOR_PATH = os.path.join(MODEL_BASE_PATH, "andmal2020_detector_v1.pkl")
ANDMAL_SCALER_PATH = os.path.join(MODEL_BASE_PATH, "andmal_scaler.pkl")
ANDMAL_FEATURE_NAMES_PATH = os.path.join(MODEL_BASE_PATH, "andmal_feature_names.pkl")
ANDMAL_METADATA_PATH = os.path.join(MODEL_BASE_PATH, "andmal2020_metadata.json")

# CIC-IDS Intrusion Detector Models
INTRUSION_DETECTOR_PATH = os.path.join(MODEL_BASE_PATH, "intrusion_detector_v1.pkl")
CIC_SCALER_PATH = os.path.join(MODEL_BASE_PATH, "cic_scaler.pkl")
CIC_FEATURE_NAMES_PATH = os.path.join(MODEL_BASE_PATH, "cic_feature_names.pkl")

# Real-time ML Recommender Model
REALTIME_RECOMMENDER_PATH = os.path.join(MODEL_BASE_PATH, "realtime_ml_recommender.pkl")

# OTX Threat Classifier Model (trained on OTX data)
OTX_THREAT_CLASSIFIER_PATH = os.path.join(MODEL_BASE_PATH, "otx_threat_classifier_v1.pkl")
OTX_THREAT_CLASSIFIER_METADATA_PATH = os.path.join(MODEL_BASE_PATH, "otx_threat_classifier_metadata.json")


def verify_models_exist():
    """
    Verify that all required model files exist.
    Returns a dictionary with model names and their existence status.
    """
    models = {
        "OTX Threat Classifier": OTX_THREAT_CLASSIFIER_PATH,
        "AndMal Detector": ANDMAL_DETECTOR_PATH,
        "AndMal Scaler": ANDMAL_SCALER_PATH,
        "AndMal Feature Names": ANDMAL_FEATURE_NAMES_PATH,
        "Intrusion Detector": INTRUSION_DETECTOR_PATH,
        "CIC Scaler": CIC_SCALER_PATH,
        "Real-time Recommender": REALTIME_RECOMMENDER_PATH,
    }

    status = {}
    for name, path in models.items():
        exists = os.path.exists(path)
        status[name] = exists
        if not exists:
            print(f"⚠️  {name} missing: {path}")
        else:
            print(f"✅ {name} found: {path}")

    return status


def get_model_info():
    """
    Get information about models - location and existence.
    """
    print(f"\n📁 Model Base Path: {MODEL_BASE_PATH}")
    print(f"   Exists: {os.path.exists(MODEL_BASE_PATH)}")

    verify_models_exist()


if __name__ == "__main__":
    get_model_info()
