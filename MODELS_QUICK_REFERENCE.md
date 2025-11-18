# Models Quick Reference Guide

## Model Locations

### In Virtual Environment (Recommended for Jenkins)
```
cti/venv/models/
├── andmal2020_detector_v1.pkl       (7.9 MB) - AndMal malware detector
├── andmal_scaler.pkl                 (226 KB) - AndMal feature scaler
├── andmal_feature_names.pkl          (84 KB)  - AndMal feature names
├── intrusion_detector_v1.pkl         (14 MB)  - CIC-IDS intrusion detector
├── cic_scaler.pkl                    (4.2 KB) - CIC-IDS feature scaler
└── realtime_ml_recommender.pkl       (11 MB)  - ML action recommender
```

## Using Models in Code

### Option 1: Using model_utils (Recommended)
```python
from model_utils import (
    ANDMAL_DETECTOR_PATH,
    ANDMAL_SCALER_PATH,
    ANDMAL_FEATURE_NAMES_PATH,
    INTRUSION_DETECTOR_PATH,
    CIC_SCALER_PATH,
    CIC_FEATURE_NAMES_PATH,
    REALTIME_RECOMMENDER_PATH
)

# Load models
model = joblib.load(ANDMAL_DETECTOR_PATH)
scaler = joblib.load(ANDMAL_SCALER_PATH)
```

### Option 2: Direct Path Usage
```python
import joblib
import os

# Model will be found automatically in venv
model = joblib.load('path/to/andmal2020_detector_v1.pkl')
```

## Model Descriptions

| Model | Purpose | Input | Output |
|-------|---------|-------|--------|
| **andmal2020_detector_v1** | Detects malware from binary features | 1000+ features | Probability [0-1] |
| **andmal_scaler** | Normalizes AndMal features | Raw features | Scaled features |
| **andmal_feature_names** | Feature names for interpretation | - | List of feature names |
| **intrusion_detector_v1** | Detects network intrusions | 78 network features | Binary: 0=Normal, 1=Attack |
| **cic_scaler** | Normalizes network features | Raw features | Scaled features |
| **realtime_ml_recommender** | Recommends security actions | Threat data | Action recommendations |

## Common Tasks

### Load AndMal Detector
```python
from model_utils import ANDMAL_DETECTOR_PATH
import joblib

model_data = joblib.load(ANDMAL_DETECTOR_PATH)
model = model_data['model']
scaler = model_data['scaler']
feature_names = model_data['feature_names']
```

### Load Intrusion Detector
```python
from cti.ml_models.intrusion_detector import IntrusionDetector

detector = IntrusionDetector()
detector.load_model()  # Uses default path from model_utils
```

### Load ML Recommender
```python
from realtime_ml_recommender import RealTimeMLRecommender

recommender = RealTimeMLRecommender()
recommender.load_model()  # Uses default path from model_utils
```

### Check If Models Exist
```python
from model_utils import verify_models_exist

status = verify_models_exist()
for name, exists in status.items():
    print(f"{name}: {'OK' if exists else 'MISSING'}")
```

### Get Model Base Path
```python
from model_utils import MODEL_BASE_PATH
import os

print(f"Models are in: {MODEL_BASE_PATH}")
print(f"Exists: {os.path.exists(MODEL_BASE_PATH)}")
```

## Training New Models

### After Training AndMal
```python
from model_utils import ANDMAL_DETECTOR_PATH
import os

model_dir = os.path.dirname(ANDMAL_DETECTOR_PATH)
os.makedirs(model_dir, exist_ok=True)
joblib.dump(model_data, ANDMAL_DETECTOR_PATH)
```

### After Training Intrusion Detector
```python
from cti.ml_models.intrusion_detector import IntrusionDetector

detector = IntrusionDetector()
detector.train(X_train, y_train)
detector.save_model()  # Automatically uses model_utils path
```

## Jenkins Deployment

Models are automatically included in the venv:
```bash
# In Jenkins
. .venv/bin/activate
python cti_pipeline.py  # Models found automatically
```

## Troubleshooting

### Model Not Found
```bash
# Check what path is being used
python -c "from cti.model_utils import MODEL_BASE_PATH, verify_models_exist; verify_models_exist()"
```

### Wrong Python Path
```python
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from model_utils import ANDMAL_DETECTOR_PATH
```

### Models Missing from venv
```bash
# Copy models manually
mkdir -p cti/venv/models
cp models/*.pkl cti/venv/models/
```

## Model Sizes
- **andmal2020_detector_v1.pkl**: 7.9 MB
- **intrusion_detector_v1.pkl**: 14 MB
- **realtime_ml_recommender.pkl**: 11 MB
- **Scalers & features**: ~314 KB
- **Total**: ~32 MB

## Files Using Models

| File | Models Used |
|------|------------|
| `cti_pipeline.py` | andmal_detector, realtime_recommender |
| `predict_otx_with_andmal.py` | andmal_detector |
| `train_andmal_detector.py` | andmal_scaler, andmal_features |
| `prepare_andmal_ml_data.py` | andmal_scaler, andmal_features (saves) |
| `intrusion_detector.py` | cic_features, intrusion_model (saves) |
| `prepare_cic_ml_data.py` | cic_scaler, cic_features (saves) |
| `test_model.py` | intrusion_detector |
| `realtime_ml_recommender.py` | recommender_model |

## Path Resolution Order

When loading models, the system checks in this order:
1. `cti/venv/models/` (Jenkins/production)
2. `./models/` (Local development)
3. `../models/` (Alternative)
4. Default: `cti/venv/models/`

This ensures models are found in both development and production environments.
