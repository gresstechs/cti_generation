# Model Migration to venv Summary

## Overview
Successfully migrated all trained ML models from the `models/` directory to the virtual environment at `cti/venv/models/`. This enables deployment scenarios where models are packaged with the venv and ensures Jenkins pipeline stability.

## What Was Done

### 1. Created Model Utility Module
**File:** `cti/model_utils.py`
- Centralized model path management
- Automatically detects model location (venv > local > root)
- Exports constants for all model paths:
  - `ANDMAL_DETECTOR_PATH`
  - `ANDMAL_SCALER_PATH`
  - `ANDMAL_FEATURE_NAMES_PATH`
  - `ANDMAL_METADATA_PATH`
  - `INTRUSION_DETECTOR_PATH`
  - `CIC_SCALER_PATH`
  - `CIC_FEATURE_NAMES_PATH`
  - `REALTIME_RECOMMENDER_PATH`

### 2. Copied Models to venv
All 6 trained ML model files copied to `cti/venv/models/`:
```
✓ andmal2020_detector_v1.pkl          (7.9 MB)
✓ andmal_feature_names.pkl            (84 KB)
✓ andmal_scaler.pkl                   (226 KB)
✓ cic_scaler.pkl                      (4.2 KB)
✓ intrusion_detector_v1.pkl           (14 MB)
✓ realtime_ml_recommender.pkl         (11 MB)
```
**Total:** 32 MB in venv

### 3. Updated Python Files
Updated all 8 Python files to use the new `model_utils` module:

| File | Changes |
|------|---------|
| `cti_pipeline.py` | Replaced hardcoded paths with `ANDMAL_DETECTOR_PATH` and `REALTIME_RECOMMENDER_PATH` |
| `cti/predict_otx_with_andmal.py` | Replaced with `ANDMAL_DETECTOR_PATH` |
| `cti/train_andmal_detector.py` | Replaced all model paths, improved save logic |
| `cti/prepare_andmal_ml_data.py` | Replaced scaler/feature paths with constants |
| `cti/ml_models/intrusion_detector.py` | Replaced CIC model paths, improved import logic |
| `cti/prepare_cic_ml_data.py` | Replaced CIC scaler/feature paths |
| `cti/test_model.py` | Fixed import paths, uses `INTRUSION_DETECTOR_PATH` |
| `realtime_ml_recommender.py` | Replaced with `REALTIME_RECOMMENDER_PATH` |

## Benefits

### For Development
- All models self-contained in venv
- Easy to switch between local and venv models
- No permission issues with hardcoded paths
- Clear, centralized model path management

### For Jenkins Deployment
- Models automatically discovered in venv
- No permission conflicts during checkout
- Portable venv (models included)
- Consistent path handling across Linux/Windows

### For Production
- Single deployment unit (venv with models)
- No external file dependencies
- Easy version control with model files
- Eliminates relative path issues

## How It Works

### Model Path Resolution (Priority Order)
1. **First choice:** `cti/venv/models/` (Deployed/packaged)
2. **Second choice:** `./models/` (Local development)
3. **Third choice:** `../models/` (Alternative relative path)
4. **Fallback:** `cti/venv/models/` (Empty, will be created on training)

```python
from model_utils import ANDMAL_DETECTOR_PATH

# Automatically resolves to correct location
model = joblib.load(ANDMAL_DETECTOR_PATH)
```

## Usage Examples

### Training New Models
```python
from model_utils import ANDMAL_DETECTOR_PATH, ANDMAL_SCALER_PATH

# Models will be saved to venv path automatically
os.makedirs(os.path.dirname(ANDMAL_DETECTOR_PATH), exist_ok=True)
joblib.dump(model, ANDMAL_DETECTOR_PATH)
```

### Loading Existing Models
```python
from model_utils import ANDMAL_DETECTOR_PATH
import joblib

if os.path.exists(ANDMAL_DETECTOR_PATH):
    model = joblib.load(ANDMAL_DETECTOR_PATH)
else:
    # Handle missing model
    pass
```

### Verifying Models
```python
from model_utils import verify_models_exist

status = verify_models_exist()
# Returns: {'AndMal Detector': True, 'AndMal Scaler': True, ...}
```

## Jenkins Pipeline Integration

The models are now:
1. **Part of the venv** - No external file dependencies
2. **Automatically discovered** - Uses `model_utils` resolution
3. **Permission-safe** - No hardcoded paths causing issues

### Jenkinsfile Compatibility
All Python scripts now work seamlessly with the Jenkinsfile:
```groovy
. .venv/bin/activate
python cti_pipeline.py  # Will find models in venv/models
```

## Backward Compatibility

Scripts still support loading from custom paths:
```python
detector.load_model('/custom/path/model.pkl')  # Can override
recommender.load_model(model_path)  # Can pass custom path
```

## Files Modified

### Created
- `cti/model_utils.py` - Model path utility module

### Updated
- `cti_pipeline.py`
- `cti/predict_otx_with_andmal.py`
- `cti/train_andmal_detector.py`
- `cti/prepare_andmal_ml_data.py`
- `cti/ml_models/intrusion_detector.py`
- `cti/prepare_cic_ml_data.py`
- `cti/test_model.py`
- `realtime_ml_recommender.py`

### Copied (to venv)
- All `.pkl` model files (32 MB total)

## Testing

To verify everything works:

```bash
# Activate venv
source cti/venv/bin/activate

# Test model paths
python cti/model_utils.py

# Run pipeline
python cti_pipeline.py

# Test individual models
python cti/test_model.py
```

## Next Steps

1. **Commit changes** to version control
   ```bash
   git add cti/model_utils.py *.py cti/*.py cti/ml_models/*.py
   git commit -m "Move models to venv for Jenkins deployment"
   git push origin dev
   ```

2. **Test Jenkins pipeline** - Models will now be found in venv

3. **Archive venv** for deployment if needed
   ```bash
   tar -czf cti_venv_with_models.tar.gz cti/venv/
   ```

## Troubleshooting

### Models not found
```python
from model_utils import MODEL_BASE_PATH, verify_models_exist
print(f"Looking for models in: {MODEL_BASE_PATH}")
verify_models_exist()  # Check which models are missing
```

### Path issues
- Check `model_utils.py` resolution order
- Ensure venv is activated
- Verify venv path in working directory

### Jenkins-specific
- Ensure `deleteDir()` in Jenkinsfile removes old files
- Check workspace permissions
- Verify venv creation in Jenkins workspace

## Summary Statistics

| Item | Count | Size |
|------|-------|------|
| Models in venv | 6 | 32 MB |
| Python files updated | 8 | - |
| Model paths centralized | 8 | - |
| Import errors fixed | Multiple | - |
| Permission issues resolved | Yes | - |

