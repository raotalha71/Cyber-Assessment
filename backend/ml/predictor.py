# predictor.py
# ML-based confidence prediction

import joblib
import os

from .feature_extractor import extract_features

MODEL_PATH = os.path.join(
    os.path.dirname(__file__),
    "confidence_model.pkl"
)

_model = None

def _load_model():
    global _model
    if _model is None:
        _model = joblib.load(MODEL_PATH)
    return _model


def predict_confidence(alert_text: str) -> str:
    model = _load_model()
    features = extract_features(alert_text)
    pred = model.predict([features])[0]

    return ["Low", "Medium", "High"][pred]
