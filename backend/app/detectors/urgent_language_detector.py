import os
import joblib
import logging
from typing import Optional

from app.settings.config import settings
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.core.base import BaseDetector
from app.detectors.core.registry import DetectorRegistry

logger = logging.getLogger(__name__)

_ML_ARTIFACTS = {
    "model": None,
    "vectorizer": None,
    "loaded": False
}

@DetectorRegistry.register
class UrgentLanguageDetector(BaseDetector):
    def __init__(self):
        _load_artifacts_if_needed()
        self.model = _ML_ARTIFACTS["model"]
        self.vectorizer = _ML_ARTIFACTS["vectorizer"]

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        if not self.model or not self.vectorizer:
            return

        try:
            text_content = f"{email.subject or ''} {email.body_plain or ''}".strip()
            
            if not text_content:
                return

            X = self.vectorizer.transform([text_content])
            probabilities = self.model.predict_proba(X)[0]
            phishing_prob = probabilities[1] 
            
            # TUNING: Naive Bayes is more "aggressive", so we use 0.95+ for extreme precision
            if phishing_prob > 0.90:
                # Normalize 0.95 - 1.0 to 0 - 1.0
                normalized = (phishing_prob - 0.90) / 0.05
                
                # High certainty -> High impact
                impact = 60 + (normalized * 35)
                
                confidence_pct = int(phishing_prob * 100)
                description = f"Phishing language patterns detected (Word-based Confidence: {confidence_pct}%)"

                return DetectorResult(
                    detector_name="Phishing Language Analysis",
                    score_impact=round(impact, 1),
                    description=description
                )
                
        except Exception as e:
            logger.error(f"ML Detector failed: {e}")
            return 
        return 

def _load_artifacts_if_needed():
    if _ML_ARTIFACTS["loaded"]:
        return

    try:
        model_path = settings.PHISHING_MODEL_PATH
        vec_path = settings.PHISHING_VECTORIZER_PATH

        if model_path.exists() and vec_path.exists():
            _ML_ARTIFACTS["model"] = joblib.load(model_path)
            _ML_ARTIFACTS["vectorizer"] = joblib.load(vec_path)
            _ML_ARTIFACTS["loaded"] = True
            logger.info("Classic ML artifacts (NB + TF-IDF) loaded successfully.")
        else:
            logger.warning("ML artifacts not found. Please run training script.")
    except Exception as e:
        logger.error(f"Error loading ML artifacts: {e}")
