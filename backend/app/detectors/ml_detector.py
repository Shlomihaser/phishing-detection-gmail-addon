import os
import joblib
import logging
from typing import Optional

from app.settings.config import settings

from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.base import BaseDetector
from app.detectors.registry import DetectorRegistry

logger = logging.getLogger(__name__)

_ML_ARTIFACTS = {
    "model": None,
    "vectorizer": None,
    "loaded": False
}


@DetectorRegistry.register
class MLPhishingDetector(BaseDetector):
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

            features = self.vectorizer.transform([text_content])
            probabilities = self.model.predict_proba(features)[0]
            phishing_prob = probabilities[1] 
            
            if phishing_prob > 0.50:
                impact = float(phishing_prob * 100)
                
                confidence_pct = int(phishing_prob * 100)
                description = f"AI Model detected suspicious content (Confidence: {confidence_pct}%)"

                return DetectorResult(
                    detector_name="AI Phishing Model",
                    score_impact=impact,
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
        if settings.PHISHING_MODEL_PATH.exists() and settings.TFIDF_VECTORIZER_PATH.exists():
            _ML_ARTIFACTS["model"] = joblib.load(settings.PHISHING_MODEL_PATH)
            _ML_ARTIFACTS["vectorizer"] = joblib.load(settings.TFIDF_VECTORIZER_PATH)
            _ML_ARTIFACTS["loaded"] = True
            logger.info("ML Artifacts loaded successfully in MLPhishingDetector.")
        else:
            logger.warning(f"ML artifacts not found at {settings.ML_DIR}")
    except Exception as e:
        logger.error(f"Error loading ML artifacts: {e}")



