import os
import joblib
import logging
from typing import Optional

from sentence_transformers import SentenceTransformer
from app.settings.config import settings
from app.models.domain import Email
from app.models.risk import DetectorResult
from app.detectors.core.base import BaseDetector
from app.detectors.core.registry import DetectorRegistry

logger = logging.getLogger(__name__)

_ML_ARTIFACTS = {
    "model": None,
    "encoder": None, 
    "loaded": False
}


@DetectorRegistry.register
class UrgentLanguageDetector(BaseDetector):
    def __init__(self):
        _load_artifacts_if_needed()
        _load_artifacts_if_needed()
        self.model = _ML_ARTIFACTS["model"]
        self.encoder = _ML_ARTIFACTS["encoder"]

    def evaluate(self, email: Email) -> Optional[DetectorResult]:
        if not self.model or not self.encoder:
            return

        try:
            text_content = f"{email.subject or ''} {email.body_plain or ''}".strip()
            
            if not text_content:
                return

            # Transform text to BERT embeddings
            features = self.encoder.encode([text_content])
            probabilities = self.model.predict_proba(features)[0]
            phishing_prob = probabilities[1] 
            
            if phishing_prob > 0.50:
                impact = float(phishing_prob * 100)
                
                confidence_pct = int(phishing_prob * 100)
                description = f"Urgent/Suspicious language patterns detected (Confidence: {confidence_pct}%)"

                return DetectorResult(
                    detector_name="Urgent Language Analysis",
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
        # We only need the model path to exist. The encoder is loaded via library.
        if settings.PHISHING_MODEL_PATH.exists():
            _ML_ARTIFACTS["model"] = joblib.load(settings.PHISHING_MODEL_PATH)
            
            logger.info("Loading BERT encoder (this may take a moment)...")
            _ML_ARTIFACTS["encoder"] = SentenceTransformer("paraphrase-multilingual-MiniLM-L12-v2")
            
            _ML_ARTIFACTS["loaded"] = True
            logger.info("ML Artifacts loaded successfully in UrgentLanguageDetector.")
        else:
            logger.warning(f"ML artifacts not found at {settings.ML_DIR} (Model missing)")
    except Exception as e:
        logger.error(f"Error loading ML artifacts: {e}")



