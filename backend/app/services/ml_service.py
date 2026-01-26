import os
import logging
import joblib

from app.models.risk import MLPrediction

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
ML_DIR = os.path.join(BASE_DIR, "ml")
PHISHING_MODEL_PATH = os.path.join(ML_DIR, "phishing_model.joblib")
TFIDF_VECTORIZER_PATH = os.path.join(ML_DIR, "tfidf_vectorizer.joblib")

class MLService:
    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self):
        try:
            self._model = joblib.load(PHISHING_MODEL_PATH)
            self._vectorizer = joblib.load(TFIDF_VECTORIZER_PATH)
            logger.info("ML Artifacts loaded successfully.")
        except Exception as e:
            logger.error(f"Error loading ML artifacts: {e}")

    def predict(self, text: str) -> MLPrediction:
        if not self._model or not self._vectorizer:
            logger.warning("ML Model not loaded")
            return MLPrediction(is_scanned=False)

        try:
            features = self._vectorizer.transform([text])
            prediction = self._model.predict(features)[0]
            probabilities = self._model.predict_proba(features)[0]
            phishing_prob = probabilities[1]

            return MLPrediction(
                is_phishing=bool(prediction == 1),
                confidence=float(phishing_prob),
                is_scanned=True
            )
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return MLPrediction(is_scanned=False)
