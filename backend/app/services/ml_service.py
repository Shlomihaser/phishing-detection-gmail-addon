import os
import logging
import joblib

logger = logging.getLogger(__name__)


class MLService:
    def __init__(self):
        self._model = None
        self._vectorizer = None
        self._load_artifacts()

    def _load_artifacts(self):
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        ml_dir = os.path.join(base_dir, "ml")

        model_path = os.path.join(ml_dir, "phishing_model.joblib")
        vectorizer_path = os.path.join(ml_dir, "tfidf_vectorizer.joblib")

        try:
            self._model = joblib.load(model_path)
            self._vectorizer = joblib.load(vectorizer_path)
            logger.info("ML Artifacts loaded successfully.")
        except FileNotFoundError as e:
            logger.error(f"ML artifacts not found: {e}")
            self._model = None
            self._vectorizer = None
        except Exception as e:
            logger.error(f"Error loading ML artifacts: {e}")
            self._model = None
            self._vectorizer = None

    def predict(self, text: str) -> dict:
        if not self._model or not self._vectorizer:
            logger.warning("ML Model not loaded, returning default safe.")
            return {"is_phishing": False, "confidence": 0.0}

        try:
            features = self._vectorizer.transform([text])
            prediction = self._model.predict(features)[0]
            probabilities = self._model.predict_proba(features)[0]
            phishing_prob = probabilities[1]

            return {
                "is_phishing": bool(prediction == 1),
                "confidence": float(phishing_prob),
            }
        except Exception as e:
            logger.error(f"Error during ML prediction: {e}")
            return {"is_phishing": False, "confidence": 0.0}
