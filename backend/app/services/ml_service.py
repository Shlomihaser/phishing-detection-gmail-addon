import os
import joblib

class MLService:
    _instance = None
    _model = None
    _vectorizer = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(MLService, cls).__new__(cls)
            cls._instance._load_artifacts()
        return cls._instance

    def _load_artifacts(self):
        """Loads the model and vectorizer from the filesystem."""
        base_dir = os.path.dirname(os.path.dirname(os.path.dirname(__file__))) 
        ml_dir = os.path.join(base_dir, 'ml')
        
        model_path = os.path.join(ml_dir, 'phishing_model.joblib')
        vectorizer_path = os.path.join(ml_dir, 'tfidf_vectorizer.joblib')

        try:
            self._model = joblib.load(model_path)
            self._vectorizer = joblib.load(vectorizer_path)
            print("ML Artifacts loaded successfully.")
        except Exception as e:
            print(f"Error loading ML artifacts: {e}")
            self._model = None
            self._vectorizer = None

    def predict(self, text: str) -> dict:
        """
        Predicts whether the text is phishing or safe.
        Returns a dictionary with 'is_phishing' (bool) and 'confidence' (float 0-1).
        """
        if not self._model or not self._vectorizer:
            print("ML Model not loaded, returning default safe.")
            return {"is_phishing": False, "confidence": 0.0}

        try:
            # Transform text
            features = self._vectorizer.transform([text])
            
            # Predict class
            prediction = self._model.predict(features)[0] # 1 or 0
            
            # Predict probabilities
            probabilities = self._model.predict_proba(features)[0]
            
            # Get confidence for the predicted class
            # probabilities is [prob_safe, prob_phishing]
            phishing_prob = probabilities[1]
            
            return {
                "is_phishing": bool(prediction == 1),
                "confidence": float(phishing_prob)
            }
        except Exception as e:
            print(f"Error during ML prediction: {e}")
            return {"is_phishing": False, "confidence": 0.0}
