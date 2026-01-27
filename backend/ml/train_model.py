import os
import logging
import joblib
import pandas as pd
from typing import Tuple, Optional

from app.settings.config import settings
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

MAX_SAMPLES = 50000 


def get_paths() -> Tuple[str, str, str]:
    """Return paths for dataset and artifacts."""
    return (
        str(settings.DATASET_PATH),
        str(settings.PHISHING_MODEL_PATH),
        str(settings.PHISHING_VECTORIZER_PATH)
    )

def load_data(filepath: str) -> Optional[pd.DataFrame]:
    """Load dataset from CSV."""
    logger.info(f"Loading dataset from {filepath}...")
    try:
        return pd.read_csv(filepath)
    except FileNotFoundError:
        logger.error(f"Dataset not found at {filepath}")
        return 

def clean_data(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """Clean and normalize dataset labels and features."""
    required_columns = ["subject", "body", "label"]
    if not all(col in df.columns for col in required_columns):
        logger.error(f"Dataset missing required columns: {required_columns}")
        logger.info(f"Found columns: {df.columns.tolist()}")
        return 

    df = df[required_columns].copy()

    # Normalize labels
    def map_label(val):
        s = str(val).lower().strip()
        if s in ["spam", "phishing", "1"]:
            return 1
        elif s in ["ham", "safe", "0", "valid"]:
            return 0
        return

    df["label"] = df["label"].apply(map_label)
    
    # Drop invalid labels
    invalid_count = df["label"].isnull().sum()
    if invalid_count > 0:
        logger.warning(f"Dropping {invalid_count} rows with undefined labels.")
        df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    

    
    if len(df) > MAX_SAMPLES:
        logger.info(f"Sampling {MAX_SAMPLES} rows for training...")
        df = df.sample(n=MAX_SAMPLES, random_state=42).reset_index(drop=True)

    logger.info(f"Data cleaned. Shape: {df.shape}")
    logger.info(f"Class distribution:\n{df['label'].value_counts()}")
    
    return df

def train_and_evaluate(df: pd.DataFrame) -> Tuple[MultinomialNB, TfidfVectorizer]:
    """Train Naive Bayes on TF-IDF features."""
    logger.info("Vectorizing text using TF-IDF...")
    texts = (df["subject"] + " " + df["body"]).tolist()
    
    vectorizer = TfidfVectorizer(
        max_features=5000,
        stop_words='english',
        ngram_range=(1, 2)
    )
    
    X = vectorizer.fit_transform(texts)
    y = df["label"]

    # Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Train Model (Naive Bayes is great for text classification)
    logger.info("Training Multinomial Naive Bayes classifier...")
    model = MultinomialNB(alpha=0.1) # Alpha 0.1 for high sensitivity
    model.fit(X_train, y_train)

    # Evaluate Model
    logger.info("Evaluating model...")
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"])
    print("\nClassification Report:\n")
    print(report)

    return model, vectorizer

def save_artifacts(model, vectorizer, model_path: str, vectorizer_path: str):
    """Save model and vectorizer."""
    logger.info(f"Saving artifacts to {os.path.dirname(model_path)}...")
    joblib.dump(model, model_path)
    joblib.dump(vectorizer, vectorizer_path)
    logger.info("Artifacts saved successfully.")

def train_phishing_model():
    """Main orchestration function."""
    dataset_path, model_path, vectorizer_path = get_paths()
    
    df = load_data(dataset_path)
    if df is None: return

    df = clean_data(df)
    if df is None: return

    model, vectorizer = train_and_evaluate(df)
    save_artifacts(model, vectorizer, model_path, vectorizer_path)

if __name__ == "__main__":
    train_phishing_model()
