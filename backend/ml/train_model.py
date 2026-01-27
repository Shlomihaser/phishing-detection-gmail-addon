import os
import logging
import joblib
import pandas as pd
from typing import Tuple, Optional
import sys

# Ensure backend root is in python path to import app.
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.settings.config import settings

from sklearn.model_selection import train_test_split
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report
from sentence_transformers import SentenceTransformer

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Model Configuration
BERT_MODEL_NAME = "paraphrase-multilingual-MiniLM-L12-v2"

def get_paths() -> Tuple[str, str, str]:
    """Return paths for dataset and artifacts."""
    return str(settings.DATASET_PATH), str(settings.PHISHING_MODEL_PATH), ""


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
    # Check for Kaggle format
    if "Email Text" in df.columns and "Email Type" in df.columns:
        logger.info("Detected Kaggle Phishing Email dataset format.")
        df = df.rename(columns={"Email Text": "body", "Email Type": "label"})
        df["subject"] = "" # Kaggle dataset doesn't have subject
    
    required_columns = ["subject", "body", "label"]
    if not all(col in df.columns for col in required_columns):
        logger.error(f"Dataset missing required columns: {required_columns}")
        logger.info(f"Found columns: {df.columns.tolist()}")
        return 

    df = df[required_columns].copy()

    # Normalize labels
    def map_label(val):
        s = str(val).lower().strip()
        if s in ["spam", "phishing", "phishing email", "1"]:
            return 1
        elif s in ["ham", "safe", "safe email", "0", "valid"]:
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
    
    # LIMIT: Sample 20,000 rows for faster training if dataset is large
    MAX_SAMPLES = 20000
    if len(df) > MAX_SAMPLES:
        logger.info(f"Sampling {MAX_SAMPLES} rows from {len(df)} total rows for training...")
        df = df.sample(n=MAX_SAMPLES, random_state=42).reset_index(drop=True)

    logger.info(f"Data cleaned and sampled. Shape: {df.shape}")
    logger.info(f"Class distribution:\n{df['label'].value_counts()}")
    
    return df


def train_and_evaluate(df: pd.DataFrame) -> Tuple[LogisticRegression, SentenceTransformer]:
    """Train Logistic Regression on BERT embeddings."""
    logger.info(f"Loading BERT model: {BERT_MODEL_NAME}...")
    encoder = SentenceTransformer(BERT_MODEL_NAME)

    logger.info("Encoding text features (this may take a while)...")
    # Combine subject and body
    texts = (df["subject"] + " " + df["body"]).tolist()
    
    # Generate Embeddings
    X_embeddings = encoder.encode(texts, show_progress_bar=True, batch_size=32)
    y = df["label"]

    # Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X_embeddings, y, test_size=0.2, random_state=42
    )

    # Train Model (Logistic Regression works well with high-dim embeddings)
    logger.info("Training Logistic Regression classifier...")
    model = LogisticRegression(max_iter=1000)
    model.fit(X_train, y_train)

    # Evaluate Model
    logger.info("Evaluating model...")
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"])
    print("\nClassification Report:\n")
    print(report)

    return model, encoder


def save_artifacts(model, encoder, model_path: str, vectorizer_path: str):
    """Save trained classifier. BERT model is loaded by name, so we just save the classifier."""
    logger.info(f"Saving classifier to {model_path}...")
    joblib.dump(model, model_path)
    logger.info("Artifacts saved successfully.")


def train_phishing_model():
    """Main orchestration function."""
    dataset_path, model_path, _ = get_paths()
    
    df = load_data(dataset_path)
    if df is None:
        return

    df = clean_data(df)
    if df is None:
        return

    model, encoder = train_and_evaluate(df)
    save_artifacts(model, encoder, model_path, "")


if __name__ == "__main__":
    train_phishing_model()
