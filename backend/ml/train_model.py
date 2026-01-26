import os
import logging
import joblib
import pandas as pd
from typing import Tuple, Optional

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


def get_paths() -> Tuple[str, str, str]:
    """Return paths for dataset and artifacts."""
    base_dir = os.path.dirname(__file__)
    dataset_path = os.path.join(base_dir, "CEAS_08.csv")
    model_path = os.path.join(base_dir, "phishing_model.joblib")
    vectorizer_path = os.path.join(base_dir, "tfidf_vectorizer.joblib")
    return dataset_path, model_path, vectorizer_path


def load_data(filepath: str) -> Optional[pd.DataFrame]:
    """Load dataset from CSV."""
    logger.info(f"Loading dataset from {filepath}...")
    try:
        return pd.read_csv(filepath)
    except FileNotFoundError:
        logger.error(f"Dataset not found at {filepath}")
        return None


def clean_data(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """Clean and normalize dataset labels and features."""
    required_columns = ["subject", "body", "label"]
    if not all(col in df.columns for col in required_columns):
        logger.error(f"Dataset missing required columns: {required_columns}")
        logger.info(f"Found columns: {df.columns.tolist()}")
        return None

    df = df[required_columns].copy()

    # Normalize labels
    def map_label(val):
        s = str(val).lower().strip()
        if s in ["spam", "phishing", "1"]:
            return 1
        elif s in ["ham", "safe", "0", "valid"]:
            return 0
        return None

    df["label"] = df["label"].apply(map_label)
    
    # Drop invalid labels
    invalid_count = df["label"].isnull().sum()
    if invalid_count > 0:
        logger.warning(f"Dropping {invalid_count} rows with undefined labels.")
        df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")
    
    logger.info(f"Data cleaned. Shape: {df.shape}")
    logger.info(f"Class distribution:\n{df['label'].value_counts()}")
    
    return df


def train_and_evaluate(df: pd.DataFrame) -> Tuple[MultinomialNB, TfidfVectorizer]:
    """Train Naive Bayes model and evaluate performance."""
    logger.info("Preparing features...")
    X = df["subject"] + " " + df["body"]
    y = df["label"]

    # Initialize TF-IDF Vectorizer
    tfidf = TfidfVectorizer(stop_words="english", max_features=5000, ngram_range=(1, 2))
    X_tfidf = tfidf.fit_transform(X)

    # Split Data
    X_train, X_test, y_train, y_test = train_test_split(
        X_tfidf, y, test_size=0.2, random_state=42
    )

    # Train Model
    logger.info("Training Naive Bayes model...")
    model = MultinomialNB()
    model.fit(X_train, y_train)

    # Evaluate Model
    logger.info("Evaluating model...")
    y_pred = model.predict(X_test)
    report = classification_report(y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"])
    print("\nClassification Report:\n")
    print(report)

    return model, tfidf


def save_artifacts(model, vectorizer, model_path: str, vectorizer_path: str):
    """Save trained model and vectorizer to disk."""
    logger.info(f"Saving model to {model_path}...")
    joblib.dump(model, model_path)
    logger.info(f"Saving vectorizer to {vectorizer_path}...")
    joblib.dump(vectorizer, vectorizer_path)
    logger.info("Artifacts saved successfully.")


def train_phishing_model():
    """Main orchestration function."""
    dataset_path, model_path, vectorizer_path = get_paths()
    
    df = load_data(dataset_path)
    if df is None:
        return

    df = clean_data(df)
    if df is None:
        return

    model, vectorizer = train_and_evaluate(df)
    save_artifacts(model, vectorizer, model_path, vectorizer_path)


if __name__ == "__main__":
    train_phishing_model()
