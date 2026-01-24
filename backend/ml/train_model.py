import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report


def train_phishing_model():
    # File paths
    DATASET_PATH = os.path.join(os.path.dirname(__file__), "CEAS_08.csv")
    MODEL_DIR = os.path.dirname(__file__)
    MODEL_PATH = os.path.join(MODEL_DIR, "phishing_model.joblib")
    VECTORIZER_PATH = os.path.join(MODEL_DIR, "tfidf_vectorizer.joblib")

    print(f"Loading dataset from {DATASET_PATH}...")

    try:
        df = pd.read_csv(DATASET_PATH)
    except FileNotFoundError:
        print(f"Error: Dataset not found at {DATASET_PATH}")
        return

    # 1. Specific Data Selection
    # Load the CSV and immediately drop all columns except subject, body, and label.
    required_columns = ["subject", "body", "label"]

    # Check if columns exist
    if not all(col in df.columns for col in required_columns):
        print(f"Error: Dataset missing one of the required columns: {required_columns}")
        print(f"Found columns: {df.columns.tolist()}")
        return

    df = df[required_columns].copy()

    # Ensure the label column is handled correctly: if it contains text (e.g., "spam"/"ham"), map it to 1 (Phishing) and 0 (Safe).
    # Assuming standard 'spam' = 1 (phishing), 'ham' = 0 (safe) mapping.
    # Adjust mapping based on actual content if needed. Converting to lowercase for safety.

    # First, let's look at unique labels to be sure, but we will apply a robust mapping logic.
    # We will assume:
    # 1 (Phishing) -> 'spam', 'phishing', '1'
    # 0 (Safe) -> 'ham', 'safe', '0', 'valid'

    def map_label(val):
        s = str(val).lower().strip()
        if s in ["spam", "phishing", "1"]:
            return 1
        elif s in ["ham", "safe", "0", "valid"]:
            return 0
        else:
            return None  # Handle unexpected labels later if needed

    df["label"] = df["label"].apply(map_label)

    # Drop rows where label interpretation failed
    if df["label"].isnull().any():
        print(
            f"Warning: {df['label'].isnull().sum()} rows have undefined labels and will be dropped."
        )
        df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)

    # Handle missing values by replacing NaN with an empty string in the text columns.
    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")

    print(f"Data loaded and cleaned. Shape: {df.shape}")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    # 2. Text Synthesis
    # Create a combined feature: X = df['subject'] + " " + df['body'].
    X = df["subject"] + " " + df["body"]
    y = df["label"]

    # 3. Vectorization (TF-IDF)
    print("Vectorizing text data...")
    # Initialize TfidfVectorizer(stop_words='english', max_features=5000, ngram_range=(1,2)).
    tfidf = TfidfVectorizer(stop_words="english", max_features=5000, ngram_range=(1, 2))

    X_tfidf = tfidf.fit_transform(X)

    # 4. Training & Evaluation
    # Split the data (80% train, 20% test).
    X_train, X_test, y_train, y_test = train_test_split(
        X_tfidf, y, test_size=0.2, random_state=42
    )

    # Use MultinomialNB.
    print("Training Naive Bayes model...")
    nb_model = MultinomialNB()
    nb_model.fit(X_train, y_train)

    # Print a detailed classification_report so I can see the Precision and Recall (crucial for phishing).
    print("Evaluating model...")
    y_pred = nb_model.predict(X_test)
    report = classification_report(
        y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]
    )
    print("\nClassification Report:\n")
    print(report)

    # Use joblib to save the model and the vectorizer to backend/ml/.
    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(nb_model, MODEL_PATH)

    print(f"Saving vectorizer to {VECTORIZER_PATH}...")
    joblib.dump(tfidf, VECTORIZER_PATH)

    print("Done.")


if __name__ == "__main__":
    train_phishing_model()
