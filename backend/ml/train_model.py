import os
import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import classification_report


def train_phishing_model():
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

    required_columns = ["subject", "body", "label"]

    if not all(col in df.columns for col in required_columns):
        print(f"Error: Dataset missing one of the required columns: {required_columns}")
        print(f"Found columns: {df.columns.tolist()}")
        return

    df = df[required_columns].copy()

    def map_label(val):
        s = str(val).lower().strip()
        if s in ["spam", "phishing", "1"]:
            return 1
        elif s in ["ham", "safe", "0", "valid"]:
            return 0
        else:
            return None

    df["label"] = df["label"].apply(map_label)

    if df["label"].isnull().any():
        print(
            f"Warning: {df['label'].isnull().sum()} rows have undefined labels and will be dropped."
        )
        df = df.dropna(subset=["label"])

    df["label"] = df["label"].astype(int)

    df["subject"] = df["subject"].fillna("")
    df["body"] = df["body"].fillna("")

    print(f"Data loaded and cleaned. Shape: {df.shape}")
    print(f"Class distribution:\n{df['label'].value_counts()}")

    X = df["subject"] + " " + df["body"]
    y = df["label"]

    print("Vectorizing text data...")
    tfidf = TfidfVectorizer(stop_words="english", max_features=5000, ngram_range=(1, 2))

    X_tfidf = tfidf.fit_transform(X)

    X_train, X_test, y_train, y_test = train_test_split(
        X_tfidf, y, test_size=0.2, random_state=42
    )

    print("Training Naive Bayes model...")
    nb_model = MultinomialNB()
    nb_model.fit(X_train, y_train)

    print("Evaluating model...")
    y_pred = nb_model.predict(X_test)
    report = classification_report(
        y_test, y_pred, target_names=["Safe (0)", "Phishing (1)"]
    )
    print("\nClassification Report:\n")
    print(report)

    print(f"Saving model to {MODEL_PATH}...")
    joblib.dump(nb_model, MODEL_PATH)

    print(f"Saving vectorizer to {VECTORIZER_PATH}...")
    joblib.dump(tfidf, VECTORIZER_PATH)

    print("Done.")


if __name__ == "__main__":
    train_phishing_model()
