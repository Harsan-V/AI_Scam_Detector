import json
import os
import re
from pathlib import Path

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline


BASE_DIR = Path(__file__).resolve().parent
MODEL_DIR = BASE_DIR / "models"
METRICS_PATH = MODEL_DIR / "training_metrics.json"
MODEL_PATH = MODEL_DIR / "scam_detector_model.pkl"

SPAM_CSV_PATH = Path(r"C:\Users\harsh\Downloads\spam.csv")
EMAILS_ZIP_PATH = Path(r"C:\Users\harsh\Downloads\emails.csv.zip")


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " urltoken ", text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def load_sms_spam_dataset():
    df = pd.read_csv(SPAM_CSV_PATH, encoding="latin-1")
    df = df[["v1", "v2"]].rename(columns={"v1": "label_text", "v2": "message"})
    df["label"] = df["label_text"].map({"ham": 0, "spam": 1})
    df = df.dropna(subset=["message", "label"])
    df["source"] = "sms_spam_csv"
    return df[["message", "label", "source"]]


def load_legitimate_email_sample(max_rows=5000):
    chunks = []
    loaded = 0

    for chunk in pd.read_csv(
        EMAILS_ZIP_PATH,
        compression="zip",
        usecols=["message"],
        chunksize=1000,
        on_bad_lines="skip",
    ):
        chunk = chunk.dropna(subset=["message"])
        chunks.append(chunk)
        loaded += len(chunk)
        if loaded >= max_rows:
            break

    email_df = pd.concat(chunks, ignore_index=True).head(max_rows)
    email_df["label"] = 0
    email_df["source"] = "enron_legitimate_email_sample"
    return email_df[["message", "label", "source"]]


def train():
    sms_df = load_sms_spam_dataset()
    email_df = load_legitimate_email_sample(max_rows=5000)
    dataset = pd.concat([sms_df, email_df], ignore_index=True)
    dataset["clean_message"] = dataset["message"].apply(clean_text)
    dataset = dataset[dataset["clean_message"].str.len() > 0]

    X_train, X_test, y_train, y_test = train_test_split(
        dataset["clean_message"],
        dataset["label"],
        test_size=0.25,
        random_state=42,
        stratify=dataset["label"],
    )

    model = Pipeline(
        [
            (
                "tfidf",
                TfidfVectorizer(
                    stop_words="english",
                    ngram_range=(1, 2),
                    min_df=2,
                    max_features=50000,
                ),
            ),
            (
                "classifier",
                LogisticRegression(
                    max_iter=1000,
                    class_weight="balanced",
                    random_state=42,
                ),
            ),
        ]
    )

    model.fit(X_train, y_train)
    predictions = model.predict(X_test)

    metrics = {
        "dataset_rows": int(len(dataset)),
        "sms_dataset_rows": int(len(sms_df)),
        "email_sample_rows": int(len(email_df)),
        "class_counts": {
            "legitimate": int((dataset["label"] == 0).sum()),
            "scam_or_spam": int((dataset["label"] == 1).sum()),
        },
        "accuracy": float(accuracy_score(y_test, predictions)),
        "confusion_matrix": confusion_matrix(y_test, predictions).tolist(),
        "classification_report": classification_report(
            y_test,
            predictions,
            target_names=["Legitimate", "Scam/Spam"],
            output_dict=True,
        ),
    }

    MODEL_DIR.mkdir(exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2), encoding="utf-8")

    print(f"Rows used: {metrics['dataset_rows']}")
    print(f"Legitimate: {metrics['class_counts']['legitimate']}")
    print(f"Scam/Spam: {metrics['class_counts']['scam_or_spam']}")
    print(f"Accuracy: {metrics['accuracy']:.4f}")
    print(f"Saved model: {MODEL_PATH}")
    print(f"Saved metrics: {METRICS_PATH}")


if __name__ == "__main__":
    train()
