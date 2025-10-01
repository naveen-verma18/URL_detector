"""
Modular ML component for URL-based cyber attack detection.

Features:
- Data preprocessing: URL cleaning, handcrafted features, optional TF-IDF
- Training: binary (benign vs malicious) and multiclass (attack type)
- Models: Logistic Regression, Random Forest (kept to existing dependencies)
- Prediction utilities: predict_url, predict_batch
- Evaluation: accuracy, precision, recall, F1, confusion matrix
- Export: CSV/JSON for batch predictions

Usage (CLI):
  python scripts/url_ml.py train \
    --csv data/url_data.csv \
    --task multiclass \
    --model rf \
    --use-tfidf 1 \
    --save models/url_detector_multiclass.pkl

  python scripts/url_ml.py predict-url \
    --model models/url_detector_multiclass.pkl \
    --url "http://example.com/index.php?id=1"

  python scripts/url_ml.py predict-batch \
    --model models/url_detector_multiclass.pkl \
    --csv data/url_data.csv \
    --out-csv data/predictions.csv \
    --out-json data/predictions.json
"""

from __future__ import annotations

from pathlib import Path
from dataclasses import dataclass
from typing import List, Tuple, Dict, Any
import argparse
import json
import math
import re

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, TransformerMixin
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import FunctionTransformer
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)
import joblib


# --------------------------------- Utilities ---------------------------------

SUSPICIOUS_CHARS = ["'", '"', "<", ">", ";", "--", "../", "%"]
SUSPICIOUS_KEYWORDS = [
    # SQLi
    "select", "union", "drop", "insert", "update", "delete", "or 1=1", "sleep(",
    # XSS
    "<script", "javascript:", "onerror=", "onload=",
    # Command Injection
    "cmd=", ";", "&&", "||", "`", "$(",
    # Traversal / LFI/RFI
    "../", "..\\", "etc/passwd", "file://", "php://", "data://",
    # SSRF
    "http://169.254.169.254", "metadata.google.internal",
    # Cred Stuffing / brute force hints
    "login", "signin", "password=", "passwd=",
    # HPP
    "&&", "%26",
    # XXE
    "<!doctype", "<!entity", "!entity",
    # Web shell
    "webshell", ".php?", "cmd.php", "shell.php",
]


def clean_url(url: str) -> str:
    if not isinstance(url, str):
        return ""
    return url.strip()


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: Dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def count_query_params(url: str) -> int:
    if "?" not in url:
        return 0
    query = url.split("?", 1)[1]
    if not query:
        return 0
    return sum(1 for part in query.split("&") if part)


class HandcraftedFeatures(BaseEstimator, TransformerMixin):
    """Generate numeric features from raw URL strings.

    Output shape: (n_samples, n_features)
    Features include:
      0. length of URL
      1. number of query params
      2..n: presence counts for suspicious characters
      n+..: presence counts for suspicious keywords
      last: shannon entropy of URL
    """

    def __init__(self):
        self.char_list = list(SUSPICIOUS_CHARS)
        self.keyword_list = list(SUSPICIOUS_KEYWORDS)

    def fit(self, X: List[str], y: Any = None):  # noqa: N802 (sklearn API)
        return self

    def transform(self, X: List[str]):  # noqa: N802 (sklearn API)
        vectors: List[List[float]] = []
        for url in X:
            u = clean_url(str(url).lower())
            length = float(len(u))
            n_params = float(count_query_params(u))
            char_counts = [float(u.count(ch.lower())) for ch in self.char_list]
            keyword_counts = [float(u.count(kw)) for kw in self.keyword_list]
            entropy = float(shannon_entropy(u))
            vec = [length, n_params] + char_counts + keyword_counts + [entropy]
            vectors.append(vec)
        return np.array(vectors, dtype=np.float64)


def build_pipeline(model_name: str = "rf", use_tfidf: bool = True):
    components: List[Tuple[str, Any]] = []

    # Handcrafted numeric features
    components.append(("handcrafted", HandcraftedFeatures()))

    # Optional character-level TF-IDF (captures patterns like ../, <script, etc.)
    if use_tfidf:
        tfidf = TfidfVectorizer(
            analyzer="char", ngram_range=(3, 5), min_df=2, max_features=5000
        )
        # Use vectorizer directly to avoid non-picklable lambdas
        components.append(("tfidf", tfidf))

    # Combine features
    union = FeatureUnion(components)

    # Classifier
    if model_name == "logreg":
        clf = LogisticRegression(max_iter=200, n_jobs=None)
    else:
        clf = RandomForestClassifier(n_estimators=300, random_state=42)

    return Pipeline(steps=[("union", union), ("clf", clf)])


def _prepare_labels(labels: pd.Series, task: str) -> Tuple[pd.Series, List[str]]:
    labels = labels.astype(str)
    if task == "binary":
        y = labels.apply(lambda x: "benign" if x.lower() == "benign" else "malicious")
        classes = sorted(y.unique().tolist())
        return y, classes
    classes = sorted(labels.unique().tolist())
    return labels, classes


@dataclass
class TrainResult:
    model_path: Path
    classes: List[str]
    metrics: Dict[str, Any]


def train_model(
    csv_path: str | Path,
    task: str = "multiclass",
    model_name: str = "rf",
    use_tfidf: bool = True,
    save_path: str | Path | None = None,
) -> TrainResult:
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")

    data = pd.read_csv(csv_path)
    required = {"url", "label"}
    if not required.issubset(set(data.columns)):
        raise ValueError(f"CSV must contain columns {required}, got {list(data.columns)}")

    urls = data["url"].astype(str).map(clean_url)
    labels, classes = _prepare_labels(data["label"], task)

    X_train, X_test, y_train, y_test = train_test_split(
        urls, labels, test_size=0.25, random_state=42, stratify=labels
    )

    pipe = build_pipeline(model_name=model_name, use_tfidf=use_tfidf)
    pipe.fit(X_train.tolist(), y_train.tolist())

    y_pred = pipe.predict(X_test.tolist())
    acc = float(accuracy_score(y_test, y_pred))
    prec, rec, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="macro", zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred, labels=classes).tolist()

    metrics = {
        "task": task,
        "accuracy": acc,
        "precision_macro": float(prec),
        "recall_macro": float(rec),
        "f1_macro": float(f1),
        "classes": classes,
        "confusion_matrix": cm,
        "report": classification_report(y_test, y_pred, labels=classes, zero_division=0),
    }

    # Save pipeline with class labels metadata
    if save_path is None:
        models_dir = csv_path.parent.parent / "models"
        models_dir.mkdir(parents=True, exist_ok=True)
        fname = (
            f"url_detector_{task}_{model_name}{'_tfidf' if use_tfidf else ''}.pkl"
        )
        save_path = models_dir / fname
    else:
        save_path = Path(save_path)
        save_path.parent.mkdir(parents=True, exist_ok=True)

    payload = {"pipeline": pipe, "classes": classes, "task": task}
    joblib.dump(payload, save_path)

    return TrainResult(model_path=save_path, classes=classes, metrics=metrics)


def _load_model(model_path: str | Path):
    model_path = Path(model_path)
    if not model_path.exists():
        raise FileNotFoundError(f"Model not found: {model_path}")
    payload = joblib.load(model_path)
    if isinstance(payload, dict) and "pipeline" in payload:
        return payload
    # Backward-compat if only pipeline was saved
    return {"pipeline": payload, "classes": None, "task": None}


def predict_url(url: str, model_path: str | Path) -> Dict[str, Any]:
    payload = _load_model(model_path)
    pipe: Pipeline = payload["pipeline"]
    task = payload.get("task", "multiclass")
    pred = pipe.predict([clean_url(url)])[0]
    is_attack = str(pred).lower() != "benign"
    return {"url": url, "is_attack": bool(is_attack), "attack_type": str(pred), "task": task}


def predict_batch(
    csv_path: str | Path,
    model_path: str | Path,
    out_csv: str | Path | None = None,
    out_json: str | Path | None = None,
) -> List[Dict[str, Any]]:
    csv_path = Path(csv_path)
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV not found: {csv_path}")
    df = pd.read_csv(csv_path)
    if "url" not in df.columns:
        raise ValueError("CSV must contain 'url' column")
    results: List[Dict[str, Any]] = []
    for url in df["url"].astype(str).tolist():
        results.append(predict_url(url, model_path))

    if out_csv:
        out_csv = Path(out_csv)
        out_csv.parent.mkdir(parents=True, exist_ok=True)
        pd.DataFrame(results).to_csv(out_csv, index=False)
    if out_json:
        out_json = Path(out_json)
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(results, indent=2), encoding="utf-8")

    return results


# ----------------------------------- CLI -------------------------------------

def _cli_train(args):
    res = train_model(
        csv_path=args.csv,
        task=args.task,
        model_name=args.model,
        use_tfidf=bool(int(args.use_tfidf)),
        save_path=args.save,
    )
    print(json.dumps({"model_path": str(res.model_path), "metrics": res.metrics}, indent=2))


def _cli_predict_url(args):
    out = predict_url(url=args.url, model_path=args.model)
    print(json.dumps(out, indent=2))


def _cli_predict_batch(args):
    out = predict_batch(
        csv_path=args.csv,
        model_path=args.model,
        out_csv=args.out_csv,
        out_json=args.out_json,
    )
    print(json.dumps({"count": len(out)}, indent=2))


def main():
    parser = argparse.ArgumentParser(description="URL attack detection ML component")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_train = sub.add_parser("train", help="Train a model")
    p_train.add_argument("--csv", required=True, help="Path to CSV with columns url,label")
    p_train.add_argument("--task", default="multiclass", choices=["binary", "multiclass"], help="Training task")
    p_train.add_argument("--model", default="rf", choices=["rf", "logreg"], help="Classifier")
    p_train.add_argument("--use-tfidf", default="1", help="Use TF-IDF (1/0)")
    p_train.add_argument("--save", default=None, help="Path to save model .pkl")
    p_train.set_defaults(func=_cli_train)

    p_pu = sub.add_parser("predict-url", help="Predict a single URL")
    p_pu.add_argument("--model", required=True, help="Path to trained model .pkl")
    p_pu.add_argument("--url", required=True, help="URL to classify")
    p_pu.set_defaults(func=_cli_predict_url)

    p_pb = sub.add_parser("predict-batch", help="Predict all URLs in a CSV")
    p_pb.add_argument("--model", required=True, help="Path to trained model .pkl")
    p_pb.add_argument("--csv", required=True, help="CSV with column url")
    p_pb.add_argument("--out-csv", default=None, help="Optional: write predictions to CSV")
    p_pb.add_argument("--out-json", default=None, help="Optional: write predictions to JSON")
    p_pb.set_defaults(func=_cli_predict_batch)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()


