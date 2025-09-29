"""
Training script for URL Detector II.

This script:
- Loads the CSV dataset from `data/url_data.csv` using robust paths
- Extracts simple URL features
- Trains a RandomForestClassifier
- Evaluates on a hold-out split
- Saves the trained model to `models/url_detector.pkl`
"""

from pathlib import Path
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import joblib


def get_project_paths():
    """Return important project paths regardless of current working directory."""
    scripts_dir = Path(__file__).resolve().parent
    project_root = scripts_dir.parent
    data_path = project_root / 'data' / 'url_data.csv'
    models_dir = project_root / 'models'
    models_dir.mkdir(parents=True, exist_ok=True)
    model_path = models_dir / 'url_detector.pkl'
    return project_root, data_path, model_path


def extract_features(url: str):
    """Extract simple numerical features from a URL string in a defined order.

    Feature order must match the one used in the API for inference.
    """
    return [
        len(url),            # 0: URL length
        url.count('.'),      # 1: number of dots
        url.count('-'),      # 2: number of dashes
        int(url.startswith('https')),  # 3: https present (strict startswith)
        url.count('@'),      # 4: number of '@'
    ]


def main():
    _, data_path, model_path = get_project_paths()

    # Load dataset
    if not data_path.exists():
        raise FileNotFoundError(f"Dataset not found at {data_path}. Please ensure the CSV exists.")
    data = pd.read_csv(data_path)

    # Basic validation
    expected_cols = {'url', 'label'}
    if not expected_cols.issubset(set(data.columns)):
        raise ValueError(f"Dataset must contain columns {expected_cols}, got {set(data.columns)}")

    # Create features and labels
    X = data['url'].astype(str).apply(extract_features).tolist()
    y = data['label'].astype(int).values

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y if len(set(y)) > 1 else None
    )

    # Train model
    model = RandomForestClassifier(n_estimators=200, max_depth=None, random_state=42)
    model.fit(X_train, y_train)

    # Evaluate
    y_pred = model.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"Hold-out accuracy: {acc:.3f}")

    # Persist model
    joblib.dump(model, model_path)
    print(f"Model saved to {model_path}")


if __name__ == '__main__':
    main()
