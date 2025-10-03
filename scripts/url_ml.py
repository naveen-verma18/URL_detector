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

<<<<<<< HEAD
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
=======
SUSPICIOUS_CHARS = ["'", '"', "<", ">", ";", "--", "../", "%", "`", "$", "&", "|", "\\", "{", "}", "[", "]", "(", ")", "*", "?", "+", "=", "~", "^"]

# Comprehensive attack-specific keywords
SUSPICIOUS_KEYWORDS = [
    # SQL Injection
    "select", "union", "drop", "insert", "update", "delete", "or 1=1", "sleep(", "waitfor", 
    "exec", "execute", "sp_", "xp_", "information_schema", "sysobjects", "syscolumns",
    "having", "group by", "order by", "limit", "offset", "concat", "char(", "ascii(",
    "substring", "mid(", "length(", "count(", "database()", "version()", "user()",
    "@@version", "@@user", "load_file", "into outfile", "into dumpfile",
    
    # Cross-Site Scripting (XSS)
    "<script", "javascript:", "onerror=", "onload=", "onmouseover=", "onclick=", 
    "onfocus=", "onblur=", "onchange=", "onsubmit=", "alert(", "confirm(", "prompt(",
    "document.cookie", "document.write", "innerhtml", "eval(", "settimeout",
    "setinterval", "fromcharcode", "unescape", "decodeuri", "atob", "btoa",
    
    # Directory Traversal
    "../", "..\\", "....//", "....\\\\", "%2e%2e%2f", "%2e%2e%5c", "etc/passwd", 
    "etc/shadow", "boot.ini", "win.ini", "system32", "windows/system32",
    
    # Command Injection
    "cmd=", "command=", "exec=", ";", "&&", "||", "`", "$(", "system(", "shell_exec",
    "passthru", "popen", "proc_open", "/bin/sh", "/bin/bash", "cmd.exe", "powershell",
    "whoami", "id", "pwd", "ls", "dir", "cat", "type", "echo", "ping", "nslookup",
    "wget", "curl", "nc", "netcat", "telnet", "ssh",
    
    # Server-Side Request Forgery (SSRF)
    "http://169.254.169.254", "metadata.google.internal", "localhost", "127.0.0.1",
    "0.0.0.0", "::1", "file://", "gopher://", "dict://", "ftp://", "tftp://",
    "ldap://", "jar://", "netdoc://", "http://metadata", "169.254.169.254",
    
    # Local/Remote File Inclusion (LFI/RFI)
    "file://", "php://", "data://", "expect://", "zip://", "compress.zlib://",
    "compress.bzip2://", "phar://", "rar://", "ogg://", "ssh2://", "glob://",
    "include=", "require=", "page=", "file=", "path=", "template=", "doc=",
    
    # Brute Force/Credential Stuffing
    "login", "signin", "password=", "passwd=", "user=", "username=", "email=",
    "admin", "administrator", "root", "guest", "test", "demo", "default",
    "auth", "authenticate", "credential", "token=", "session=",
    
    # HTTP Parameter Pollution
    "&&", "%26", "param=", "var=", "field=", "input=", "data=",
    
    # XXE (XML External Entity)
    "<!doctype", "<!entity", "!entity", "system", "public", "<?xml", "<!xml",
    "<!element", "<!attlist", "<!notation", "external", "entity",
    
    # Web Shell Upload
    "webshell", ".php?", "cmd.php", "shell.php", "c99.php", "r57.php", "wso.php",
    "upload", "file_upload", "fileupload", "upload.php", "uploader.php",
    "shell", "backdoor", "trojan", "malware", "virus",
    
    # Typosquatting indicators
    "paypal", "amazon", "google", "microsoft", "apple", "facebook", "twitter",
    "github", "stackoverflow", "wikipedia", "youtube", "instagram", "linkedin",
    "netflix", "spotify", "dropbox", "gmail", "yahoo", "hotmail", "outlook"
]

# Attack type labels for multiclass classification
ATTACK_TYPES = [
    "benign",
    "typosquatting", 
    "sql_injection",
    "xss",
    "directory_traversal",
    "command_injection", 
    "ssrf",
    "lfi_rfi",
    "brute_force",
    "http_parameter_pollution",
    "xxe",
    "web_shell_upload"
>>>>>>> origin/feature/enhanced-multiclass-ml-detector
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
<<<<<<< HEAD
    """Generate numeric features from raw URL strings.
=======
    """Generate comprehensive numeric features from raw URL strings.
>>>>>>> origin/feature/enhanced-multiclass-ml-detector

    Output shape: (n_samples, n_features)
    Features include:
      0. length of URL
<<<<<<< HEAD
      1. number of query params
      2..n: presence counts for suspicious characters
=======
      1. number of query parameters
      2. number of path segments (directories)
      3. number of subdomains
      4. has IP address instead of domain (0/1)
      5. uses HTTPS (0/1)
      6. has port number (0/1)
      7. has authentication info (user:pass@) (0/1)
      8. has fragment (#) (0/1)
      9. URL depth (number of '/' in path)
      10. domain length
      11. path length
      12. query string length
      13. number of digits in URL
      14. number of uppercase letters
      15. ratio of digits to total characters
      16. ratio of special chars to total characters
      17..n: presence counts for suspicious characters
>>>>>>> origin/feature/enhanced-multiclass-ml-detector
      n+..: presence counts for suspicious keywords
      last: shannon entropy of URL
    """

    def __init__(self):
        self.char_list = list(SUSPICIOUS_CHARS)
        self.keyword_list = list(SUSPICIOUS_KEYWORDS)

    def fit(self, X: List[str], y: Any = None):  # noqa: N802 (sklearn API)
        return self

<<<<<<< HEAD
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
=======
    def _extract_url_parts(self, url: str) -> dict:
        """Extract different parts of URL for feature calculation."""
        from urllib.parse import urlparse
        try:
            parsed = urlparse(url)
            return {
                'scheme': parsed.scheme or '',
                'netloc': parsed.netloc or '',
                'path': parsed.path or '',
                'query': parsed.query or '',
                'fragment': parsed.fragment or '',
                'hostname': parsed.hostname or '',
                'port': parsed.port
            }
        except:
            return {
                'scheme': '', 'netloc': '', 'path': '', 'query': '', 
                'fragment': '', 'hostname': '', 'port': None
            }

    def _is_ip_address(self, hostname: str) -> bool:
        """Check if hostname is an IP address."""
        import re
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        return bool(re.match(ipv4_pattern, hostname) or re.match(ipv6_pattern, hostname))

    def transform(self, X: List[str]):  # noqa: N802 (sklearn API)
        vectors: List[List[float]] = []
        for url in X:
            u = clean_url(str(url))
            u_lower = u.lower()
            
            # Parse URL components
            parts = self._extract_url_parts(u)
            
            # Basic features
            length = float(len(u))
            n_params = float(count_query_params(u))
            
            # URL structure features
            path_segments = float(len([p for p in parts['path'].split('/') if p]))
            subdomains = float(len(parts['hostname'].split('.')) - 2) if parts['hostname'] and '.' in parts['hostname'] else 0.0
            has_ip = float(self._is_ip_address(parts['hostname']) if parts['hostname'] else False)
            uses_https = float(parts['scheme'] == 'https')
            has_port = float(parts['port'] is not None)
            has_auth = float('@' in parts['netloc'])
            has_fragment = float(bool(parts['fragment']))
            url_depth = float(u.count('/') - 2) if u.startswith(('http://', 'https://')) else float(u.count('/'))
            
            # Length features
            domain_length = float(len(parts['hostname'])) if parts['hostname'] else 0.0
            path_length = float(len(parts['path']))
            query_length = float(len(parts['query']))
            
            # Character composition features
            digits = sum(1 for c in u if c.isdigit())
            uppercase = sum(1 for c in u if c.isupper())
            digit_ratio = float(digits / len(u)) if len(u) > 0 else 0.0
            special_chars = sum(1 for c in u if not c.isalnum() and c not in ':/.-_')
            special_ratio = float(special_chars / len(u)) if len(u) > 0 else 0.0
            
            # Suspicious character and keyword counts
            char_counts = [float(u_lower.count(ch.lower())) for ch in self.char_list]
            keyword_counts = [float(u_lower.count(kw)) for kw in self.keyword_list]
            
            # Entropy
            entropy = float(shannon_entropy(u))
            
            # Combine all features
            vec = [
                length, n_params, path_segments, subdomains, has_ip, uses_https,
                has_port, has_auth, has_fragment, url_depth, domain_length,
                path_length, query_length, float(digits), float(uppercase),
                digit_ratio, special_ratio
            ] + char_counts + keyword_counts + [entropy]
            
>>>>>>> origin/feature/enhanced-multiclass-ml-detector
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


<<<<<<< HEAD
=======
def detect_attack_type(url: str) -> str:
    """Automatically detect attack type based on URL patterns."""
    url_lower = url.lower()
    
    # SQL Injection patterns
    sql_patterns = ["'", "union", "select", "drop", "insert", "update", "delete", 
                   "or 1=1", "sleep(", "waitfor", "information_schema", "@@version"]
    if any(pattern in url_lower for pattern in sql_patterns):
        return "sql_injection"
    
    # XSS patterns
    xss_patterns = ["<script", "javascript:", "onerror=", "onload=", "alert(", 
                   "document.cookie", "eval(", "<iframe", "<img", "<svg"]
    if any(pattern in url_lower for pattern in xss_patterns):
        return "xss"
    
    # Directory Traversal patterns
    traversal_patterns = ["../", "..\\", "....//", "....\\\\", "%2e%2e%2f", 
                         "etc/passwd", "boot.ini", "win.ini"]
    if any(pattern in url_lower for pattern in traversal_patterns):
        return "directory_traversal"
    
    # Command Injection patterns
    cmd_patterns = ["cmd=", "command=", "exec=", "system(", "shell_exec", 
                   "whoami", "cat ", "ls ", "dir ", "ping ", "wget ", "curl "]
    if any(pattern in url_lower for pattern in cmd_patterns):
        return "command_injection"
    
    # SSRF patterns
    ssrf_patterns = ["169.254.169.254", "localhost", "127.0.0.1", "metadata", 
                    "file://", "gopher://", "dict://", "ftp://"]
    if any(pattern in url_lower for pattern in ssrf_patterns):
        return "ssrf"
    
    # LFI/RFI patterns
    lfi_patterns = ["php://", "data://", "expect://", "zip://", "compress.", 
                   "phar://", "include=", "page=", "file="]
    if any(pattern in url_lower for pattern in lfi_patterns):
        return "lfi_rfi"
    
    # XXE patterns
    xxe_patterns = ["<!doctype", "<!entity", "<?xml", "<!element", "system"]
    if any(pattern in url_lower for pattern in xxe_patterns):
        return "xxe"
    
    # Web Shell Upload patterns
    shell_patterns = ["upload", "shell.php", "cmd.php", "webshell", "backdoor", 
                     "c99.php", "r57.php", "wso.php"]
    if any(pattern in url_lower for pattern in shell_patterns):
        return "web_shell_upload"
    
    # HTTP Parameter Pollution (multiple same parameters)
    if url.count('&') > 0:
        params = url.split('?')[-1].split('&') if '?' in url else []
        param_names = [p.split('=')[0] for p in params if '=' in p]
        if len(param_names) != len(set(param_names)):
            return "http_parameter_pollution"
    
    # Brute Force patterns
    brute_patterns = ["login", "password=", "passwd=", "username=", "admin", 
                     "root", "guest", "test", "demo", "default"]
    if any(pattern in url_lower for pattern in brute_patterns):
        return "brute_force"
    
    # Typosquatting patterns (common brand misspellings)
    typo_patterns = ["gooogle", "payp4l", "amazom", "micr0soft", "fac3book", 
                    "twitt3r", "gith0b", "netfl1x", "sp0tify", "dr0pbox", 
                    "gmai1", "yah00", "hotmai1", "0utlook", "instaqram"]
    if any(pattern in url_lower for pattern in typo_patterns):
        return "typosquatting"
    
    return "benign"

>>>>>>> origin/feature/enhanced-multiclass-ml-detector
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


