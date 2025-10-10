"""
Simple test client for the URL Detector II API.

Usage:
  1) Start the API:  python app.py
  2) Run this script: python scripts/test_api.py
"""

import json
import sys
from pathlib import Path

import requests


def main():
    # Allow overriding the URL via CLI: python scripts/test_api.py http://127.0.0.1:5000
    base_url = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:5000"
    predict_url = f"{base_url.rstrip('/')}/predict"

    sample_url = "http://malicious-site.ru/free-money"
    payload = {"url": sample_url}

    try:
        resp = requests.post(predict_url, json=payload, timeout=10)
        print(f"Status: {resp.status_code}")
        try:
            print(json.dumps(resp.json(), indent=2))
        except Exception:
            print(resp.text)
    except requests.RequestException as e:
        print(f"Request failed: {e}")


if __name__ == "__main__":
    main()
