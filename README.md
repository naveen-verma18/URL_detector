# URL Detector II — Full Stack URL & PCAP Threat Detection

A complete, ready-to-run project:
- Python Flask backend for single URL prediction and PCAP upload, parsing, and batch detection
- React frontend (Vite) with Tailwind (CDN) and Recharts
- SQLite for upload history

## Project Structure

```
url-detector-II/
├─ app.py
├─ pcap_processor.py
├─ storage.py
├─ data/
│  ├─ url_data.csv
│  ├─ known_suspicious_ips.txt
│  ├─ raw_uploads/
│  └─ uploads/
├─ models/
│  └─ url_detector.pkl
├─ scripts/
│  ├─ train_model.py
│  └─ test_api.py
├─ frontend/
│  ├─ package.json
│  ├─ vite.config.js
│  ├─ index.html
│  └─ src/...
├─ requirements.txt
├─ README.md
└─ .gitignore
```

## Backend Setup

1. Create venv and install deps
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

2. OS dependency for pyshark (tshark)
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y tshark
# Allow non-root capture (optional)
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
# Then re-login or `newgrp wireshark`
```
If `tshark` is not available, the project will attempt a Scapy fallback (less detailed).

3. Train model (if not already)
```bash
python scripts/train_model.py
```

4. Run backend
```bash
export FLASK_DEBUG=1   # optional
python app.py
# API at http://127.0.0.1:5000
```

## Frontend Setup
```bash
cd frontend
npm install
npm run dev
# open the URL from Vite (usually http://127.0.0.1:5173)
```

## Key API Endpoints
- GET `/` → health
- POST `/predict` → body: `{ "url":"http://example.com" }` → `{ url, is_malicious }`
- POST `/upload-pcap` → multipart form: `file: sample.pcap`
  - returns: `{ upload_id, status }`
  - processing runs in background
- GET `/upload-status/<upload_id>` → returns status and paths
- GET `/results/<upload_id>` → full results JSON `{ summary, results }`
- GET `/history?page=1&page_size=10` → uploads history
- GET `/download/<upload_id>/<fmt>` → fmt=csv|json (results). For parsed records, CSV may be served from `<upload_id>_parsed.csv`.

## Heuristics
- Attack types:
  - phishing: URL contains `login, signin, bank, verify, update, secure, account`
  - malware-download: URL ends with `.exe,.zip,.scr,.msi,.jar,.bat,.cmd` or path contains `/download`
  - suspicious-redirect: URL contains `redirect, url=, dest=, destination=` or base64-like query values
  - unknown: default
- Attack success:
  - success if HTTP `status_code == 200` and executable-like `content-type`, or destination IP in `data/known_suspicious_ips.txt`
  - otherwise false; if no response details, marks `requires_manual_review`

## Sample PCAP
Public samples:
- https://wiki.wireshark.org/SampleCaptures
- https://www.malware-traffic-analysis.net/
Place a file locally and upload via the UI. You can also use a tiny PCAP with simple HTTP requests.

## Running Everything (Quick Start)
Backend:
```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
python scripts/train_model.py
python app.py
```
Frontend:
```bash
cd frontend
npm install
npm run dev
```

## Notes
- Upload limit: 100 MB PCAPs
- Filenames sanitized and stored in `data/raw_uploads/`
- Parsed CSV and results JSON saved in `data/uploads/`
- History stored in SQLite `data/uploads.db`

## Extending
- Add richer features (domain age, WHOIS, JA3 fingerprinting)
- Improve attack success heuristics with response analysis
- Replace threading with a job queue (RQ/Celery)
- Add authentication and role-based access for multi-user use
