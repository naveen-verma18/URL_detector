"""
Flask backend for URL Detector II (full-stack).

Features:
- Single URL prediction: POST /predict
- PCAP upload, parse, batch predict: POST /upload-pcap
- Upload status polling: GET /upload-status/<upload_id>
- Results retrieval: GET /results/<upload_id>
- History with pagination: GET /history?page=<int>&page_size=<int>
- Export results: GET /download/<upload_id>/<fmt> (fmt=json|csv)

Notes:
- Uses SQLite at data/uploads.db for uploads metadata.
- Stores raw PCAPs in data/raw_uploads/
- Stores parsed CSV and results JSON in data/uploads/
- Requires trained model at models/url_detector.pkl
"""

from pathlib import Path
from datetime import datetime
import threading
import json
import csv
import os

from flask import Flask, request, jsonify, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
import joblib

from pcap_processor import parse_pcap, analyze_records, featureize_url
# Import ML classes needed for model loading
try:
    from scripts.url_ml import HandcraftedFeatures, build_pipeline, predict_url
except ImportError:
    # Fallback if import fails
    HandcraftedFeatures = None
from storage import (
    init_db,
    insert_upload,
    update_upload_status,
    update_upload_counts_and_paths,
    get_upload,
    list_uploads,
)

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parent
DATA_DIR = PROJECT_ROOT / "data"
RAW_UPLOADS_DIR = DATA_DIR / "raw_uploads"
UPLOADS_DIR = DATA_DIR / "uploads"
MODEL_PATH = PROJECT_ROOT / "models" / "url_detector_multiclass.pkl"
FALLBACK_MODEL_PATH = PROJECT_ROOT / "models" / "url_detector.pkl"
KNOWN_SUSPICIOUS_IPS = DATA_DIR / "known_suspicious_ips.txt"

RAW_UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)

MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100 MB
ALLOWED_EXTENSIONS = {".pcap", ".pcapng"}

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
CORS(app, resources={r"/*": {"origins": "*"}})  # Simple CORS for local dev

# -----------------------------------------------------------------------------
# Model loading
# -----------------------------------------------------------------------------
def load_model():
    """Load the multiclass model, fallback to binary model if not available."""
    if MODEL_PATH.exists():
        try:
            model_data = joblib.load(MODEL_PATH)
            if isinstance(model_data, dict) and "pipeline" in model_data:
                return model_data  # Enhanced multiclass model
            else:
                return {"pipeline": model_data, "classes": None, "task": "binary"}  # Legacy format
        except Exception as e:
            print(f"Error loading multiclass model: {e}")
    
    # Fallback to binary model
    if FALLBACK_MODEL_PATH.exists():
        try:
            model = joblib.load(FALLBACK_MODEL_PATH)
            return {"pipeline": model, "classes": None, "task": "binary"}
        except Exception as e:
            print(f"Error loading fallback model: {e}")
    
    raise FileNotFoundError(
        f"No model found. Train with `python scripts/url_ml.py train --csv data/url_data_multiclass.csv --task multiclass`"
    )

try:
    MODEL = load_model()
except Exception:
    MODEL = None  # Allow server to start; /predict and others will error with helpful message

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------
def allowed_file(filename: str) -> bool:
    return Path(filename).suffix.lower() in ALLOWED_EXTENSIONS

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def ensure_model_ready():
    if MODEL is None:
        raise RuntimeError(
            "Model is not loaded. Please run `python scripts/url_ml.py train --csv data/url_data_multiclass.csv --task multiclass` and restart the server."
        )

def save_results_to_disk(upload_id: str, records: list, results: list, summary: dict):
    parsed_csv_path = UPLOADS_DIR / f"{upload_id}_parsed.csv"
    results_json_path = UPLOADS_DIR / f"{upload_id}_results.json"
    results_csv_path = UPLOADS_DIR / f"{upload_id}_results.csv"

    # Save parsed records CSV
    if records:
        with parsed_csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=[
                    "timestamp",
                    "src_ip",
                    "dst_ip",
                    "domain",
                    "url",
                    "user_agent",
                    "status_code",
                    "content_type",
                ],
            )
            writer.writeheader()
            for r in records:
                writer.writerow(r)

    # Save results JSON
    payload = {"summary": summary, "results": results}
    results_json_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    # Save results CSV
    if results:
        with results_csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(
                f,
                fieldnames=list(results[0].keys()),
            )
            writer.writeheader()
            for row in results:
                writer.writerow(row)

    return parsed_csv_path, results_json_path, results_csv_path

# -----------------------------------------------------------------------------
# Endpoints
# -----------------------------------------------------------------------------
@app.route("/", methods=["GET"])
def health():
    return "URL Detector II API is running!"

@app.route("/predict", methods=["POST"])
def predict():
    ensure_model_ready()
    data = request.get_json(silent=True) or {}
    url = data.get("url")
    if not url or not isinstance(url, str):
        return jsonify({"error": 'Invalid payload. Use {"url": "URL_HERE"}'}), 400

    try:
        # Try to use the enhanced predict_url function if available
        if predict_url and MODEL_PATH.exists():
            try:
                result = predict_url(url, MODEL_PATH)
                return jsonify({
                    "url": result["url"],
                    "is_malicious": result["is_attack"],
                    "is_attack": result["is_attack"],
                    "attack_type": result["attack_type"],
                    "task": result.get("task", "multiclass"),
                    "confidence": "high"
                })
            except Exception as e:
                print(f"Enhanced prediction failed: {e}")
                # Fall back to direct model usage
        
        # Fallback to direct model usage
        pipeline = MODEL["pipeline"]
        task = MODEL.get("task", "binary")
        
        if task == "multiclass":
            # Use the enhanced multiclass model
            pred = pipeline.predict([url])[0]
            is_attack = str(pred).lower() != "benign"
            
            return jsonify({
                "url": url,
                "is_malicious": is_attack,
                "is_attack": is_attack,
                "attack_type": str(pred),
                "task": task,
                "confidence": "high"
            })
        else:
            # Use the legacy binary model
            feats = [featureize_url(url)]
            pred = pipeline.predict(feats)[0]
            is_malicious = bool(int(pred) == 1)
            
            return jsonify({
                "url": url,
                "is_malicious": is_malicious,
                "is_attack": is_malicious,
                "attack_type": "malicious" if is_malicious else "benign",
                "task": task
            })
            
    except Exception as e:
        return jsonify({"error": f"Prediction failed: {e}"}), 500

@app.route("/upload-pcap", methods=["POST"])
def upload_pcap():
    """
    Multipart form:
      file: the .pcap/.pcapng file
    Returns:
      { upload_id, status }
    """
    ensure_model_ready()

    if "file" not in request.files:
        return jsonify({"error": "No file part in request"}), 400
    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "No selected file"}), 400

    if not allowed_file(file.filename):
        return jsonify({"error": "Unsupported file type. Use .pcap or .pcapng"}), 400

    # Sanitize filename and store
    safe_name = secure_filename(file.filename)
    upload_id = datetime.utcnow().strftime("%Y%m%d%H%M%S%f")
    raw_path = RAW_UPLOADS_DIR / f"{upload_id}__{safe_name}"
    file.save(raw_path)

    # Insert upload record with status in_progress
    init_db()
    insert_upload(
        upload_id=upload_id,
        filename=str(raw_path.name),
        uploaded_at=now_iso(),
        total_urls=0,
        malicious_count=0,
        summary_json_path="",
        results_json_path="",
        status="in_progress",
    )

    # Background parsing and analysis
    def worker():
        try:
            update_upload_status(upload_id, "parsing")
            records = parse_pcap(raw_path, KNOWN_SUSPICIOUS_IPS)

            update_upload_status(upload_id, "predicting")
            results, summary = analyze_records(records, MODEL, KNOWN_SUSPICIOUS_IPS)

            parsed_csv_path, results_json_path, _ = save_results_to_disk(
                upload_id, records, results, summary
            )

            update_upload_counts_and_paths(
                upload_id=upload_id,
                total_urls=summary.get("total_urls", 0),
                malicious_count=summary.get("malicious_count", 0),
                summary_json_path=str(UPLOADS_DIR / f"{upload_id}_results.json"),
                results_json_path=str(UPLOADS_DIR / f"{upload_id}_results.json"),
                status="completed",
            )
        except Exception as e:
            update_upload_status(upload_id, f"failed: {e}")

    threading.Thread(target=worker, daemon=True).start()

    return jsonify({"upload_id": upload_id, "status": "in_progress"})

@app.route("/upload-status/<upload_id>", methods=["GET"])
def upload_status(upload_id):
    init_db()
    row = get_upload(upload_id)
    if not row:
        return jsonify({"error": "upload_id not found"}), 404
    return jsonify(
        {
            "upload_id": row["upload_id"],
            "filename": row["filename"],
            "uploaded_at": row["uploaded_at"],
            "total_urls": row["total_urls"],
            "malicious_count": row["malicious_count"],
            "summary_json_path": row["summary_json_path"],
            "results_json_path": row["results_json_path"],
            "status": row["status"],
        }
    )

@app.route("/results/<upload_id>", methods=["GET"])
def get_results(upload_id):
    path = UPLOADS_DIR / f"{upload_id}_results.json"
    if not path.exists():
        return jsonify({"error": "results not found"}), 404
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except Exception as e:
        return jsonify({"error": f"failed to read results: {e}"}), 500
    return jsonify(data)

@app.route("/history", methods=["GET"])
def history():
    page = int(request.args.get("page", 1))
    page_size = int(request.args.get("page_size", 10))
    init_db()
    items, total = list_uploads(page=page, page_size=page_size)
    return jsonify({"page": page, "page_size": page_size, "total": total, "items": items})

@app.route("/download/<upload_id>/<fmt>", methods=["GET"])
def download(upload_id, fmt):
    """
    fmt: json or csv
    """
    if fmt not in {"json", "csv"}:
        return jsonify({"error": "fmt must be json or csv"}), 400

    path = UPLOADS_DIR / f"{upload_id}_results.{fmt}"
    if not path.exists():
        # For parsed CSV request
        if fmt == "csv":
            alt = UPLOADS_DIR / f"{upload_id}_parsed.csv"
            if alt.exists():
                return send_file(alt, as_attachment=True)
        return jsonify({"error": "file not found"}), 404

    return send_file(path, as_attachment=True)


if __name__ == "__main__":
    # Production note: use a WSGI server (gunicorn/uwsgi) in prod environments.
    debug = os.environ.get("FLASK_DEBUG", "1") == "1"
    app.run(host="0.0.0.0", port=5000, debug=debug)
