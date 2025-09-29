"""
PCAP parsing and threat analysis utilities.

Functions:
- parse_pcap(file_path, known_suspicious_ips_path) -> list[record]
- analyze_records(records, model, known_suspicious_ips_path) -> (results, summary)
- featureize_url(url) -> feature vector used by model

Record schema (dict):
{
  "timestamp": str (ISO),
  "src_ip": str,
  "dst_ip": str,
  "domain": str or "",
  "url": str or "",
  "user_agent": str or "",
  "status_code": int or None,
  "content_type": str or ""
}
"""

from pathlib import Path
from datetime import datetime
import re

# Try pyshark first; fallback to scapy if unavailable
try:
    import pyshark  # Requires tshark installed on OS
    HAS_PYSHARK = True
except Exception:
    HAS_PYSHARK = False

try:
    from scapy.all import rdpcap, Raw
    HAS_SCAPY = True
except Exception:
    HAS_SCAPY = False


def _read_known_bad(path: Path) -> set:
    if not path or not Path(path).exists():
        return set()
    out = set()
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.add(line.lower())
    return out


def _iso(ts) -> str:
    # handle ts as float seconds or pyshark DT; best-effort
    try:
        return datetime.utcfromtimestamp(float(ts)).isoformat() + "Z"
    except Exception:
        return datetime.utcnow().isoformat() + "Z"


def _build_record(
    timestamp, src_ip, dst_ip, domain="", url="", user_agent="", status_code=None, content_type=""
):
    return {
        "timestamp": timestamp,
        "src_ip": src_ip or "",
        "dst_ip": dst_ip or "",
        "domain": domain or "",
        "url": url or "",
        "user_agent": user_agent or "",
        "status_code": int(status_code) if status_code is not None else None,
        "content_type": content_type or "",
    }


essential_fields = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "domain",
    "url",
    "user_agent",
    "status_code",
    "content_type",
]


def parse_pcap(file_path: Path, known_suspicious_ips_path: Path) -> list:
    """
    Extract HTTP/HTTPS requests and URLs with fallback to DNS.
    Prefers pyshark for richer protocol details; falls back to scapy if needed.
    """
    records = []
    if HAS_PYSHARK:
        try:
            cap = pyshark.FileCapture(
                str(file_path),
                keep_packets=False,
                use_json=True,
                include_raw=False,
            )
            for pkt in cap:
                # Common layers availability is best-effort; guard with try/except
                ts = getattr(pkt, "sniff_timestamp", None) or getattr(pkt, "sniff_time", None)
                timestamp = _iso(ts)

                src_ip = getattr(getattr(pkt, "ip", None), "src", "") or getattr(getattr(pkt, "ipv6", None), "src", "")
                dst_ip = getattr(getattr(pkt, "ip", None), "dst", "") or getattr(getattr(pkt, "ipv6", None), "dst", "")

                domain = ""
                url = ""
                user_agent = ""
                status_code = None
                content_type = ""

                # HTTP
                http_layer = getattr(pkt, "http", None)
                if http_layer:
                    host = getattr(http_layer, "host", "") or getattr(http_layer, "request_full_uri", "")
                    uri = getattr(http_layer, "request_uri", "")
                    full_uri = getattr(http_layer, "request_full_uri", "") or (f"http://{host}{uri}" if host else uri)
                    domain = host or domain
                    url = full_uri or url
                    user_agent = getattr(http_layer, "user_agent", "") or user_agent
                    try:
                        status_code = int(getattr(http_layer, "response_code", "") or 0) or None
                    except Exception:
                        status_code = None
                    content_type = getattr(http_layer, "content_type", "") or content_type

                # TLS SNI (capture HTTPS domains)
                tls = getattr(pkt, "tls", None)
                if tls and not domain:
                    sni = getattr(tls, "handshake_extensions_server_name", "") or getattr(
                        tls, "handshake_extensions_server_name", ""
                    )
                    domain = sni or domain
                    if domain and not url:
                        url = f"https://{domain}/"

                # DNS fallback
                dns = getattr(pkt, "dns", None)
                if dns and not domain:
                    qname = getattr(dns, "qry_name", "")
                    domain = qname or domain

                if url or domain:
                    records.append(
                        _build_record(timestamp, src_ip, dst_ip, domain, url, user_agent, status_code, content_type)
                    )
            try:
                cap.close()
            except Exception:
                pass
            return records
        except Exception:
            # Fallback to scapy
            pass

    if HAS_SCAPY:
        try:
            packets = rdpcap(str(file_path))
            for p in packets:
                ts = getattr(p, "time", None)
                timestamp = _iso(ts)
                # scapy ip extraction (best-effort)
                src_ip = getattr(getattr(p, "payload", None), "src", "")
                dst_ip = getattr(getattr(p, "payload", None), "dst", "")
                domain = ""
                url = ""
                user_agent = ""
                status_code = None
                content_type = ""
                # Very naive HTTP extraction: look for Raw payload
                if hasattr(p, 'haslayer') and p.haslayer(Raw):
                    try:
                        payload = bytes(p[Raw].load).decode("latin-1", errors="ignore")
                        if "HTTP" in payload or "Host:" in payload:
                            host = ""
                            uri = "/"
                            for line in payload.splitlines():
                                if line.lower().startswith("host:"):
                                    host = line.split(":", 1)[1].strip()
                                elif "GET " in line or "POST " in line:
                                    parts = line.split()
                                    if len(parts) >= 2:
                                        uri = parts[1]
                                elif line.lower().startswith("user-agent:"):
                                    user_agent = line.split(":", 1)[1].strip()
                                elif line.lower().startswith("content-type:"):
                                    content_type = line.split(":", 1)[1].strip()
                                elif line.startswith("HTTP/") and len(line.split()) >= 2:
                                    try:
                                        status_code = int(line.split()[1])
                                    except Exception:
                                        pass
                            if host:
                                domain = host
                                # Scheme guess; better accuracy requires ports parsing
                                scheme = "https" if ":443" in payload else "http"
                                url = f"{scheme}://{host}{uri}"
                    except Exception:
                        pass

                if url or domain:
                    records.append(
                        _build_record(timestamp, src_ip, dst_ip, domain, url, user_agent, status_code, content_type)
                    )
            return records
        except Exception:
            return records

    # Neither parser available
    return records


# -------------------------- Model feature extraction --------------------------

def featureize_url(url: str):
    # Keep order identical to training
    return [
        len(url),              # length
        url.count("."),        # dots
        url.count("-"),        # dashes
        int(url.startswith("https")),  # https present
        url.count("@"),        # @ count
    ]


# --------------------------- Heuristic attack analysis ------------------------
MALWARE_EXTS = (".exe", ".zip", ".scr", ".msi", ".jar", ".bat", ".cmd")
PHISHING_KEYWORDS = ("login", "signin", "bank", "verify", "update", "secure", "account")
REDIRECT_KEYS = ("redirect", "url=", "dest=", "destination=")

def _is_base64_like(s: str) -> bool:
    s = s.strip().rstrip("=")
    if len(s) < 8:
        return False
    # Basic base64 shape
    return bool(re.fullmatch(r"[A-Za-z0-9+/]+", s))


def infer_attack_type(url: str, method: str | None = None) -> str:
    u = url.lower()
    # Phishing
    if any(k in u for k in PHISHING_KEYWORDS):
        return "phishing"
    # Malware download
    if u.endswith(MALWARE_EXTS) or "/download" in u:
        return "malware-download"
    # Suspicious redirect
    if any(k in u for k in REDIRECT_KEYS):
        return "suspicious-redirect"
    # Base64 payload-like in query
    q = u.split("?", 1)[1] if "?" in u else ""
    if any(_is_base64_like(part) for part in q.split("&") if "=" in part for part in [part.split("=", 1)[1]]):
        return "suspicious-redirect"
    return "unknown"


def infer_attack_success(record: dict, known_bad_ips: set) -> tuple[bool, bool]:
    """
    Returns (attack_success, requires_manual_review)
    Heuristics:
    - If status_code == 200 and content-type looks like executable/archive, mark success.
    - If dst_ip is in known suspicious list, consider success.
    - Otherwise mark as False, possibly requires manual review (if missing response info).
    """
    status = record.get("status_code")
    ctype = (record.get("content_type") or "").lower()
    dst_ip = (record.get("dst_ip") or "").lower()

    if status == 200 and any(x in ctype for x in ("application/x-msdownload", "application/zip", "application/octet-stream")):
        return True, False
    if dst_ip and dst_ip in known_bad_ips:
        return True, False

    # If we had no response info, ask for manual review
    if status is None and not ctype:
        return False, True
    return False, False


def analyze_records(records: list, model, known_suspicious_ips_path: Path):
    known_bad = _read_known_bad(known_suspicious_ips_path)

    results = []
    malicious_count = 0
    domains_counter = {}

    for r in records:
        url = r.get("url") or (f"https://{r['domain']}/" if r.get("domain") else "")
        if not url:
            # skip if no URL or domain
            continue
        feats = [featureize_url(url)]
        try:
            pred = model.predict(feats)[0]
        except Exception:
            pred = 0
        is_mal = bool(int(pred) == 1)
        if is_mal:
            malicious_count += 1

        domain = r.get("domain", "")
        if domain:
            domains_counter[domain] = domains_counter.get(domain, 0) + (1 if is_mal else 0)

        attack_type = infer_attack_type(url)
        attack_success, requires_manual_review = infer_attack_success(r, known_bad)

        out = {
            "timestamp": r.get("timestamp"),
            "src_ip": r.get("src_ip"),
            "dst_ip": r.get("dst_ip"),
            "domain": domain,
            "url": url,
            "user_agent": r.get("user_agent"),
            "status_code": r.get("status_code"),
            "content_type": r.get("content_type"),
            "is_malicious": is_mal,
            "attack_type": attack_type,
            "attack_success": attack_success,
            "requires_manual_review": requires_manual_review,
        }
        results.append(out)

    # Summary
    top_domains = sorted(domains_counter.items(), key=lambda x: x[1], reverse=True)[:10]
    time_range = (
        min((r.get("timestamp") for r in records if r.get("timestamp")), default=None),
        max((r.get("timestamp") for r in records if r.get("timestamp")), default=None),
    )
    types_breakdown = {}
    for x in results:
        t = x["attack_type"]
        types_breakdown[t] = types_breakdown.get(t, 0) + 1

    summary = {
        "total_urls": len(results),
        "malicious_count": malicious_count,
        "top_malicious_domains": top_domains,
        "time_range": time_range,
        "attack_types_breakdown": types_breakdown,
    }
    return results, summary
