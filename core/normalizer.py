"""
normalizer.py
Converts heterogeneous parsed records into one common event schema:

{
  event_id, timestamp, src_ip, dst_ip, user, host, action,
  status (success/fail/unknown), message, severity, raw
}
"""
import re
import uuid
from datetime import datetime

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
USER_RE = re.compile(r"\b(?:user|usr|account|src_user)[=:]\s*([A-Za-z0-9_\-\.@]+)", re.I)
USER_FOR_RE = re.compile(r"\bfor\s+(?:invalid user\s+)?([A-Za-z0-9_\-\.@]+)\s+from\b", re.I)

FAIL_WORDS = ["fail", "denied", "invalid", "error", "unauthorized", "blocked", "reject"]
SUCCESS_WORDS = ["success", "accepted", "allowed", "established", "logon", "login successful"]


def _extract_ips(text):
    return IP_RE.findall(text or "")


def _guess_status(text):
    t = (text or "").lower()
    if any(w in t for w in FAIL_WORDS):
        return "failure"
    if any(w in t for w in SUCCESS_WORDS):
        return "success"
    return "unknown"


def _guess_user(record, text):
    for key in ("user", "username", "src_user", "account", "suser"):
        if record.get(key):
            return record[key]
    m = USER_RE.search(text or "")
    if m:
        return m.group(1)
    m2 = USER_FOR_RE.search(text or "")
    return m2.group(1) if m2 else None


def normalize_record(record: dict) -> dict:
    text = record.get("message") or record.get("_raw") or ""
    ips = _extract_ips(text) or _extract_ips(str(record))

    src_ip = record.get("src") or record.get("src_ip") or record.get("source_ip")
    dst_ip = record.get("dst") or record.get("dst_ip") or record.get("dest_ip")
    if not src_ip and ips:
        src_ip = ips[0]
    if not dst_ip and len(ips) > 1:
        dst_ip = ips[1]

    ts = record.get("timestamp") or record.get("time") or record.get("@timestamp")
    if not ts:
        ts = datetime.utcnow().isoformat()

    severity = record.get("severity") or record.get("sev") or "info"

    return {
        "event_id": str(uuid.uuid4())[:8],
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "user": _guess_user(record, text),
        "host": record.get("host") or record.get("hostname"),
        "process": record.get("process") or record.get("name") or record.get("device_product"),
        "action": record.get("action") or record.get("name") or record.get("signature_id"),
        "status": _guess_status(text),
        "severity": str(severity),
        "message": text,
        "raw": record.get("_raw", text),
        "source_format": record.get("raw_format", "unknown"),
    }


def normalize_records(records: list) -> list:
    normalized = [normalize_record(r) for r in records]
    normalized.sort(key=lambda r: r["timestamp"] or "")
    return normalized
