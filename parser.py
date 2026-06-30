"""
parser.py
Parses raw logs of different formats into a list of dict records.
Supports: JSON lines, Syslog (RFC3164-ish), CEF, Windows Event (key=value), CSV-ish auth logs.
Auto-detects format per line.
"""
import json
import re
import csv
import io
from datetime import datetime


SYSLOG_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<process>[\w\-\.\/]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"
)

CEF_RE = re.compile(r"^(?P<prefix>.*)CEF:0\|(?P<rest>.*)$")

KV_RE = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _parse_json_line(line):
    try:
        return json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return None


def _parse_syslog_line(line):
    m = SYSLOG_RE.match(line.strip())
    if not m:
        return None
    d = m.groupdict()
    year = datetime.now().year
    try:
        ts = datetime.strptime(f"{year} {d['month']} {d['day']} {d['time']}", "%Y %b %d %H:%M:%S")
    except ValueError:
        ts = None
    return {
        "timestamp": ts.isoformat() if ts else None,
        "host": d["host"],
        "process": d["process"],
        "pid": d.get("pid"),
        "message": d["message"],
        "raw_format": "syslog",
    }


def _parse_cef_line(line):
    m = CEF_RE.match(line.strip())
    if not m:
        return None
    rest = m.group("rest")
    parts = rest.split("|")
    if len(parts) < 7:
        return None
    device_vendor, device_product, device_version, sig_id, name, severity = parts[0:6]
    extension = parts[6] if len(parts) > 6 else ""
    kv = dict(KV_RE.findall(extension))
    return {
        "device_vendor": device_vendor,
        "device_product": device_product,
        "signature_id": sig_id,
        "name": name,
        "severity": severity,
        "message": name,
        "raw_format": "cef",
        **kv,
    }


def _parse_kv_line(line):
    kv = dict(KV_RE.findall(line))
    if len(kv) < 2:
        return None
    kv["raw_format"] = "kv"
    kv.setdefault("message", line.strip())
    return kv


def _parse_generic_line(line):
    return {"message": line.strip(), "raw_format": "plain"}


def parse_log_text(text: str):
    """Parse raw multi-line log text into a list of normalized-ish dict records."""
    records = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue

        parsed = (
            _parse_json_line(line)
            or _parse_cef_line(line)
            or _parse_syslog_line(line)
            or _parse_kv_line(line)
            or _parse_generic_line(line)
        )
        parsed["_raw"] = line
        records.append(parsed)
    return records


def parse_log_file(path: str):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return parse_log_text(f.read())
