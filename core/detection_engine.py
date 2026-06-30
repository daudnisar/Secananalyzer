"""
detection_engine.py
Simple, extensible rule engine. Each rule looks at the normalized event stream
and returns Detection objects. Add new rules by appending to RULES.
"""
from collections import defaultdict, Counter
from datetime import datetime


def _parse_ts(ts):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return None


def rule_brute_force(events, threshold=5, window_minutes=10):
    """Multiple failed logins from same src_ip/user within a time window."""
    detections = []
    buckets = defaultdict(list)
    for e in events:
        if e["status"] == "failure" and ("login" in (e["message"] or "").lower()
                                          or "auth" in (e["message"] or "").lower()
                                          or "logon" in (e["message"] or "").lower()
                                          or e["process"] in ("sshd", "su", "login")):
            key = (e["src_ip"], e["user"])
            buckets[key].append(e)

    for (src_ip, user), evs in buckets.items():
        if len(evs) >= threshold:
            times = sorted(filter(None, (_parse_ts(e["timestamp"]) for e in evs)))
            if times and (times[-1] - times[0]).total_seconds() <= window_minutes * 60:
                detections.append({
                    "rule": "Brute Force Login Attempt",
                    "severity": "high",
                    "src_ip": src_ip,
                    "user": user,
                    "count": len(evs),
                    "event_ids": [e["event_id"] for e in evs],
                    "description": f"{len(evs)} failed login attempts from {src_ip} "
                                    f"(user={user}) within {window_minutes} minutes.",
                })
    return detections


def rule_impossible_geo_or_multi_ip_login(events):
    """Same user logging in successfully from many distinct IPs."""
    detections = []
    user_ips = defaultdict(set)
    user_events = defaultdict(list)
    for e in events:
        if e["status"] == "success" and e["user"] and e["src_ip"]:
            user_ips[e["user"]].add(e["src_ip"])
            user_events[e["user"]].append(e)

    for user, ips in user_ips.items():
        if len(ips) >= 3:
            detections.append({
                "rule": "Multiple Source IP Logins (possible account compromise)",
                "severity": "medium",
                "user": user,
                "src_ips": list(ips),
                "event_ids": [e["event_id"] for e in user_events[user]],
                "description": f"User '{user}' logged in successfully from {len(ips)} "
                               f"distinct IP addresses.",
            })
    return detections


def rule_privilege_escalation_keywords(events):
    keywords = ["sudo", "su:", "privilege", "elevated", "admin granted", "root access",
                "setuid", "useradd", "usermod -aG sudo", "added to group"]
    detections = []
    for e in events:
        msg = (e["message"] or "").lower()
        if any(k in msg for k in keywords):
            detections.append({
                "rule": "Potential Privilege Escalation",
                "severity": "high",
                "user": e["user"],
                "host": e["host"],
                "event_ids": [e["event_id"]],
                "description": f"Privilege-related activity detected: {e['message'][:160]}",
            })
    return detections


def rule_suspicious_process_or_command(events):
    keywords = ["powershell -enc", "base64", "wget http", "curl http", "nc -e", "ncat",
                "/etc/shadow", "rm -rf /", "mimikatz", "certutil -urlcache",
                "invoke-webrequest", "iex(", "bypass"]
    detections = []
    for e in events:
        msg = (e["message"] or "").lower()
        if any(k in msg for k in keywords):
            detections.append({
                "rule": "Suspicious Command/Process Execution",
                "severity": "critical",
                "host": e["host"],
                "user": e["user"],
                "event_ids": [e["event_id"]],
                "description": f"Suspicious command pattern: {e['message'][:160]}",
            })
    return detections


def rule_port_scan_like(events, threshold=15):
    """Same src_ip touching many distinct dst hosts/ports quickly -> recon-like behavior."""
    detections = []
    src_targets = defaultdict(set)
    src_events = defaultdict(list)
    for e in events:
        if e["src_ip"] and e["dst_ip"]:
            src_targets[e["src_ip"]].add(e["dst_ip"])
            src_events[e["src_ip"]].append(e)
    for src_ip, targets in src_targets.items():
        if len(targets) >= threshold:
            detections.append({
                "rule": "Possible Network Scanning / Reconnaissance",
                "severity": "medium",
                "src_ip": src_ip,
                "target_count": len(targets),
                "event_ids": [e["event_id"] for e in src_events[src_ip]],
                "description": f"{src_ip} contacted {len(targets)} distinct destination IPs "
                                f"— pattern consistent with scanning/recon.",
            })
    return detections


def rule_malware_av_alerts(events):
    keywords = ["virus", "malware", "trojan", "ransomware", "worm detected", "quarantine"]
    detections = []
    for e in events:
        msg = (e["message"] or "").lower()
        if any(k in msg for k in keywords):
            detections.append({
                "rule": "Malware/AV Alert",
                "severity": "critical",
                "host": e["host"],
                "event_ids": [e["event_id"]],
                "description": f"AV/Malware indicator: {e['message'][:160]}",
            })
    return detections


RULES = [
    rule_brute_force,
    rule_impossible_geo_or_multi_ip_login,
    rule_privilege_escalation_keywords,
    rule_suspicious_process_or_command,
    rule_port_scan_like,
    rule_malware_av_alerts,
]


def run_detections(events: list) -> list:
    all_detections = []
    for rule_fn in RULES:
        try:
            all_detections.extend(rule_fn(events))
        except Exception as ex:
            all_detections.append({
                "rule": f"ERROR in {rule_fn.__name__}",
                "severity": "info",
                "description": str(ex),
                "event_ids": [],
            })
    return all_detections
