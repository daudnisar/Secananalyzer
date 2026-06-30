"""
threat_intel.py
Enriches detected IPs with threat intel. Uses free feeds:
- AbuseIPDB (needs free key)
- AlienVault OTX (needs free key)
If no keys configured, falls back to a local static "known-bad" sample list
so the tool still works out of the box.
"""
import os
import requests
from core.config import THREAT_INTEL

LOCAL_BLOCKLIST = {
    "203.0.113.66": "Known scanning host (sample/demo data)",
    "198.51.100.23": "Reported brute-force source (sample/demo data)",
}


def _check_abuseipdb(ip):
    key = os.getenv(THREAT_INTEL["abuseipdb"]["key_env"])
    if not key:
        return None
    try:
        r = requests.get(
            THREAT_INTEL["abuseipdb"]["url"],
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": key, "Accept": "application/json"},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json().get("data", {})
            return {
                "source": "AbuseIPDB",
                "abuse_score": data.get("abuseConfidenceScore"),
                "total_reports": data.get("totalReports"),
                "country": data.get("countryCode"),
            }
    except requests.RequestException:
        return None
    return None


def _check_otx(ip):
    key = os.getenv(THREAT_INTEL["otx"]["key_env"])
    if not key:
        return None
    try:
        r = requests.get(
            THREAT_INTEL["otx"]["url"].format(ioc=ip),
            headers={"X-OTX-API-KEY": key},
            timeout=8,
        )
        if r.status_code == 200:
            data = r.json()
            pulses = data.get("pulse_info", {}).get("count", 0)
            return {"source": "OTX", "pulse_count": pulses}
    except requests.RequestException:
        return None
    return None


def enrich_ip(ip: str) -> dict:
    if not ip:
        return {}
    result = {"ip": ip, "reputation": "unknown", "sources": []}

    if ip in LOCAL_BLOCKLIST:
        result["reputation"] = "malicious"
        result["sources"].append({"source": "local_blocklist", "note": LOCAL_BLOCKLIST[ip]})

    abuse = _check_abuseipdb(ip)
    if abuse:
        result["sources"].append(abuse)
        if (abuse.get("abuse_score") or 0) > 50:
            result["reputation"] = "malicious"
        elif (abuse.get("abuse_score") or 0) > 10 and result["reputation"] == "unknown":
            result["reputation"] = "suspicious"

    otx = _check_otx(ip)
    if otx:
        result["sources"].append(otx)
        if otx.get("pulse_count", 0) > 0 and result["reputation"] == "unknown":
            result["reputation"] = "suspicious"

    return result


def enrich_detections(detections: list) -> list:
    """Adds threat_intel info to any detection that has src_ip / src_ips."""
    enriched = []
    cache = {}
    for d in detections:
        d = dict(d)
        ips = []
        if d.get("src_ip"):
            ips.append(d["src_ip"])
        if d.get("src_ips"):
            ips.extend(d["src_ips"])

        intel = []
        for ip in set(ips):
            if ip not in cache:
                cache[ip] = enrich_ip(ip)
            intel.append(cache[ip])
        d["threat_intel"] = intel
        enriched.append(d)
    return enriched
