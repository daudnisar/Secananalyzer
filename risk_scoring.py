"""
risk_scoring.py
Computes a 0-100 risk score per detection and an overall incident risk score.
"""

SEVERITY_WEIGHTS = {"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}
REP_WEIGHTS = {"malicious": 30, "suspicious": 15, "unknown": 0}


def score_detection(detection: dict) -> dict:
    score = SEVERITY_WEIGHTS.get(detection.get("severity", "info"), 1)

    # bump for threat intel hits
    for intel in detection.get("threat_intel", []):
        score += REP_WEIGHTS.get(intel.get("reputation", "unknown"), 0)

    # bump for volume (e.g. brute force count, target_count)
    count = detection.get("count") or detection.get("target_count") or 0
    score += min(count, 20)

    score = max(0, min(100, score))

    if score >= 75:
        label = "Critical"
    elif score >= 50:
        label = "High"
    elif score >= 25:
        label = "Medium"
    else:
        label = "Low"

    detection = dict(detection)
    detection["risk_score"] = score
    detection["risk_label"] = label
    return detection


def score_all(detections: list) -> list:
    return [score_detection(d) for d in detections]


def overall_incident_score(scored_detections: list) -> dict:
    if not scored_detections:
        return {"score": 0, "label": "None", "top_risks": []}

    top = sorted(scored_detections, key=lambda d: d["risk_score"], reverse=True)
    overall = min(100, round(sum(d["risk_score"] for d in top) / len(top) + len(top) * 2, 1))

    if overall >= 75:
        label = "Critical"
    elif overall >= 50:
        label = "High"
    elif overall >= 25:
        label = "Medium"
    else:
        label = "Low"

    return {
        "score": overall,
        "label": label,
        "top_risks": top[:5],
    }
