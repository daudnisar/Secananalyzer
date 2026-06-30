"""
timeline_builder.py
Builds a chronological timeline correlating raw events referenced by detections.
"""
from datetime import datetime


def _ts_key(ts):
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.min


def build_timeline(events: list, detections: list) -> list:
    event_by_id = {e["event_id"]: e for e in events}
    timeline = []

    for d in detections:
        for eid in d.get("event_ids", []):
            e = event_by_id.get(eid)
            if not e:
                continue
            timeline.append({
                "timestamp": e["timestamp"],
                "event_id": eid,
                "rule": d["rule"],
                "severity": d.get("severity"),
                "src_ip": e.get("src_ip"),
                "dst_ip": e.get("dst_ip"),
                "user": e.get("user"),
                "host": e.get("host"),
                "message": e.get("message"),
                "mitre": d.get("mitre"),
            })

    timeline.sort(key=lambda t: _ts_key(t["timestamp"]))
    return timeline


def timeline_summary(timeline: list) -> dict:
    if not timeline:
        return {"start": None, "end": None, "duration_minutes": 0, "event_count": 0}
    start = _ts_key(timeline[0]["timestamp"])
    end = _ts_key(timeline[-1]["timestamp"])
    duration = (end - start).total_seconds() / 60 if start != datetime.min else 0
    return {
        "start": timeline[0]["timestamp"],
        "end": timeline[-1]["timestamp"],
        "duration_minutes": round(duration, 1),
        "event_count": len(timeline),
    }
