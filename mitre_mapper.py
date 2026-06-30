"""
mitre_mapper.py
Maps rule names to MITRE ATT&CK tactics/techniques.
"""

MITRE_MAP = {
    "Brute Force Login Attempt": {
        "tactic": "Credential Access",
        "technique_id": "T1110",
        "technique": "Brute Force",
    },
    "Multiple Source IP Logins (possible account compromise)": {
        "tactic": "Initial Access / Defense Evasion",
        "technique_id": "T1078",
        "technique": "Valid Accounts",
    },
    "Potential Privilege Escalation": {
        "tactic": "Privilege Escalation",
        "technique_id": "T1068",
        "technique": "Exploitation for Privilege Escalation / T1548 Abuse Elevation Control",
    },
    "Suspicious Command/Process Execution": {
        "tactic": "Execution",
        "technique_id": "T1059",
        "technique": "Command and Scripting Interpreter",
    },
    "Possible Network Scanning / Reconnaissance": {
        "tactic": "Reconnaissance / Discovery",
        "technique_id": "T1046",
        "technique": "Network Service Discovery",
    },
    "Malware/AV Alert": {
        "tactic": "Execution / Impact",
        "technique_id": "T1204",
        "technique": "User Execution (malware delivery)",
    },
}


def map_detection_to_mitre(detection: dict) -> dict:
    info = MITRE_MAP.get(detection["rule"], {
        "tactic": "Unknown",
        "technique_id": "N/A",
        "technique": "Unmapped",
    })
    detection = dict(detection)
    detection["mitre"] = info
    return detection


def map_detections(detections: list) -> list:
    return [map_detection_to_mitre(d) for d in detections]
