import os
import re
from typing import  Any
import hashlib

def generate_report(result) -> dict: 
    score = calculate_final_score([result["SA"]["score"],result["VT"]["score"],result["OWASP"]["score"]]) 
    description = result["SA"]["descriptions"]
    permissions = result["permissions"]
    risks = result["SA"]["risk_types"]
    malware_types = result["OWASP"]["malware_type"] + result["VT"]["malware_types"]
    file_hash = print(hashlib.file_digest(open(result["file_path"],'rb'),'sha256').hexdigest())
    extension_id = result["extension_id"]
    verdict = label_from_score(score)
    
    report = {
        "score": score,
        "verdict": verdict,
        "description": description,
        "permissions": permissions,
        "risks": risks,
        "malware_types": malware_types,
        "extension_id": extension_id,
        "file_hash": file_hash
    }

    print(report)

    return report


def label_from_score(s):
    if s<=25: return "OK / Clean"
    if s<=40: return "Low suspicion"
    if s<=55: return "Suspicious"
    if s<=80: return "Malicious"
    return "Highly malicious"

def calculate_final_score(scores: list[int]) -> int:
    total = 0
    count = 0

    for s in scores:
        if s is None:
            s = 0
        elif not isinstance(s, (int, float)):
            s = 0
        total += s
        count += 1

    if count == 0:
        return 0

    average = total / count
    return round(average)
