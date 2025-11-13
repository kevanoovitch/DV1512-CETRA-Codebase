import os
import re
from typing import  Any
import hashlib
import logging
logger = logging.getLogger(__name__)
def generate_report(result) -> dict: 
    logger.info("Generating Report...")

    score = calculate_final_score([result["SA"]["score"],result["VT"]["score"],result["OWASP"]["score"]]) 
    description = result["SA"]["descriptions"]
    permissions = result["permissions"]
    risks = result["SA"]["risk_types"]
    malware_types = result["OWASP"]["malware_type"] + result["VT"]["malware_types"]
    with open(result["file_path"], "rb") as f:
        file_hash = hashlib.file_digest(f, hashlib.sha256).hexdigest()
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
    logger.info("Generated report succesfully!")

    return report


def label_from_score(s):
    if s<=25: return "OK / Clean"
    if s<=40: return "Low suspicion"
    if s<=55: return "Suspicious"
    if s<=80: return "Malicious"
    return "Highly malicious"

def calculate_final_score(scores: list[int]) -> int:

    sum = 0
    count = 0
    logger.info("Calculating score...")
    for s in scores:
        if s == None:
            s = -1 #Treat none as missing data
        if isinstance(s,float): 
            s = round(s,0)  

        if s != -1: 
            sum += s
            count += 1 #only count valid values

    if count == 0:
        return 0

    average = sum / count
    logger.info("Calculated score %d from the scores: %s", average, scores)

    return round(average)
