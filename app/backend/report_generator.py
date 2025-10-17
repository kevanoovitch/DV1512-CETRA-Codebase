import os
import re
from typing import  Any


#FIXME: Don't use hardcoded scores
dummy_dict: dict[str, Any] = {
"SecureAnnex": {"score": 40},
"VirusTotal": {"score": 30},
"OPSWAT": {"score": 20}
}

        
def generate_report(result) -> dict: 
    """arg a dictionary returns parsed and normalize dict based on all API's output"""

    final_report: dict[str, Any] = {
    "score": 0,
    "verdict": "",
    "description": "",
    "permissions": [],
    "risks": [],
    "malware_types": [],
    "extension_id": None,
    "file_hash": ""
    }   


    # 1. parse the opswat dict and put in final_report
    

    # 2. parse the vt dict and put in final report

    # 3. parse SA dict and put in final report


    return final_report


    
def calculate_final_score(result) -> int:
    
    valid_scores = []


    for data in result:
        score = data.get("score")
        if isinstance(score, (int, float)):
            valid_scores.append(float(score))
    
    if not valid_scores:
        return 0
    
    total = 0.0
    for s in valid_scores:
        total += s

    avg = total / 3.0
    return round(avg)
