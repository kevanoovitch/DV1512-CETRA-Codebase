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
    """arg a dictionary returns a dict"""

    pass 


    
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
