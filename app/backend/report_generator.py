import os
import re
from typing import  Any

class ReportGenerator:
    
    def __init__(self) -> None:
        #FIXME: Don't use hardcoded scores
        self._result: dict[str, Any] = {
        "SecureAnnex": {"score": 40},
        "VirusTotal": {"score": 30},
        "OPSWAT": {"score": 20}
        }

        
    
    def _calculate_final_score(self) -> int:
        
        valid_scores = []


        for data in self._result.values():
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
    