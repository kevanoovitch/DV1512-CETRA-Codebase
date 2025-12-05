import os
import re
from typing import  Any
import logging
from app.backend.utils import Ai_Helper
from app.backend.utils.classlibrary import ApiResult, Finding
from app.constants import FINDINGS_API_NAMES

logger = logging.getLogger(__name__)
"""
summery_and_behaviour_prompt = {
    request: ""
    
}
"""

def generate_report(result: ApiResult) -> dict:
    logger.info("Generating Report...")
    


    score = calculate_final_score(result.findings)
    verdict = label_from_score(score)
    file_hash = result.file_hash

    summery = None
    behaviour = None

    summery_and_behaviour_prompt = {
        "request":"request how the prmpt is",
        "response":"how teh response should be",
        "prompt_data": {
            "score": score,
            "verdict": verdict,
            "Findings":result.findings, # A list of Findings
            "behaviour": result.behavior, # text
            "Permissions": result.permissions,
            "extension_id": result.extension_id
        }
    }
    print(summery_and_behaviour_prompt)

    """
    if result.behavior is not None or summery:
        calling_AI = Ai_Helper(
            request="",
            response="",
            data={}
        )
    """

    report = {
        "score": score,
        "verdict": verdict,
        "Findings":result.findings, # A list of Findings
        "Summary": None, # text
        "behaviour": None, # text
        "Permissions": result.permissions,
        "extension_id": result.extension_id
    }

    logger.info("Generated report successfully!")
    print(report)
    return report


def label_from_score(s):
    if s<=25: return "OK / Clean"
    if s<=40: return "Low suspicion"
    if s<=55: return "Suspicious"
    if s<=80: return "Malicious"
    return "Highly malicious"

def avg(lst):
    return sum(lst) / len(lst) if lst else None

def calculate_final_score(findings: list[Finding]) -> int:



    sa_scores = []
    vt_scores = []
    op_scores = []
    # create three sublist based on the findings
    for finding in findings:        
        if finding.score is not -1:
            if finding.api == FINDINGS_API_NAMES["SA"]:
                sa_scores.append(finding.score)
            elif finding.api == FINDINGS_API_NAMES["VT"]:
                print("FOUND VT! ", finding.api)
                vt_scores.append(finding.score)
            elif finding.api == FINDINGS_API_NAMES["OP"]:
                op_scores.append(finding.score)
        
    logging.info("Organizing score based on findings input")
    
    sa_total = avg(sa_scores)
    vt_total = avg(vt_scores)
    op_total = avg(op_scores)

    

    logging.info(f"Organization result VT: {vt_total} SA: {sa_total} OP: {op_total}")

    totals = [sa_total, vt_total, op_total]

    valid_totals = [x for x in totals if x is not None]

    if not valid_totals:
        return -1

    final_score = sum(valid_totals) / len(valid_totals)

    return round(final_score)
