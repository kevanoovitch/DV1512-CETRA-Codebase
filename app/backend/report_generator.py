import os
import re
from typing import  Any
import logging
from app.backend.utils import Ai_Helper
from app.backend.utils.classlibrary import ApiResult, Finding
from app.constants import FINDINGS_API_NAMES

logger = logging.getLogger(__name__)

responseTemplate = {
  "summary": "Write an approximately 100-word summary of the Chrome extension. Use the extension ID to identify the extension, its name, purpose, and main functionality. Include relevant context such as common user feedback or sentiment (especially if there are notable negative reviews). Briefly mention any potential concerns or risks, but do not over-focus on them.",

  "permissions": "In short, free-text form, analyze the permissions requested by the extension. Explain whether the permissions match the extension's purpose, whether any permissions appear excessive, and what these permissions allow the extension to do or access.",

  "risk_types": "Describe the potential risks associated with this extension, based on its permissions, behavior, reputation, or user reports. Discuss high-level risk categories without over-explaining.",

  "malware_types": "If applicable, describe what types of malware or malicious behavior this extension could be associated with based on available data. Keep this section concise and focused on risk classification (e.g., spyware, adware, data harvesting)."
}

def generate_report(result: ApiResult) -> dict:
    logger.info("Generating Report...")
    score = calculate_final_score(result.findings)
    permissions = result.permissions
    extension_id = result.extension_id
    verdict = label_from_score(score)
    #description = result["SA"]["descriptions"]
    file_hash = result.file_hash


    behaviour_summary = None
    if result.behavior is not None:
        behaviour_summary = Ai_Helper(
            #TODO: Refractor this
        )
    if behaviour_summary is None:
        behaviour_summary = "Unavailable"

    """
        calling_AI = Ai_Helper(
            request="please analyse the data field, check the data key in this dict, if the data key is empty return the string 'UNAVAILABLE', and please respond in a dict fashion, as in the response template sent to you in the response key, you are being called by a script please dont respond in  any other way than this",
            response=responseTemplate,
            data={"generalData":description,"extension_id":extension_id,"permissions":permissions,"malware_risk_types": malware_types+risks}
        )
        print(calling_AI)
    """


    report = {
        "score": score,
        "verdict": verdict,
        "Findings": [], # A list of Findings
        "Summery": None, # text
        "Permissions": [],
        "Targets": None, #Text
        "behaviour": behaviour_summary
    }

    logger.info("Generated report successfully!")

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

    print(findings)

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

    final_score = sum(valid_totals) / len(valid_totals)

    return round(final_score)
