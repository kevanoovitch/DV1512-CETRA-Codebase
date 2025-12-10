import os
import re
from typing import  Any
import logging
from app.backend.utils import Ai_Helper, offline_analysis_from_components
from app.backend.utils.classlibrary import ApiResult, Finding
from app.constants import FINDINGS_API_NAMES
import json

logger = logging.getLogger(__name__)


def generate_report(result: ApiResult) -> dict:
    logger.info("Generating Report...")
    


    score = calculate_final_score(result.findings)
    verdict = label_from_score(score)
    file_hash = result.file_hash

    summery = None
    behaviour = None

    summery_and_behaviour_prompt = {
        "request": (
            "You will receive an object called 'prompt_data' containing:\n"
            "- score: numeric risk score\n"
            "- verdict: overall classification\n"
            "- Findings: list of findings\n"
            "- behaviour: behavior report text\n"
            "- Permissions: list of permissions\n"
            "- extension_id: extension identifier\n\n"
            "Your task:\n"
            "1. Analyze all fields.\n"
            "2. Produce a human-readable EXTENSION SUMMARY describing:\n"
            "   - What the extension does.\n"
            "   - Whether it is malicious/suspicious/benign.\n"
            "   - Any dangerous or high-risk permissions.\n"
            "   - Any privacy or security concerns.\n"
            "   - Any context inferred from provided data.\n"
            "3. Produce a FILE BEHAVIOR SUMMARY describing:\n"
            "   - What the extension/file does at runtime based on the 'behaviour' field.\n"
            "   - Any malicious patterns such as persistence, injection, data exfiltration, etc.\n"
            "   - Interpret the findings and behavior into a readable explanation.\n\n"
            "Return ONLY a JSON dict using this exact schema:\n"
            "{\n"
            '  \"extension_summary\": string,\n'
            '  \"file_behavior_summary\": string\n'
            "}\n\n"
            "Important:\n"
            "- DO NOT output anything outside the JSON.\n"
            "- DO NOT restate the prompt_data raw.\n"
            "- DO NOT add extra fields.\n"
            "- Only provide interpreted summaries."
        ),
        "response": (
            "The response MUST be exactly:\n"
            "{\n"
            '  \"extension_summary\": \"...\",\n'
            '  \"file_behavior_summary\": \"...\"\n'
            "}\n"
            "Return NOTHING else."
        ),
        "prompt_data": {
            "score": score,
            "verdict": verdict,
            "Findings": result.findings,
            "behaviour": result.behavior,
            "Permissions": result.permissions,
            "extension_id": result.extension_id,
            "manifest_file": result.extensionData
        }
    }



    if result.behavior is not None or summery:
        
        calling_AI = Ai_Helper(
            request=summery_and_behaviour_prompt["request"],
            response=summery_and_behaviour_prompt["response"],
            data=summery_and_behaviour_prompt["prompt_data"]
        )

        if(calling_AI is not None):
            match = re.search(r'\{.*\}', calling_AI, re.DOTALL)

            if match:
                clean_json = match.group(0)
                try:
                    data = json.loads(clean_json)
                except json.JSONDecodeError:
                    offline_analysis_from_components(result = offline_analysis_from_components(
                        findings=result.findings,
                        behaviour=result.behavior,
                        score=score,
                        verdict=verdict,
                        permissions=result.permissions,
                        extension_id=result.extension_id
                    ))
                    calling_AI = None
            else:
                calling_AI = None


    if(calling_AI is None):
        data = offline_analysis_from_components(result = offline_analysis_from_components(
            findings=result.findings,
            behaviour=result.behavior,
            score=score,
            verdict=verdict,
            permissions=result.permissions,
            extension_id=result.extension_id
        ))
            

    summary = data["extension_summary"]
    behavior = data["file_behavior_summary"]

    report = {
        "score": score,
        "verdict": verdict,
        "findings":result.findings, # A list of Findings
        "summary": summary, # text
        "behaviour": behavior, # text
        "permissions": result.permissions,
        "extension_id": result.extension_id,
        "file_hash": result.file_hash
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
                #print("FOUND VT! ", finding.api)
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
