import os
import re
from typing import  Any
import logging
from app.backend.utils import Ai_Helper

logger = logging.getLogger(__name__)

responseTemplate = {
  "summary": "Write an approximately 100-word summary of the Chrome extension. Use the extension ID to identify the extension, its name, purpose, and main functionality. Include relevant context such as common user feedback or sentiment (especially if there are notable negative reviews). Briefly mention any potential concerns or risks, but do not over-focus on them.",
  
  "permissions": "In short, free-text form, analyze the permissions requested by the extension. Explain whether the permissions match the extension's purpose, whether any permissions appear excessive, and what these permissions allow the extension to do or access.",
  
  "risk_types": "Describe the potential risks associated with this extension, based on its permissions, behavior, reputation, or user reports. Discuss high-level risk categories without over-explaining.",
  
  "malware_types": "If applicable, describe what types of malware or malicious behavior this extension could be associated with based on available data. Keep this section concise and focused on risk classification (e.g., spyware, adware, data harvesting)."
}


def generate_report(result) -> dict: 
    logger.info("Generating Report...")
    score = calculate_final_score([result["SA"]["score"],result["VT"]["score"],result["OWASP"]["score"]])
    permissions = result["permissions"]
    risks = result["SA"]["risk_types"]
    malware_types = result["OWASP"]["malware_type"] + result["VT"]["malware_types"]
    extension_id = result["extension_id"]
    verdict = label_from_score(score)
    description = result["SA"]["descriptions"]
    file_hash = result["file_hash"]

    
    behaviour_summary = None
    if result["VT"]["behaviour"] is not None:
        behaviour_summary = Ai_Helper(
            request="analyse the data key, this is sandbox behaviour analyses from virustotal, and asnwer as asked for in the response",
            response="please respond in freetext manner, no point or dhashes normal freetext, describing how this extension behaves, approximitly 100 words, see if its doing something millicios talk about the security aspects",
            data=result["VT"]["behaviour"]
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
    #FIXME: print?
    print(behaviour_summary)
    report = {
        "score": score,
        "verdict": verdict,
        "description": description,
        "permissions": permissions,
        "risks": risks,
        "malware_types": malware_types,
        "extension_id": extension_id,
        "file_hash": file_hash,
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
