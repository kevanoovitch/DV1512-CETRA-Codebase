#fetch hash
# from app.backend.report_generator import file_hash  

#get curl command
from app.backend.mitreFolder import mitreDatabaseOperations
import json
import requests
import os
import logging
from dotenv import load_dotenv
load_dotenv()

logger = logging.getLogger(__name__)

def print_mitre(parsed: dict):
    logger.info("File Hash: %s", parsed["file_hash"])

    for sandbox, tactics in parsed.items():
        if sandbox == "file_hash":
            continue
        logger.info("Sandbox: %s", sandbox)
        for tactic in tactics:
            logger.info("  Tactic: %s (%s)", tactic['tactic_name'], tactic['tactic_id'])
            for technique in tactic["techniques"]:
                logger.info("    Technique: %s (%s)", technique['technique_name'], technique['technique_id'])
        logger.info("")


def mitre_report(filehash: str, response):
    # Fallback if MITRE data missing
    if "data" not in response or not response["data"]:
        logger.warning("[MITRE] No MITRE data found for %s", filehash)
        parsed = {"file_hash": filehash}
        mitreDatabaseOperations.mitreDatabaseOperations(parsed)
        return
    
    parsed = {
        "file_hash": filehash, 
        
        }
    
    for sandbox_name, sandbox_data in response["data"].items():
        parsed[sandbox_name] = []  # each sandbox holds a list of tactic-technique mappings
        
        for tactic in sandbox_data.get("tactics", []):
            tactic_entry = {
            "tactic_id": tactic.get("id"),
            "tactic_name": tactic.get("name"),
            "techniques": []
        }

            for technique in tactic.get("techniques", []):
                tactic_entry["techniques"].append({
                "technique_id": technique.get("id"),
                "technique_name": technique.get("name")
            })

            parsed[sandbox_name].append(tactic_entry)

    logger.debug("Parsed MITRE response: %s", json.dumps(parsed, indent=2))
    mitreDatabaseOperations.mitreDatabaseOperations(parsed)
    pass


headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
    
}


def mitreCall(filehash: str):
    url = f"https://www.virustotal.com/api/v3/files/{filehash}/behaviour_mitre_trees"
    response = requests.get(url, headers=headers)
    json_resp = response.json()

    if "data" not in json_resp or not json_resp["data"]:
        return {
            "success": False,
            "message": f"No MITRE behaviour is available for this file ({filehash})."
        }

    # otherwise → normal flow
    mitre_report(filehash, json_resp)
    return { "success": True }
  
if __name__ == "__main__":
    test_hash = "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26"
    mitreCall(test_hash)
