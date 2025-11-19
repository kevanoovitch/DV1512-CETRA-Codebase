#fetch hash
# from app.backend.report_generator import file_hash  

#get curl command
import mitreDatabaseOperations
import json
import requests
import os
from dotenv import load_dotenv
load_dotenv()

# filehash = "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26"

def print_mitre(parsed: dict):
    print(f"File Hash: {parsed['file_hash']}\n")

    for sandbox, tactics in parsed.items():
        if sandbox == "file_hash":
            continue
        print(f"Sandbox: {sandbox}")
        for tactic in tactics:
            print(f"  Tactic: {tactic['tactic_name']} ({tactic['tactic_id']})")
            for technique in tactic["techniques"]:
                print(f"    Technique: {technique['technique_name']} ({technique['technique_id']})")
        print()


def mitre_report(filehash: str, response):
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

    # print(json.dumps(parsed, indent=2))
    print_mitre(parsed)
    mitreDatabaseOperations.mitreDatabaseOperations(parsed)
    pass


headers = {
    "accept": "application/json",
    "x-apikey": os.getenv("VT_API_KEY")
    
}


def mitreCall(filehash: str):
  url = f"https://www.virustotal.com/api/v3/files/{filehash}/behaviour_mitre_trees"
  
  response = requests.get(url, headers=headers)

  #print(response.status_code)
  #print(response.json())

  mitre_report(filehash, response.json())

#exists = requests.get(f"https://www.virustotal.com/api/v3/files/{hash}", headers=headers)
#print(exists.status_code)
#print(exists.json())
