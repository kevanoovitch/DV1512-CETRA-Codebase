import json
import datetime

def ParseReport(report :dict):
    
    report_hash = report.get("file_hash")
    report_score = report.get("score")
    report_verdict = report.get("verdict")
    report_description = report.get("description")
    report_permissions = report.get("permissions")
    report_risks = report.get("risks")
    report_malware_types = report.get("malware_types")
    report_ExtentionID = report.get("extention_id")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    
    
    print("Hash: ", report_hash)
    print("Score: ", report_score)
    print("Verdict: ", report_verdict)
    print("Description: ", report_description)
    print("Permissions: ", report_permissions)
    print("Risks: ", report_risks)
    print("Malware Types: ", report_malware_types)
    print("Extention ID: ", report_ExtentionID)
    print("Datetime: ", report_date)
    


if __name__ == "__main__":
    dummyreport = {
        "score": 85,
        "verdict": "malicious",
        "description": ["Blabla", "Albalb", "hhhhhhh"],
        "permissions": ["read_contacts", "send_sms", "etc."],
        "risks": ["data_leak", "financial_loss", "etc."],
        "malware_types": ["trojan", "ransomware", "etc."],
        "extention_id": "ext123",
        "file_hash": "abc123",
        }

    ParseReport(dummyreport)
