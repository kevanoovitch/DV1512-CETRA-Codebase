import json
import sqlite3
import datetime
import os

directory = os.path.dirname(os.path.abspath(__file__))
root_parent = os.path.dirname(directory)
root_grandparent = os.path.dirname(root_parent)

# SQL statements

delete_reports_table = """
DROP TABLE IF EXISTS reports;
"""

create_reports_table = """
CREATE TABLE IF NOT EXISTS reports (
    file_hash varchar(50) NOT NULL PRIMARY KEY, 
    score INTEGER,
    verdict varcar(20), 
    description TEXT,
    permissions TEXT,
    risks TEXT,
    malware_types TEXT,
    extention_id varchar(32),
    date varchar(20)
);
    """
def add_report(conn, report):
    # insert table statement
    insert = f"""
    INSERT INTO reports
    (file_hash, score, verdict, description, permissions, risks, malware_types, extention_id, date)
    VALUES
    (?,?,?,?,?,?,?,?,?);
    """
    report_hash = report.get("file_hash")
    report_score = report.get("score")
    report_verdict = report.get("verdict")
    report_description = report.get("description")
    report_permissions = report.get("permissions")
    report_risks = report.get("risks")
    report_malware_types = report.get("malware_types")
    report_ExtentionID = report.get("extension_id")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create  a cursor
    cur = conn.cursor()

    # execute the INSERT statement
    cur.execute(insert, (report_hash, report_score, report_verdict, json.dumps(report_description), json.dumps(report_permissions), json.dumps(report_risks), json.dumps(report_malware_types), report_ExtentionID, report_date))

    # commit the changes
    conn.commit()

    # get the id of the last inserted row
    return True

def ParseReport(report :dict):
    print("\n Storing in Database...\n")
    
    try:
        with sqlite3.connect(os.path.join(root_grandparent, "db.sqlite3")) as conn:  
            cursor = conn.cursor()
            #cursor.execute(delete_reports_table)
            # create reports table
            cursor.execute(create_reports_table)
                  
            success = add_report(conn, report)
            if success:
                print("Report added successfully.")
    except sqlite3.Error as e:
        print(e)


dummyreport = {
        "score": 85,
        "verdict": "malicious",
        "description": ["Blabla", "Albalb", "hhhhhhh"],
        "permissions": ["read_contacts", "send_sms", "etc."],
        "risks": ["data_leak", "financial_loss", "etc."],
        "malware_types": ["trojan", "ransomware", "etc."],
        "extension_id": "ext123",
        "file_hash": "abc123",
        }


if __name__ == "__main__":
    
    ParseReport()
