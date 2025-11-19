import os
import sqlite3
import datetime
import json

directory = os.path.dirname(os.path.abspath(__file__))
root_parent = os.path.dirname(directory)
root_uncle = os.path.dirname(root_parent)
root_grandparent = os.path.dirname(root_uncle)

delete_mitre_table = """
DROP TABLE IF EXISTS mitre;
"""

create_mitre_table = """
CREATE TABLE IF NOT EXISTS mitre (
    file_hash varchar(50) NOT NULL, 
    sandbox varchar(50),
    tactics TEXT,
    techniques TEXT,
    date varchar(20)
); """
def addMitreResults(conn, report: dict, reportHash: str):
    # insert table statement
    insert = f"""
    INSERT INTO mitre
    (file_hash, sandbox, tactics, techniques, date)
    VALUES
    (?,?,?,?,?);
    """
    # report_hash = report.get("file_hash")
    report_hash = reportHash
    report_sandbox = report.get("sandbox")
    report_tactics = report.get("tactics")
    report_techniques = report.get("techniques")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create  a cursor
    cur = conn.cursor()

    # execute the INSERT statement
    cur.execute(insert, (report_hash, report_sandbox,json.dumps(report_tactics), json.dumps(report_techniques), report_date))

    # commit the changes
    conn.commit()

    # get the id of the last inserted row
    return True


def mitreDatabaseOperations(report: dict):
    print("\n Storing in Database...\n")
    
    input_data = report
    
    mitre_reports = []

    file_hash = input_data["file_hash"]

    for sandbox_name, sandbox_entries in input_data.items():
        if sandbox_name == "file_hash":
            continue

        tactics = []
        techniques = []

        for entry in sandbox_entries:
        # Collect tactic names
            tactics.append(entry["tactic_name"])

        # Collect list of "id, name" strings for each tactic
            tactic_techniques = [
                f'{tech["technique_id"]}, {tech["technique_name"]}'
                for tech in entry["techniques"]
        ]
            techniques.append(tactic_techniques)

    # Build output dict for this sandbox
        mitre_reports.append({
        "file_hash": file_hash,
        "sandbox": sandbox_name,
        "tactics": tactics,
        "techniques": techniques
        })

    
    try:
        with sqlite3.connect(os.path.join(root_grandparent, "db.sqlite3")) as conn:  
            cursor = conn.cursor()
            
            cursor.execute(delete_mitre_table)
            
            # create mitre table
            cursor.execute(create_mitre_table)
            
            reportHash = report.get("file_hash")
            i = 0
                  
            for sandbox in mitre_reports:
                i = i + 1
                print(sandbox)
                success = addMitreResults(conn, sandbox, reportHash)
                if success:
                    print(f"Sandbox report number {i} added successfully.")
    except sqlite3.Error as e:
        print(e)
        
dummy_mitre_report = {
    "file_hash": "dummyhash123",
    "sandbox": "sandbox_name",
    "tactics": ["tactic1","tactic2"],
    "techniques": [["techniqueId, techniqueName", "techniqueId2, techniqueName2"], ["techniqueId3, techniqueName3", "techniqueId4, techniqueName4"]]
}

if __name__ == "__main__":
    mitreDatabaseOperations(dummy_mitre_report)