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
    file_hash varchar(50) NOT NULL PRIMARY KEY, 
    sandbox varchar(50),
    tactics TEXT,
    techniques TEXT,
    date varchar(20)
);
    """
def addMitreResults(conn, report):
    # insert table statement
    insert = f"""
    INSERT INTO mitre
    (file_hash, sandbox, tactics, techniques, date)
    VALUES
    (?,?,?,?,?);
    """
    report_hash = report.get("file_hash")
    report_sandbox = report.get("sandbox")
    report_tactics = report.get("tactics")
    report_techniques = report.get("techniques")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create  a cursor
    cur = conn.cursor()

    # execute the INSERT statement
    cur.execute(insert, (report_hash, report_sandbox, json.dumps(report_tactics), json.dumps(report_techniques), report_date))

    # commit the changes
    conn.commit()

    # get the id of the last inserted row
    return True


def mitreDatabaseOperations(report: dict):
    print("\n Storing in Database...\n")
    
    try:
        with sqlite3.connect(os.path.join(root_grandparent, "db.sqlite3")) as conn:  
            cursor = conn.cursor()
            
            cursor.execute(delete_mitre_table)
            
            # create mitre table
            cursor.execute(create_mitre_table)
                  
            success = addMitreResults(conn, report)
            if success:
                print("Report added successfully.")
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