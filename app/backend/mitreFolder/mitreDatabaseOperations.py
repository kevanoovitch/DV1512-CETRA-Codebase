import sqlite3
import datetime
import json
import logging

try:
    from app.backend.db_initializer import ensure_tables, DB_PATH
except ImportError:
    from ..db_initializer import ensure_tables, DB_PATH

logger = logging.getLogger(__name__)

delete_mitre_table = """
DROP TABLE IF EXISTS mitre;
"""


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

    # if primary key contraint fails, set answer to False
    answer = True
    if cur.rowcount != 1:
        answer = False
    
    # get the id of the last inserted row
    return answer


def mitreDatabaseOperations(report: dict):
    logger.info("Storing MITRE data in database")
    
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
        ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            reportHash = report.get("file_hash")
            i = 0
                  
            for sandbox in mitre_reports:
                i = i + 1
                success = addMitreResults(conn, sandbox, reportHash)
                if success:
                    logger.debug("Stored sandbox data: %s", sandbox)
                    logger.info("Sandbox report number %s added successfully.", i)
    except sqlite3.Error:
        logger.exception("Failed to store MITRE data in database")

dummy_mitre_report = {
  "file_hash": "0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26",
  "Sandbox 1": [
    {
      "tactic_id": "tacticid1",
      "tactic_name": "tacticname1",
      "techniques": [
        {
          "technique_id": "techniqueid1",
          "technique_name": "techniquename1"
        }
      ]
    }
  ],
  "Sandbox 2": [
    {
      "tactic_id": "tacticid2",
      "tactic_name": "tacticname2",
      "techniques": [
        {
          "technique_id": "tecniqueid2",
          "technique_name": "techniquename2"
        }
      ]
    },
    {
      "tactic_id": "tacticid2.1",
      "tactic_name": "tacticname2.1",
      "techniques": [
        {
          "technique_id": "tecniqueid2.1",
          "technique_name": "tecniquename2.1"
        },
        {
          "technique_id": "tecniqueid2.11",
          "technique_name": "techniquename2.11"
        },
        {
          "technique_id": "tecniqueid2.12",
          "technique_name": "techniquename2.12"
        },
        {
          "technique_id": "tecniqueid2.13",
          "technique_name": "techniquename2.13"
        }
      ]
    }
  ],
}

if __name__ == "__main__":
    mitreDatabaseOperations(dummy_mitre_report)
