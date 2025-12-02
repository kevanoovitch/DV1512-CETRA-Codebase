import json
import sqlite3
import datetime
import logging
try:
    from app.backend.db_initializer import ensure_tables, DB_PATH
except ImportError:
    # Support running as a script from the backend directory
    from db_initializer import ensure_tables, DB_PATH

logger = logging.getLogger(__name__)

def add_report(conn, report):
    # insert table statement
    insert = f"""
    INSERT INTO reports
    (file_hash, score, verdict, description, permissions, risks, malware_types, extention_id, behaviour ,date)
    VALUES
    (?,?,?,?,?,?,?,?,?,?);
    """
    report_hash = report.get("file_hash")
    report_score = report.get("score")
    report_verdict = report.get("verdict")
    report_description = report.get("description")
    report_permissions = report.get("permissions")
    report_risks = report.get("risks")
    report_malware_types = report.get("malware_types")
    report_ExtentionID = report.get("extension_id")
    report_behaviour = report.get("behaviour")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create  a cursor
    cur = conn.cursor()

    # execute the INSERT statement
    cur.execute(insert, (report_hash, report_score, report_verdict, json.dumps(report_description), json.dumps(report_permissions), json.dumps(report_risks), json.dumps(report_malware_types), report_ExtentionID, report_behaviour ,report_date))

    # commit the changes
    conn.commit()

    # get the id of the last inserted row
    return True

def ParseReport(report :dict):
    logger.info("Writing report to database")
    
    try:
        ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            success = add_report(conn, report)
            if success:
                logger.info("Report added successfully.")
    except sqlite3.Error:
        logger.exception("Failed to write report to database")

