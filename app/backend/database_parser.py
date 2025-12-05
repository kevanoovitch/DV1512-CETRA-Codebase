import json
import sqlite3
import datetime
import logging
from app.backend.utils.classlibrary import Finding

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
    (file_hash, score, verdict, summary, extention_id, behaviour ,date)
    VALUES
    (?,?,?,?,?,?,?,?,?,?);
    """
    report_hash = report.get("file_hash")
    report_score = report.get("score")
    report_verdict = report.get("verdict")
    report_summary = report.get("summary")
    report_ExtentionID = report.get("extension_id")
    report_behaviour = report.get("behaviour")
    report_date = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    # Create  a cursor
    cur = conn.cursor()

    # execute the INSERT statement
    cur.execute(insert, (report_hash, report_score, report_verdict, report_summary, report_ExtentionID, report_behaviour ,report_date))

    # commit the changes
    conn.commit()

    # get the id of the last inserted row
    return True

def add_findings(conn, findings):
    insert = f"""
    INSERT INTO findings
    (file_hash, tag, type, category, score, family, api)
    VALUES
    (?,?,?,?,?,?,?);
    """
    cur = conn.cursor()
    for finding in findings:
        finding_hash = finding.get("file_hash")
        finding_tag = finding.tag
        finding_type = finding.type
        finding_category = finding.category
        finding_score = finding.score
        finding_family = finding.family
        finding_api = finding.api

        cur.execute(insert, (finding_hash, finding_tag, finding_type, finding_category, finding_score, finding_family, finding_api))
    
    conn.commit()
    return True

def ParseReport(report :dict):
    logger.info("Writing report to database")
    
    findings = report.get("findings")
    
    try:
        ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            success = add_report(conn, report)
            success2 = add_findings(conn, findings)
            if success:
                logger.info("Report added successfully.")
            if success2:
                logger.info("Findings added successfully.")
    except sqlite3.Error:
        logger.exception("Failed to write report to database")


dummy_findings = [
    {
        "tag": "suspicious_network",
        "type": "network",
        "category": "communication",
        "score": 70,
        "family": "generic_network_anomaly",
        "api": "chrome.webRequest"
    },
    {
        "tag": "dangerous_file_access",
        "type": "file",
        "category": "filesystem",
        "score": 90,
        "family": "unauthorized_write",
        "api": "chrome.fileSystem"
    },
    {
        "tag": "high_risk_permissions",
        "type": "permission",
        "category": "privacy",
        "score": 85,
        "family": "sensitive_permissions",
        "api": "chrome.permissions"
    },
    {
        "tag": "suspicious_code_injection",
        "type": "js",
        "category": "execution",
        "score": 95,
        "family": "script_injection",
        "api": "chrome.tabs.executeScript"
    }
]

dummyreport = {
    "file_hash": "abc123",
    "score": 85,
    "findings": dummy_findings,
    "verdict": "malicious",
    "summary": "This extension exhibits multiple malicious behaviors, including data exfiltration and script injection.",
    "behaviour": "Injects JS into active tabs, monitors URLs, modifies requests.",
    "extention_id": "ext123"
}


"""
if __name__ == "__main__":
    ParseReport(dummyreport)
"""