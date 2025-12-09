import json
import sqlite3
import datetime
import logging
from app.backend.utils.classlibrary import Finding

try:
    from app.backend.db_initializer import ensure_tables, DB_PATH
except ImportError:
    from db_initializer import ensure_tables, DB_PATH

logger = logging.getLogger(__name__)

def normalize_backend_report(raw: dict) -> dict:
    """
    Cleans and normalizes backend report data so that it matches the
    database schema and internal structure.
    """

    summary = raw.get("Summary") or ""
    behaviour = raw.get("behaviour") or ""
    permissions = raw.get("Permissions") or []
    extention_id = raw.get("extension_id") or None
    findings = raw.get("Findings") or []

    return {
        "file_hash": raw.get("file_hash"),
        "score": raw.get("score", -1),
        "verdict": raw.get("verdict", "Unknown"),
        "summary": summary,
        "behaviour": behaviour,
        "permissions": permissions,
        "extention_id": extention_id,
        "findings": findings
    }


def add_report(conn, report):
    insert_sql = """
    INSERT INTO reports
    (file_hash, score, verdict, summary, behaviour, permission, extention_id, date)
    VALUES (?,?,?,?,?,?,?,?);
    """

    cur = conn.cursor()
    cur.execute(insert_sql, (
        report["file_hash"],
        report["score"],
        report["verdict"],
        report["summary"],
        report["behaviour"],
        json.dumps(report["permissions"]),
        report["extension_id"],
        datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    ))

    conn.commit()
    return True


def add_findings(conn, file_hash, findings):
    insert_sql = """
    INSERT INTO findings
    (file_hash, tag, type, category, score, family, api)
    VALUES (?,?,?,?,?,?,?);
    """

    cur = conn.cursor()

    for f in findings:
        cur.execute(insert_sql, (
            file_hash,
            f.tag,
            f.type,
            f.category,
            f.score,
            f.family,
            f.api
        ))

    conn.commit()
    return True


def ParseReport(report: dict):
    logger.info("Normalizing incoming backend report")

    #report = normalize_backend_report(raw_report)
    findings = report["findings"]
    file_hash = report["file_hash"]

    try:
        ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            add_report(conn, report)

            if findings:
                add_findings(conn, file_hash, findings)

        logger.info("Report + Findings inserted successfully.")

    except Exception:
        logger.exception("Failed to write report or findings to database")
