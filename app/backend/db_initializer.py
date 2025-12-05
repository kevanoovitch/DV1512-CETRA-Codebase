

import logging
import sqlite3
from pathlib import Path


create_reports_table = """
CREATE TABLE IF NOT EXISTS reports (
    file_hash varchar(50) NOT NULL PRIMARY KEY, 
    score INTEGER,
    verdict varcar(20), 
    summary TEXT,
    behaviour TEXT,
    extention_id varchar(32),
    date varchar(20)
);
    """

create_mitre_table = """
CREATE TABLE IF NOT EXISTS mitre (
    file_hash varchar(50) NOT NULL, 
    sandbox varchar(50),
    tactics TEXT,
    techniques TEXT,
    date varchar(20),
    PRIMARY KEY (file_hash, sandbox)
); """

create_findings_tab = """
CREATE TABLE IF NOT EXISTS findings(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_hash varchar(50) NOT NULL,
    tag TEXT,
    type TEXT, 
    category TEXT 
    score int,
    family TEXT,
    api TEXT,
    FOREIGN KEY (file_hash) REFERENCES reports(file_hash)
); """

logger = logging.getLogger(__name__)
DB_PATH = Path(__file__).resolve().parents[2] / "db.sqlite3"


def ensure_tables():
    """Ensure DB file exists and required tables are present."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(create_reports_table)
            cur.execute(create_mitre_table)
            cur.execute(create_findings_tab)
            conn.commit()
    except sqlite3.Error:
        logger.exception("Failed to initialize database")
        raise
    



# Change date, 40 days
# UPDATE reports
# SET date = datetime('now', '-40 days')
# WHERE file_hash ="0efc314b1b7f6c74e772eb1f8f207ed50c2e702aed5e565081cbcf8f28f0fe26";
# sqlite> 