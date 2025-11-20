

import logging
import sqlite3
from pathlib import Path


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
    behaviour TEXT,
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

logger = logging.getLogger(__name__)
DB_PATH = Path(__file__).resolve().parents[2] / "db.sqlite3"


def ensure_tables():
    """Ensure DB file exists and required tables are present."""
    try:
        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute(create_reports_table)
            cur.execute(create_mitre_table)
            conn.commit()
    except sqlite3.Error:
        logger.exception("Failed to initialize database")
        raise
    
