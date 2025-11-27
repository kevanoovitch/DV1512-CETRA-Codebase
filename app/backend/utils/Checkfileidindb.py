import sqlite3
from app.backend.api import compute_file_hash

def check_existing_report(file_path=None, ext_id=None):
    """
    Checks if a report exists (<30 days old) based on file hash or extension ID.
    Automatically deletes old reports (>30 days).

    Returns:
        {"exists": True/False, "hash": "...", "date": "...", "extention_id": "..."}
    """

    file_hash = None
    if file_path:
        file_hash = compute_file_hash(file_path)

    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    if file_hash:
        cursor.execute("""
            SELECT file_hash, date, extention_id
            FROM reports
            WHERE file_hash = ?
              AND date >= datetime('now', '-30 days')
        """, (file_hash,))
        row = cursor.fetchone()

        if row:
            conn.close()
            return {
                "exists": True,
                "hash": row[0],
                "date": row[1],
                "extention_id": row[2],
            }

        # No recent report, delete older ones
        cursor.execute("DELETE FROM reports WHERE file_hash = ?", (file_hash,))
        conn.commit()
        conn.close()

        return { "exists": False, "hash": file_hash }

    if ext_id:
        cursor.execute("""
            SELECT file_hash, date, extention_id
            FROM reports
            WHERE extention_id = ?
              AND date >= datetime('now', '-30 days')
        """, (ext_id,))
        row = cursor.fetchone()

        if row:
            conn.close()
            return {
                "exists": True,
                "hash": row[0],
                "date": row[1],
                "extention_id": row[2],
            }

        # Cleanup old rows
        cursor.execute("DELETE FROM reports WHERE extention_id = ?", (ext_id,))
        conn.commit()
        conn.close()

        return { "exists": False }

    conn.close()
    return { "exists": False }

def delete_report_by_hash(filehash):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reports WHERE file_hash=?", (filehash,))
    conn.commit()
    conn.close()

def delete_report_by_id(ext_id):
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()
    cursor.execute("DELETE FROM reports WHERE extention_id=?", (ext_id,))
    conn.commit()
    conn.close()
