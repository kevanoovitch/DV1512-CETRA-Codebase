import sqlite3

def reset_reports_table():
    conn = sqlite3.connect("db.sqlite3")
    cursor = conn.cursor()

    # Delete all rows from the reports table
    cursor.execute("DELETE FROM reports;")

    # Reset auto-increment counter (optional but common)
    cursor.execute("DELETE FROM sqlite_sequence WHERE name='reports';")

    conn.commit()
    conn.close()

    print("Reports table has been reset.")

if __name__ == "__main__":
    reset_reports_table()
