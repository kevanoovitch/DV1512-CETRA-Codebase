import database_parser
import os
import sqlite3
import datetime
import json

directory = os.path.dirname(os.path.abspath(__file__))
root_parent = os.path.dirname(directory)
root_uncle = os.path.dirname(root_parent)
root_grandparent = os.path.dirname(root_uncle)

create_mitre_table = """
CREATE TABLE IF NOT EXISTS mitre (
    file_hash varchar(50) NOT NULL PRIMARY KEY, 
    sandbox TEXT,
    tactics TEXT,
    techniques TEXT,
    extension_id varchar(32),
    date varchar(20)
);
    """



def main(report: dict):
    print("\n Storing in Database...\n")
    
    try:
        with sqlite3.connect(os.path.join(root_grandparent, "db.sqlite3")) as conn:  
            cursor = conn.cursor()
            #cursor.execute(delete_reports_table)
            # create reports table
            cursor.execute(create_mitre_table)
                  
            success = add_mitre_results(conn, report)
            if success:
                print("Report added successfully.")
    except sqlite3.Error as e:
        print(e)
        
