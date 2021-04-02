"""
This file creates a SQLite database file (if not created yet)
and writes the scan results to the database.
"""
import sqlite3
import os.path

def writeToSQLite(portscan_variable):
    """This function writes the scan results to a SQlite databse file."""

    # Check if the database file already exists. If not; create database file and insert table:
    if os.path.isfile('portscan.db'):
        pass
    else:
        # Create the database file and connect:
        conn = sqlite3.connect("portscan.db")
        # Create a cursor object:
        c = conn.cursor()
        # Execute the SQL query:
        c.execute('''CREATE TABLE portscans (
            host CHAR, 
            scan_type CHAR, 
            open_ports ENUM, 
            closed_ports ENUM, 
            filtered_ports ENUM, 
            filtered_or_open_ports ENUM, 
            filtered_or_closed_ports ENUM)''')
        # Commit changes and close the connection:
        conn.commit()
        conn.close()

    # Connect to the database to write the scan results.:
    conn = sqlite3.connect("portscan.db")
    c = conn.cursor()
    # Create a SQL query to insert the scan results and use question marks for best practices against SQLi:
    query = f'INSERT INTO portscans VALUES (?, ?, ?, ?, ?, ?, ?)'
    try:
        c.execute(query, (
            f'{portscan_variable["host"]}',
            f'{portscan_variable["scan_type"]}',
            f'{portscan_variable["open_ports"]}',
            f'{portscan_variable["closed_ports"]}',
            f'{portscan_variable["filtered_ports"]}',
            f'{portscan_variable["filtered_or_open_ports"]}',
            f'{portscan_variable["filtered_or_closed_ports"]}'))
    except sqlite3.OperationalError:
        print("OperationalError: Attempt to write a readonly database. Please run the script as admin/root.")
    conn.commit()
    conn.close()
