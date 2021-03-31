"""
This file creates a SQLite database file, if not created yet,
and writes the scan results to the database,
"""
import sqlite3
import os.path

# Define a function to write to the SQlite databse.
def writeToSQLite(portscan_variable):

    # Check if the database file already exists. If not; create database and insert table:
    if os.path.isfile('portscan.db'):
        pass
    else:
        # Create the datbase file and connect.
        conn = sqlite3.connect("portscan.db")
        # Create the cursor object.
        c = conn.cursor()
        # Execute SQL query.
        c.execute('''CREATE TABLE portscans (
            host CHAR, 
            scan_type CHAR, 
            open_ports ENUM, 
            closed_ports ENUM, 
            filtered_ports ENUM, 
            filtered_or_open_ports ENUM, 
            filtered_or_closed_ports ENUM)''')
        # Commit changes and close connection.
        conn.commit()
        conn.close()

    # Connect to the database to write the scan results.
    conn = sqlite3.connect("portscan.db")
    c = conn.cursor()
    # Create SQL query to insert scan results and use question marks for best practices against SQLi.
    query = f'INSERT INTO portscans VALUES (?, ?, ?, ?, ?, ?, ?)'
    c.execute(query, (
        f'{portscan_variable["host"]}',
        f'{portscan_variable["scan_type"]}',
        f'{portscan_variable["open_ports"]}',
        f'{portscan_variable["closed_ports"]}',
        f'{portscan_variable["filtered_ports"]}',
        f'{portscan_variable["filtered_or_open_ports"]}',
        f'{portscan_variable["filtered_or_closed_ports"]}'))
    conn.commit()
    conn.close()
