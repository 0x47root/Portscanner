"""This file contains all SQL related functions."""
import sqlite3
import os.path
import sys

def writeToSQLite(portscan_variable):
    """
    This function creates a SQLite database file (if not created yet)
    writes the scan results o the database.
    """

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

def show_results(ip_address):
    """This function presents the scan results of a specific IP-address to the user."""
    if not os.path.isfile('portscan.db'):
        print("Error: 'portscan.db' not found. Did you already run a scan?")
        sys.exit()
    conn = sqlite3.connect("portscan.db")
    c = conn.cursor()
    query = "SELECT * FROM portscans WHERE host=?"
    scan_results = c.execute(query, (ip_address,)) # 'ip_address' needs to be in a tuple
    for scan in scan_results:
        print(70 * "-")
        print(f"Scantype: {scan[1]}")
        # Only printing lists that contain scan results:
        if len(scan[2]) > 2:
            print(f"Open ports: {scan[2]}")
        if len(scan[3]) > 2:
            print(f"Closed ports: {scan[3]}")
        if len(scan[4]) > 2:
            print(f"Filtered ports: {scan[4]}")
        if len(scan[5]) > 2:
            print(f"Filtered or open ports: {scan[5]}")
        if len(scan[6]) > 2:
            print(f"Filtered or closed ports: {scan[6]}")
    conn.close()
