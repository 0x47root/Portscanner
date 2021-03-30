import sqlite3

portscan = {'host': '45.33.32.156', 'scan_type': '-sS', 'open_ports': [22, 80], 'closed_ports': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100], 'filtered_ports': [], 'filtered_or_open_ports': [], 'filtered_or_closed_ports': []}

# create db file (if not yet) and connect to database
conn = sqlite3.connect("portscan.db")

# create cursor object
c = conn.cursor()

# create table
c.execute('''CREATE TABLE portscan (
    host CHAR, 
    scan_type CHAR, 
    open_ports ENUM, 
    closed_ports ENUM, 
    filtered_ports ENUM, 
    filtered_or_open_ports ENUM, 
    filtered_or_closed_ports ENUM)''')

# create query to insert portscan results and use question marks for best practices against SQLi
query = f'INSERT INTO portscan VALUES (?, ?, ?, ?, ?, ?, ?)'

# execute query
c.execute(query, (
    f'{portscan["host"]}',
    f'{portscan["scan_type"]}',
    f'{portscan["open_ports"]}',
    f'{portscan["closed_ports"]}',
    f'{portscan["filtered_ports"]}',
    f'{portscan["filtered_or_open_ports"]}',
    f'{portscan["filtered_or_closed_ports"]}'))

# commit changes and close connection
conn.commit()
conn.close()