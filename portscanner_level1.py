import xml.etree.ElementTree as ET
from scapy.all import *
import ipaddress
import pyfiglet
import sqlite3
import os.path
import socket
import time
import json

# create a banner for CLI script
print(pyfiglet.figlet_format("PORT SCANNER"))
print(70 * "-")
print("By 0x47root")
print(70 * "-")

# ask user for scan type with input sanitization
scan_type = input("Please enter scan type (-sT, -sU, -sS or -sX): ")
while scan_type not in ['-sT', '-sU', '-sS', '-sX']:
    scan_type = input("Wrong input, please enter one of the given options (-sT, -sU, -sS or -sX): ")

# ask user for target with input sanitization
target = input("Please specify the IP-address to scan: ")
while True:
    try:
        ipaddress.IPv4Address(target)
        break
    except:
        target = input("Wrong input, please specify a correct IPv4 address: ")

# ask user for ports to scan with input sanitization
first_port = int(input("Please specify the first port in port range: "))
while first_port not in range(1, 65535):
    first_port = int(input("Wrong input, please specify a single port between 1 and 65535: "))
last_port = int(input("Please specify the last port in port range: ")) + 1
while last_port not in range(1, 65535):
    last_port = int(input("Wrong input, please specify a single port between 1 and 65535: ")) + 1
while last_port <= first_port:
    last_port = int(input("Please enter a number that is equal or higher than the first: ")) + 1

# ask user how to save the scan results with input sanitization
output = input("Do you want to save the output to a file? (y/n): ")
while output not in ['y', 'n']:
    output = input("Please enter a 'y' or a 'n': ")
if output == 'y':
    save_output = input("Do you want to save the results to JSON or XML?: ")
    while save_output not in ['JSON', 'XML', 'json', 'xml']:
        save_output = input("Please enter 'JSON' or 'XML'?: ")
else:
    save_output = False

# creating dictionary to store results
portscan = {}
portscan['host'] = target
portscan['scan_type'] = scan_type
portscan['open_ports'] = []
portscan['closed_ports'] = []
portscan['filtered_ports'] = []
portscan['filtered_or_open_ports'] = []
portscan['filtered_or_closed_ports'] = []

# define TCP-connect scan
def TCP_connect_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((target, port))
            print(f"Port {port} is open!!!!!!!!!!")
            # writing results to dictionary
            portscan['open_ports'].append(port)
            # closing connection
            s.close()
        except:
            print(f"Port {port} is filtered or closed")
            portscan['filtered_or_closed_ports'].append(port)

# define UDP scan
def UDP_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/UDP(dport=port), timeout=5, verbose=0)
        time.sleep(1) # sleep one second to prevent false positives
        if res == None:
            print(f"Port {port} is open or filtered")
            portscan['filtered_or_open_ports'].append(port)
        else:
            if res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) == 3:
                    print(f"Port {port} is closed")
                    portscan['closed_ports'].append(port)
                elif int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    print(f"Port {port} is filtered")
                    portscan['filtered_ports'].append(port)
            elif res.haslayer(UDP):
                print(f"Port {port} is open!!!!!!!!!!")
                portscan['open_ports'].append(port)

# define TCP-SYN scan
def TCP_SYN_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        # If the timeout value is not specified when this function is used against a unresponsive host,
        # the function will continue indefinitely
        if res == None:
            print(f"Port {port} is filtered")
            portscan['filtered_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                rst = sr(IP(dst=target)/TCP(dport=port,flags="R"), timeout = 1, verbose=0)
                print(f"Port {port} is open!!!!!!!!!!")
                portscan['open_ports'].append(port)
            elif res.getlayer(TCP).flags == 0x14: # 0x12 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
                portscan['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")
                    portscan['filtered_ports'].append(port)

# define XMAS scan
def XMAS_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), timeout=1, verbose=0) # FIN, PSH and URG
        if res == None:
            print(f"Port {port} is filtered or open!!!!!!!!!!")
            portscan['filtered_or_open_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
                portscan['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")
                    portscan['filtered_ports'].append(port)

# check which scan to conduct and execute scan
if scan_type == "-sT":
    TCP_connect_scan(target, first_port, last_port)
elif scan_type == "-sU":
    UDP_scan(target, first_port, last_port)
elif scan_type == "-sS":
    TCP_SYN_scan(target, first_port, last_port)
elif scan_type == "-sX":
    XMAS_scan(target, first_port, last_port)

# defining function to write to XML
def writeToXML():
    # creating XML file layout
    root = ET.Element("ScanResults")
    host = ET.SubElement(root, "host", {"ip": portscan["host"]})
    scan_type = ET.SubElement(host, "scan_type")
    open_ports = ET.SubElement(host, "open_ports")
    closed_ports = ET.SubElement(host, "closed_ports")
    filtered_ports = ET.SubElement(host, "filtered_ports")
    filtered_or_open_ports = ET.SubElement(host, "filtered_or_open_ports")
    filtered_or_closed_ports = ET.SubElement(host, "filtered_or_closed_ports")

    # writing scan type
    scan = ET.SubElement(scan_type, "scan")
    scan.text = portscan["scan_type"]

    # create function to fill XML file with ports
    def fillXML(port_list, port_element):
        if port_list:
            for p in port_list:
                port = ET.SubElement(port_element, "port")
                port.text = str(p)

    # filling XML file with ports
    fillXML(portscan["open_ports"], open_ports)
    fillXML(portscan["closed_ports"], closed_ports)
    fillXML(portscan["filtered_ports"], filtered_ports)
    fillXML(portscan["filtered_or_open_ports"], filtered_or_open_ports)
    fillXML(portscan["filtered_or_closed_ports"], filtered_or_closed_ports)

    # writing XML file
    tree = ET.ElementTree(root)
    tree.write("portscan.xml")

# defining function to write to JSON
def writeToJSON():
    with open("portscan.json", "w") as outfile:
        json.dump(portscan, outfile)

# writing scan results to XML or JSON if specified
if save_output:
    if save_output in ['xml', 'XML']:
        writeToXML()
    elif save_output in ['json', 'JSON']:
        writeToJSON()

# define function to write to SQlite databse
def writeToSQLite():
    # check if database file already exists. If not; create database and insert table:
    if os.path.isfile('portscan.db'):
        pass
    else:
        conn = sqlite3.connect("portscan.db")
        # create cursor object
        c = conn.cursor()
        c.execute('''CREATE TABLE portscans (
            host CHAR, 
            scan_type CHAR, 
            open_ports ENUM, 
            closed_ports ENUM, 
            filtered_ports ENUM, 
            filtered_or_open_ports ENUM, 
            filtered_or_closed_ports ENUM)''')
        # commit changes and close connection
        conn.commit()
        conn.close()

    # add the scan results to the table
    conn = sqlite3.connect("portscan.db")
    c = conn.cursor()
    # create query to insert portscan results and use question marks for best practices against SQLi
    query = f'INSERT INTO portscans VALUES (?, ?, ?, ?, ?, ?, ?)'
    # execute query
    c.execute(query, (
        f'{portscan["host"]}',
        f'{portscan["scan_type"]}',
        f'{portscan["open_ports"]}',
        f'{portscan["closed_ports"]}',
        f'{portscan["filtered_ports"]}',
        f'{portscan["filtered_or_open_ports"]}',
        f'{portscan["filtered_or_closed_ports"]}'))
    conn.commit()
    conn.close()

# write scan results to SQLite database:
writeToSQLite()