"""
This file contains all scan types the user can choose.
The first scan (TCP-Connect) uses the 'sockets' library.
All other scans use the 'scapy' library.
"""
from scapy.all import *
import socket
import time

# Define a function to conduct a TCP-connect scan.
def TCP_connect_scan(target, first_port, last_port, portscan_variable):
    for port in range(first_port, last_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((target, port))
            print(f"Port {port} is open!")
            # Writing the results to the dictionary.
            portscan_variable['open_ports'].append(port)
            # Closing the socket connection.
            s.close()
        except:
            print(f"Port {port} is filtered or closed")
            portscan_variable['filtered_or_closed_ports'].append(port)

# Define a function to conduct an UDP scan.
def UDP_scan(target, first_port, last_port, portscan_variable):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/UDP(dport=port), timeout=5, verbose=0)
        # Sleep one second to prevent false positives.
        time.sleep(1)
        if res == None:
            print(f"Port {port} is open or filtered")
            portscan_variable['filtered_or_open_ports'].append(port)
        else:
            if res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) == 3:
                    print(f"Port {port} is closed")
                    portscan_variable['closed_ports'].append(port)
                elif int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    print(f"Port {port} is filtered")
                    portscan_variable['filtered_ports'].append(port)
            elif res.haslayer(UDP):
                print(f"Port {port} is open!")
                portscan_variable['open_ports'].append(port)

# Define a function to conduct a SYN scan.
def TCP_SYN_scan(target, first_port, last_port, portscan_variable):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        # If the timeout value is not specified when this function is used against an unresponsive host,
        # the function will continue indefinitely.
        if res == None:
            print(f"Port {port} is filtered")
            portscan_variable['filtered_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                rst = sr(IP(dst=target)/TCP(dport=port,flags="R"), timeout = 1, verbose=0)
                print(f"Port {port} is open!")
                portscan_variable['open_ports'].append(port)
            elif res.getlayer(TCP).flags == 0x14: # 0x12 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
                portscan_variable['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")
                    portscan_variable['filtered_ports'].append(port)

# Define a function to conduct a XMAS scan.
def XMAS_scan(target, first_port, last_port, portscan_variable):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), timeout=1, verbose=0) # FPU = FIN, PSH and URG
        if res == None:
            print(f"Port {port} is filtered or open")
            portscan_variable['filtered_or_open_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
                portscan_variable['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")
                    portscan_variable['filtered_ports'].append(port)
