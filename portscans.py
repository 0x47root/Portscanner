"""
This file contains all scan types the user can choose to execute.
The first scan (TCP-connect) uses the 'sockets' library.
All other scans use the 'scapy' library.
"""
from scapy.all import *
import socket
import time
import sys

# Defining all scan types:
def TCP_connect_scan(target, first_port, last_port, portscan_variable):
    """This function conducts a TCP-connect scan."""
    for port in range(first_port, last_port):
        # Creating the socket:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            # Connecting to the socket:
            s.connect((target, port))
            print(f"Port {port} is open!\n")
            # Writing the results to the dictionary:
            portscan_variable['open_ports'].append(port)
        except ConnectionRefusedError:
            print(f"Port {port} is filtered or closed\n")
            portscan_variable['filtered_or_closed_ports'].append(port)
        except TimeoutError:
            print(f"Port {port} is filtered or closed\n")
            portscan_variable['filtered_or_closed_ports'].append(port)
        # Closing the socket connection:
        s.close()

def UDP_scan(target, first_port, last_port, portscan_variable):
    """This function conducts an UDP scan."""
    for port in range(first_port, last_port):
        try:
            res = sr1(IP(dst=target)/UDP(dport=port), timeout=5, verbose=0)
        except PermissionError:
            print("PermissionError: Please run the script as admin/root.")
            sys.exit()
        except ValueError:
            print("ValueError: Unknown mypcap network interface. Make sure WinPcap is installed correctly.")
            sys.exit()
        # Sleep one second to prevent false positives:
        time.sleep(1)
        if res == None:
            print(f"Port {port} is open or filtered\n")
            portscan_variable['filtered_or_open_ports'].append(port)
        else:
            if res.haslayer(ICMP):
                # Checking if the response is ICMP "port unreachable":
                if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) == 3:
                    print(f"Port {port} is closed\n")
                    portscan_variable['closed_ports'].append(port)
                # Checking if the response contains other ICMP codes as a result of a filtered port:
                elif int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    print(f"Port {port} is filtered\n")
                    portscan_variable['filtered_ports'].append(port)
            # If the response contains an UDP layer, it runs a daemon and it is open:
            elif res.haslayer(UDP):
                print(f"Port {port} is open!\n")
                portscan_variable['open_ports'].append(port)

def TCP_SYN_scan(target, first_port, last_port, portscan_variable):
    """This function conducts a TCP-SYN scan."""
    for port in range(first_port, last_port):
        try:
            res = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
            # If the 'timeout' value is not specified when this function is used against an unresponsive host,
            # the function will continue indefinitely.
        except PermissionError:
            print("PermissionError: Please run the script as admin/root.")
            sys.exit()
        except ValueError:
            print("ValueError: Unknown mypcap network interface. Make sure WinPcap is installed correctly.")
            sys.exit()
        if res == None:
            print(f"Port {port} is filtered\n")
            portscan_variable['filtered_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                # Sending a packet with the 'Reset' flag to close the connection:
                rst = sr(IP(dst=target)/TCP(dport=port,flags="R"), timeout = 1, verbose=0)
                print(f"Port {port} is open!\n")
                portscan_variable['open_ports'].append(port)
            elif res.getlayer(TCP).flags == 0x14: # 0x12 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed\n")
                portscan_variable['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered\n")
                    portscan_variable['filtered_ports'].append(port)

def XMAS_scan(target, first_port, last_port, portscan_variable):
    """This function conducts a XMAS scan."""
    for port in range(first_port, last_port):
        try:
            res = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), timeout=1, verbose=0) # FPU = FIN, PSH and URG
        except PermissionError:
            print("PermissionError: Please run the script as admin/root.")
            sys.exit()
        except ValueError:
            print("ValueError: Unknown mypcap network interface. Make sure WinPcap is installed correctly.")
            sys.exit()
        if res == None:
            print(f"Port {port} is filtered or open\n")
            portscan_variable['filtered_or_open_ports'].append(port)
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed\n")
                portscan_variable['closed_ports'].append(port)
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered\n")
                    portscan_variable['filtered_ports'].append(port)
