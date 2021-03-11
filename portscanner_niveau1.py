from scapy.all import *
import pyfiglet
import logging
import socket
import time

# suppress scapy warning message when importing module
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# create a nice banner for script
print(pyfiglet.figlet_format("PORT SCANNER"))
print(70 * "-")
print("By 0x47root | Drink all the booze, scan all machines! ;p")
print(70 * "-")

# ask user for input
scan_type = input("Please enter scan type (-sT, -sU, -sS or -sX): ")
target = input("Please specify the IP-address to scan: ")
first_port = int(input("Please specify the first port in port range: "))
last_port = int(input("Please specify the last port in port range: ")) + 1

# define TCP-connect scan
def TCP_connect_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.connect((target, port))
            print(f"Port {port} is open!!!!!!!!!!")
            s.close()
        except:
            print(f"Port {port} is filtered or closed")

# define UDP scan
def UDP_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/UDP(dport=port), timeout=5, verbose=0)
        time.sleep(1) # sleep one second to prevent false positives
        if res == None:
            print(f"Port {port} is open or filtered")
        else:
            if res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) == 3:
                    print(f"Port {port} is closed")
                elif int(res.getlayer(ICMP).type) == 3 and int(res.getlayer(ICMP).code) in [1, 2, 9, 10, 13]:
                    print(f"Port {port} is filtered")
            elif res.haslayer(UDP):
                print(f"Port {port} is open!!!!!!!!!!")

# define TCP-SYN scan
def TCP_SYN_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)
        # If the timeout value is not specified when this function is used against a unresponsive host,
        # the function will continue indefinitely
        if res == None:
            print(f"Port {port} is filtered")
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x12: # 0x12 = 18 = 16 + 2 = ACK + SYN
                rst = sr(IP(dst=target)/TCP(dport=port,flags="R"), timeout = 1, verbose=0)
                print(f"Port {port} is open!!!!!!!!!!")
            elif res.getlayer(TCP).flags == 0x14: # 0x12 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")

# define XMAS scan
def XMAS_scan(target, first_port, last_port):
    for port in range(first_port, last_port):
        res = sr1(IP(dst=target)/TCP(dport=port,flags="FPU"), timeout=1, verbose=0) # FIN, PSH and URG
        if res == None:
            print(f"Port {port} is filtered or open!!!!!!!!!!")
        elif res.haslayer(TCP):
            if res.getlayer(TCP).flags == 0x14: # 0x14 = 20 = 16 + 4 = ACK + RST
                print(f"Port {port} is closed")
            elif res.haslayer(ICMP):
                if int(res.getlayer(ICMP).type)==3 and int(res.getlayer(ICMP).code) in [1,2,3,9,10,13]:
                    print(f"Port {port} is filtered")

# check which scan to conduct
if scan_type == "-sT":
    TCP_connect_scan(target, first_port, last_port)
elif scan_type == "-sU":
    UDP_scan(target, first_port, last_port)
elif scan_type == "-sS":
    TCP_SYN_scan(target, first_port, last_port)
elif scan_type == "-sX":
    XMAS_scan(target, first_port, last_port)